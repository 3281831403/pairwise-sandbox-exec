"""safetpl.evaluate —— 白名单表达式求值器。

安全模型（这是契约，不是真正的操作系统沙箱）：

* 只解析单个表达式（``ast.parse(expr, mode="eval")``），不执行语句。
* 先做静态 AST 校验（check_ast），再做受限求值；任何违规统一抛
  ``UnsafeExpression``。
* 名称、属性、函数都走白名单；字符串/列表/字典结果大小与耗时都由
  ``limits`` 限制。
"""

from __future__ import annotations

import ast
import operator
import re
import time


class UnsafeExpression(Exception):
    """表达式或模板不安全、语法非法，或超出资源上限时抛出。"""


# 显式拒绝的危险双下划线名（开头下划线规则已覆盖，这里便于审计）。
_DANGEROUS_ATTRIBUTES = frozenset({
    "__class__",
    "__mro__",
    "__subclasses__",
    "__globals__",
    "__code__",
    "__builtins__",
})

# 允许出现的 AST 节点类型；其余一律拒绝。
_ALLOWED_NODES = (
    ast.Expression,
    ast.BinOp,
    ast.UnaryOp,
    ast.BoolOp,
    ast.Compare,
    ast.Call,
    ast.Name,
    ast.Constant,
    ast.Attribute,
    ast.Subscript,
    ast.IfExp,
    ast.List,
    ast.Tuple,
    ast.Dict,
    # 辅助节点
    ast.Load,
    ast.Store,
    ast.And,
    ast.Or,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.FloorDiv,
    ast.Mod,
    ast.Pow,
    ast.UAdd,
    ast.USub,
    ast.Not,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.In,
    ast.NotIn,
    ast.Is,
    ast.IsNot,
    ast.keyword,
)

_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

_UNARY_OPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
    ast.Not: operator.not_,
}

_CMP_OPS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
}

# printf 风格转换模式：%(name)s / %s / %5d / %-10s 等；单独的 % 文本不算。
_PRINTF_RE = re.compile(
    r"%\([^)]+\)[#0\- +]*\d*(?:\.\d+)?[diouxXeEfFgGcrs]"
    r"|%[#0\-+]*\d*(?:\.\d+)?[diouxXeEfFgGcrs]"
)

# 求值中由用户表达式引发、需要统一转换的异常。
_USER_ERRORS = (
    ZeroDivisionError,
    TypeError,
    KeyError,
    IndexError,
    AttributeError,
    ValueError,
)

_MAX_POW_EXPONENT = 1024


def _check_attribute_name(name: object, attributes) -> None:
    """校验属性名；违规抛 UnsafeExpression。"""
    if not isinstance(name, str) or not name:
        raise UnsafeExpression("attribute name must be a non-empty string")
    if name.startswith("_"):
        raise UnsafeExpression(f"attribute {name!r} is not allowed")
    if name in _DANGEROUS_ATTRIBUTES:
        raise UnsafeExpression(f"attribute {name!r} is not allowed")
    if name not in attributes:
        raise UnsafeExpression(f"attribute {name!r} is not in the whitelist")


def check_ast(tree: ast.AST, policy: dict) -> None:
    """静态校验 AST；通过返回 None，违规抛 UnsafeExpression。"""
    max_depth = policy.get("max_ast_depth", 100)
    functions = policy.get("functions", {})
    attributes = policy.get("attributes", ())

    counter = [0]
    active: set[int] = set()  # 当前递归路径上的节点 id，用于检测环

    def visit(node: ast.AST) -> None:
        counter[0] += 1
        if counter[0] > max_depth:
            raise UnsafeExpression(
                f"AST node count exceeds the limit of {max_depth}"
            )
        node_id = id(node)
        if node_id in active:
            raise UnsafeExpression("recursive AST reference detected")
        active.add(node_id)
        try:
            if not isinstance(node, _ALLOWED_NODES):
                raise UnsafeExpression(
                    f"node type {type(node).__name__} is not allowed"
                )
            if isinstance(node, ast.Name):
                if node.id.startswith("_"):
                    raise UnsafeExpression(f"name {node.id!r} is not allowed")
            elif isinstance(node, ast.Call):
                if not isinstance(node.func, ast.Name):
                    raise UnsafeExpression(
                        "only direct calls to whitelisted functions are allowed"
                    )
                if node.func.id not in functions:
                    raise UnsafeExpression(
                        f"function {node.func.id!r} is not in the whitelist"
                    )
            elif isinstance(node, ast.Attribute):
                _check_attribute_name(node.attr, attributes)
            elif isinstance(node, ast.Constant):
                if not isinstance(node.value, (str, int, float, bool, type(None))):
                    raise UnsafeExpression(
                        f"constant of type {type(node.value).__name__} "
                        "is not allowed"
                    )
            for child in ast.iter_child_nodes(node):
                visit(child)
        finally:
            active.discard(node_id)

    visit(tree)


def safe_getattr(obj: object, name: str, policy: dict) -> object:
    """按策略读取对象属性，成功时返回属性值，违规抛 UnsafeExpression。"""
    _check_attribute_name(name, policy.get("attributes", ()))
    return getattr(obj, name)


def evaluate(expr: str, ctx: dict, policy: dict, limits: dict) -> object:
    """解析、静态校验并受限求值单个表达式，返回结果。"""
    if not isinstance(expr, str) or not expr.strip():
        raise UnsafeExpression("expression must be a non-empty string")
    try:
        tree = ast.parse(expr, mode="eval")
    except (SyntaxError, ValueError, TypeError) as exc:
        raise UnsafeExpression(f"invalid expression syntax: {exc}") from exc

    check_ast(tree, policy)

    max_depth = limits["max_depth"]
    max_str = limits["max_str"]
    max_list = limits["max_list"]
    max_dict = limits["max_dict"]
    max_seconds = limits["max_seconds"]
    if max_seconds <= 0:
        raise UnsafeExpression("time budget exhausted")
    deadline = time.monotonic() + max_seconds

    functions = policy.get("functions", {})
    counter = [0]

    def check_size(value: object) -> object:
        if isinstance(value, str) and len(value) > max_str:
            raise UnsafeExpression(
                f"string result exceeds the limit of {max_str} characters"
            )
        if isinstance(value, (list, tuple)) and len(value) > max_list:
            raise UnsafeExpression(
                f"sequence result exceeds the limit of {max_list} elements"
            )
        if isinstance(value, dict) and len(value) > max_dict:
            raise UnsafeExpression(
                f"dict result exceeds the limit of {max_dict} entries"
            )
        return value

    def visit(node: ast.AST) -> object:
        counter[0] += 1
        if counter[0] > max_depth:
            raise UnsafeExpression(
                f"evaluation node count exceeds the limit of {max_depth}"
            )
        if time.monotonic() > deadline:
            raise UnsafeExpression("time budget exhausted")

        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant):
            return check_size(node.value)
        if isinstance(node, ast.Name):
            if node.id.startswith("_") or node.id not in ctx:
                raise UnsafeExpression(f"name {node.id!r} is not available")
            return check_size(ctx[node.id])
        if isinstance(node, ast.Attribute):
            return check_size(
                safe_getattr(visit(node.value), node.attr, policy)
            )
        if isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Slice):
                raise UnsafeExpression("slices are not supported")
            target = visit(node.value)
            index = visit(node.slice)
            if not isinstance(index, (int, str)):
                raise UnsafeExpression("only int/str subscripts are allowed")
            return check_size(target[index])
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                raise UnsafeExpression(
                    "only direct calls to whitelisted functions are allowed"
                )
            func = functions.get(node.func.id)
            if func is None:
                raise UnsafeExpression(
                    f"function {node.func.id!r} is not in the whitelist"
                )
            args = [visit(arg) for arg in node.args]
            kwargs = {kw.arg: visit(kw.value) for kw in node.keywords}
            return check_size(func(*args, **kwargs))
        if isinstance(node, ast.BinOp):
            op_type = type(node.op)
            func = _BIN_OPS.get(op_type)
            if func is None:
                raise UnsafeExpression(
                    f"operator {op_type.__name__} is not supported"
                )
            left = visit(node.left)
            right = visit(node.right)
            if op_type is ast.Mult:
                _precheck_mult(left, right, max_str, max_list)
            if op_type is ast.Pow:
                if isinstance(right, int) and abs(right) > _MAX_POW_EXPONENT:
                    raise UnsafeExpression("exponent is too large")
            return check_size(func(left, right))
        if isinstance(node, ast.UnaryOp):
            func = _UNARY_OPS.get(type(node.op))
            if func is None:
                raise UnsafeExpression(
                    f"operator {type(node.op).__name__} is not supported"
                )
            return check_size(func(visit(node.operand)))
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                result = None
                for value_node in node.values:
                    result = visit(value_node)
                    if not result:
                        return result
                return result
            if isinstance(node.op, ast.Or):
                result = None
                for value_node in node.values:
                    result = visit(value_node)
                    if result:
                        return result
                return result
            raise UnsafeExpression(
                f"operator {type(node.op).__name__} is not supported"
            )
        if isinstance(node, ast.Compare):
            left = visit(node.left)
            for op, comparator in zip(node.ops, node.comparators):
                func = _CMP_OPS.get(type(op))
                if func is None:
                    raise UnsafeExpression(
                        f"operator {type(op).__name__} is not supported"
                    )
                right = visit(comparator)
                if not func(left, right):
                    return False
                left = right
            return True
        if isinstance(node, ast.IfExp):
            if visit(node.test):
                return check_size(visit(node.body))
            return check_size(visit(node.orelse))
        if isinstance(node, ast.List):
            return check_size([visit(elt) for elt in node.elts])
        if isinstance(node, ast.Tuple):
            return check_size(tuple(visit(elt) for elt in node.elts))
        if isinstance(node, ast.Dict):
            result = {}
            for key_node, value_node in zip(node.keys, node.values):
                if key_node is None:
                    raise UnsafeExpression("dict unpacking is not allowed")
                result[visit(key_node)] = visit(value_node)
            return check_size(result)
        raise UnsafeExpression(
            f"node type {type(node).__name__} is not supported"
        )

    try:
        return check_size(visit(tree))
    except UnsafeExpression:
        raise
    except _USER_ERRORS as exc:
        raise UnsafeExpression(f"evaluation failed: {exc}") from exc


def _precheck_mult(left: object, right: object, max_str: int, max_list: int) -> None:
    """在执行 ``*`` 之前预检重复构造的大小，避免先分配再检查。"""
    for seq, count in ((left, right), (right, left)):
        if (
            isinstance(seq, (str, list, tuple))
            and isinstance(count, int)
            and not isinstance(count, bool)
        ):
            limit = max_str if isinstance(seq, str) else max_list
            if count > 0 and len(seq) * count > limit:
                raise UnsafeExpression(
                    f"repetition would produce {len(seq) * count} elements, "
                    f"exceeding the limit of {limit}"
                )


def render(template: str, ctx: dict, policy: dict, limits: dict) -> str:
    """渲染只含 ``{{ expr }}`` 占位符的模板，返回字符串。"""
    if _PRINTF_RE.search(template):
        raise UnsafeExpression("printf-style % formatting is not allowed")

    max_str = limits["max_str"]
    out: list[str] = []
    i = 0
    n = len(template)
    while i < n:
        if template.startswith("{{", i):
            end = template.find("}}", i + 2)
            if end == -1:
                raise UnsafeExpression("unclosed placeholder")
            inner = template[i + 2 : end]
            if "{{" in inner:
                raise UnsafeExpression("nested placeholder is not allowed")
            expr = inner.strip()
            if not expr:
                raise UnsafeExpression("empty placeholder is not allowed")
            value = evaluate(expr, ctx, policy, limits)
            out.append(str(value))
            i = end + 2
        elif template[i] in "{}":
            raise UnsafeExpression(
                "single braces (str.format style) are not allowed"
            )
        else:
            out.append(template[i])
            i += 1

    result = "".join(out)
    if len(result) > max_str:
        raise UnsafeExpression(
            f"rendered output exceeds the limit of {max_str} characters"
        )
    return result


def explain(expr: str, policy: dict) -> list[str]:
    """返回表达式被拒绝的原因列表（用于审计），合法表达式返回 []。"""
    try:
        tree = ast.parse(expr, mode="eval")
        check_ast(tree, policy)
    except (SyntaxError, ValueError, TypeError) as exc:
        return [f"invalid expression syntax: {exc}"]
    except UnsafeExpression as exc:
        return [str(exc)]
    return []

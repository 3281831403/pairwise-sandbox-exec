"""safetpl 的验收测试：15 个用例，初始全部因契约桩未实现而失败。

测试是验收基线，不可修改。覆盖五个缺陷方向：属性白名单、调用与格式化、
AST 深度/递归、结果大小上限、时间预算与模板占位符语法；另有两个合法
表达式/模板的通过路径。测试只使用标准库与 pytest，不联网。
"""

import ast

import pytest

from safetpl.evaluate import (
    UnsafeExpression,
    check_ast,
    evaluate,
    explain,
    render,
    safe_getattr,
)


POLICY = {
    "functions": {
        "len": len,
        "str": str,
        "int": int,
        "abs": abs,
        "min": min,
        "max": max,
        "sum": sum,
    },
    "attributes": {
        "upper",
        "lower",
        "strip",
        "startswith",
        "endswith",
        "keys",
        "values",
        "get",
        "items",
    },
}

LIMITS = {
    "max_depth": 50,
    "max_str": 64,
    "max_list": 16,
    "max_dict": 16,
    "max_seconds": 1.0,
}


def policy_with(**overrides):
    """返回在默认 POLICY 上覆盖若干键的策略副本。"""
    merged = dict(POLICY)
    merged.update(overrides)
    return merged


def limits_with(**overrides):
    """返回在默认 LIMITS 上覆盖若干键的限制副本。"""
    merged = dict(LIMITS)
    merged.update(overrides)
    return merged


# ---------------------------------------------------------------------------
# 缺陷 1：属性访问没有白名单
# ---------------------------------------------------------------------------


def test_class_attribute_rejected():
    obj = object()
    with pytest.raises(UnsafeExpression):
        safe_getattr(obj, "__class__", POLICY)
    with pytest.raises(UnsafeExpression):
        evaluate("obj.__class__", {"obj": obj}, POLICY, LIMITS)


def test_subclasses_attribute_rejected():
    expr = "().__class__.__bases__[0].__subclasses__()"
    with pytest.raises(UnsafeExpression):
        evaluate(expr, {}, POLICY, LIMITS)
    with pytest.raises(UnsafeExpression):
        check_ast(ast.parse(expr, mode="eval"), POLICY)


def test_leading_underscore_attribute_rejected():
    with pytest.raises(UnsafeExpression):
        safe_getattr(object(), "_private", POLICY)
    with pytest.raises(UnsafeExpression):
        evaluate("_secret", {"_secret": 1}, POLICY, LIMITS)
    assert explain("_secret", POLICY)


# ---------------------------------------------------------------------------
# 缺陷 2：内置函数与格式化逃逸
# ---------------------------------------------------------------------------


def test_getattr_call_rejected():
    assert "getattr" not in POLICY["functions"]
    with pytest.raises(UnsafeExpression):
        evaluate('getattr(obj, "upper")', {"obj": "x"}, POLICY, LIMITS)


def test_format_call_rejected():
    obj = object()
    assert "format" not in POLICY["functions"]
    with pytest.raises(UnsafeExpression):
        evaluate('"{0.__class__}".format(obj)', {"obj": obj}, POLICY, LIMITS)


def test_percent_formatting_rejected():
    with pytest.raises(UnsafeExpression):
        render("%(name)s", {"name": "world"}, POLICY, LIMITS)
    with pytest.raises(UnsafeExpression):
        render("Hello %s", {"name": "world"}, POLICY, LIMITS)


# ---------------------------------------------------------------------------
# 缺陷 3：AST 深度与递归没有上限
# ---------------------------------------------------------------------------


def test_ast_depth_limit_rejected():
    expr = "-" * 40 + "1"
    with pytest.raises(UnsafeExpression):
        evaluate(expr, {}, POLICY, limits_with(max_depth=10))
    with pytest.raises(UnsafeExpression):
        check_ast(ast.parse(expr, mode="eval"), policy_with(max_ast_depth=10))


def test_recursive_ast_reference_rejected():
    node = ast.UnaryOp(op=ast.USub(), operand=ast.Constant(value=1))
    node.operand = node  # 手工构造环：node.operand is node
    tree = ast.Expression(body=node)
    with pytest.raises(UnsafeExpression):
        check_ast(tree, policy_with(max_ast_depth=8))


# ---------------------------------------------------------------------------
# 缺陷 4：字符串乘法与容器结果没有上限
# ---------------------------------------------------------------------------


def test_string_length_limit_rejected():
    with pytest.raises(UnsafeExpression):
        evaluate('"a" * 1000', {}, POLICY, limits_with(max_str=10))


def test_list_elements_limit_rejected():
    with pytest.raises(UnsafeExpression):
        evaluate("[1, 2, 3, 4]", {}, POLICY, limits_with(max_list=3))


# ---------------------------------------------------------------------------
# 缺陷 5：没有时间预算，模板占位符没有语法校验
# ---------------------------------------------------------------------------


def test_time_budget_exhausted_rejected():
    with pytest.raises(UnsafeExpression):
        evaluate("1 + 2", {}, POLICY, limits_with(max_seconds=0.0))


def test_template_unclosed_placeholder_rejected():
    with pytest.raises(UnsafeExpression):
        render("Hello {{ name", {"name": "world"}, POLICY, LIMITS)


def test_template_nested_placeholder_rejected():
    with pytest.raises(UnsafeExpression):
        render("{{ {{ name }} }}", {"name": "world"}, POLICY, LIMITS)


# ---------------------------------------------------------------------------
# 合法路径：实现正确时应通过
# ---------------------------------------------------------------------------


def test_valid_expression_returns_value():
    expr = "len(items) + abs(-2)"
    assert evaluate(expr, {"items": [1, 2, 3]}, POLICY, LIMITS) == 5
    assert explain(expr, POLICY) == []


def test_valid_template_renders():
    out = render(
        "Hello {{ name }}! You have {{ len(items) }} items.",
        {"name": "Ada", "items": [1, 2]},
        POLICY,
        LIMITS,
    )
    assert out == "Hello Ada! You have 2 items."

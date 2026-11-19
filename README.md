# pairwise-sandbox-exec

## 题面

接入第三方模板插件后，模板引擎开始出事：属性访问没有白名单，().__class__.__bases__[0].__subclasses__() 能拿到任意类；内置函数放得太开，"{0.__class__}".format(obj) 一行就逃逸；AST 深度与递归没有上限，深层嵌套把栈打爆；字符串乘法和列表拼接不设上限，"a"*10**9 直接吃满内存；求值没有时间预算，模板占位符也没有语法校验。safetpl/evaluate.py 是核心，tests/test_evaluate.py 15个红。要修的是：属性访问走白名单并拒绝双下划线；只允许白名单函数调用；AST 深度与递归双重上限；字符串、列表、字典结果大小上限；每次求值检查单调时钟预算并校验占位符语法。

## 运行方式

在仓库根目录执行：

```bash
python -m pytest tests -q
```

初始状态应恰好得到 15 个失败，且没有 collection error、import error 或 syntax error。输出最后一行的形式为：

```text
15 failed in 0.05s
```

初始失败只来自 `safetpl/evaluate.py` 中的五个契约桩，不是测试本身出错；按契约实现后应为 `15 passed`。测试不联网、不启动外部进程，只使用标准库与 pytest。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## tests 不可修改

`tests/test_evaluate.py` 是验收基线，包含且仅包含 15 个测试，不可修改；实现只应落在 `safetpl/evaluate.py`（`conftest.py` 只负责把仓库根目录加入 `sys.path`）。

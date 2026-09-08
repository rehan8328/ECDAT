from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path


MAX_CALL_GRAPH_DEPTH = 6


@dataclass
class FunctionNode:
    identifier: str
    path: str
    qualname: str
    line: int
    end_line: int
    calls: set[str] = field(default_factory=set)
    entry_label: str | None = None

    @property
    def display(self) -> str:
        return f"{self.path}:{self.qualname}"


@dataclass
class CallGraph:
    nodes: dict[str, FunctionNode]
    callers: dict[str, set[str]]


def _module_name(relative_path: str) -> str:
    module = relative_path.removesuffix(".py").replace("/", ".")
    return module.removesuffix(".__init__")


def _decorator_entry_label(decorator: ast.expr) -> str | None:
    if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
        return None
    if decorator.func.attr.lower() not in {"get", "post", "put", "patch", "delete", "route", "api_route"}:
        return None
    path = next((item.value for item in decorator.args if isinstance(item, ast.Constant) and isinstance(item.value, str)), None)
    if path is None:
        return None
    return f"Route {path}"


def _is_main_guard(node: ast.If) -> bool:
    return (
        isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "__name__"
        and len(node.test.comparators) == 1
        and isinstance(node.test.comparators[0], ast.Constant)
        and node.test.comparators[0].value == "__main__"
    )


def _call_target(call: ast.Call, module: str, imports: dict[str, str], owner: str | None) -> str | None:
    target = call.func
    if isinstance(target, ast.Name):
        if target.id in imports:
            return imports[target.id]
        if owner and target.id != owner:
            return f"{module}.{target.id}"
        return f"{module}.{target.id}"
    if isinstance(target, ast.Attribute):
        if isinstance(target.value, ast.Name):
            base = target.value.id
            if base == "self" and owner:
                return f"{module}.{owner}.{target.attr}"
            if base in imports:
                return f"{imports[base]}.{target.attr}"
            return f"{module}.{base}.{target.attr}"
    return None


class _CallVisitor(ast.NodeVisitor):
    def __init__(self, module: str, imports: dict[str, str], owner: str | None) -> None:
        self.module = module
        self.imports = imports
        self.owner = owner
        self.calls: set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        target = _call_target(node, self.module, self.imports, self.owner)
        if target:
            self.calls.add(target)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Nested definitions have separate nodes; do not attribute their calls to the parent.
        return

    visit_AsyncFunctionDef = visit_FunctionDef


def _functions_in_tree(tree: ast.Module, module: str, imports: dict[str, str], relative_path: str) -> list[FunctionNode]:
    nodes: list[FunctionNode] = []
    for parent in tree.body:
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            visitor = _CallVisitor(module, imports, None)
            for statement in parent.body:
                visitor.visit(statement)
            entry = next((label for decorator in parent.decorator_list if (label := _decorator_entry_label(decorator))), None)
            label = entry or (f"CLI entry: {parent.name}" if parent.name == "main" else None)
            identifier = f"{module}.{parent.name}"
            nodes.append(FunctionNode(identifier, relative_path, parent.name, parent.lineno, parent.end_lineno or parent.lineno, visitor.calls, label))
        elif isinstance(parent, ast.ClassDef):
            for method in parent.body:
                if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                visitor = _CallVisitor(module, imports, parent.name)
                for statement in method.body:
                    visitor.visit(statement)
                identifier = f"{module}.{parent.name}.{method.name}"
                nodes.append(FunctionNode(identifier, relative_path, f"{parent.name}.{method.name}", method.lineno, method.end_lineno or method.lineno, visitor.calls))
    return nodes


def build_python_call_graph(root: Path) -> CallGraph:
    nodes: dict[str, FunctionNode] = {}
    main_calls: list[tuple[str, str]] = []
    for path in root.rglob("*.py"):
        if any(part in {".venv", "venv", "node_modules", "__pycache__"} for part in path.parts):
            continue
        try:
            content = path.read_text(encoding="utf-8")
            tree = ast.parse(content)
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        relative_path = path.relative_to(root).as_posix()
        module = _module_name(relative_path)
        imports: dict[str, str] = {}
        for statement in tree.body:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    imports[alias.asname or alias.name.split(".")[-1]] = alias.name
            elif isinstance(statement, ast.ImportFrom) and statement.module:
                for alias in statement.names:
                    imports[alias.asname or alias.name] = f"{statement.module}.{alias.name}"
        for node in _functions_in_tree(tree, module, imports, relative_path):
            nodes[node.identifier] = node
        for statement in tree.body:
            if isinstance(statement, ast.If) and _is_main_guard(statement):
                visitor = _CallVisitor(module, imports, None)
                for body_node in statement.body:
                    visitor.visit(body_node)
                for target in visitor.calls:
                    main_calls.append((module, target))
    for module, target in main_calls:
        if target in nodes:
            nodes[target].entry_label = nodes[target].entry_label or f"CLI entry: {target.rsplit('.', 1)[-1]}"
    callers: dict[str, set[str]] = {identifier: set() for identifier in nodes}
    for caller_id, node in nodes.items():
        for target in node.calls:
            if target in nodes:
                callers[target].add(caller_id)
    return CallGraph(nodes, callers)


def containing_function(graph: CallGraph, location: str, line: int | None) -> str | None:
    if line is None:
        return None
    matches = [node for node in graph.nodes.values() if node.path == location and node.line <= line <= node.end_line]
    if not matches:
        return None
    return min(matches, key=lambda node: node.end_line - node.line).identifier


def trace_to_entry_points(graph: CallGraph, start: str, max_depth: int = MAX_CALL_GRAPH_DEPTH) -> list[list[str]]:
    paths: list[list[str]] = []
    queue: deque[list[str]] = deque([[start]])
    while queue:
        path = queue.popleft()
        current = path[-1]
        node = graph.nodes[current]
        if node.entry_label:
            paths.append(path)
            continue
        if len(path) - 1 >= max_depth:
            continue
        for caller in sorted(graph.callers.get(current, set())):
            if caller not in path:
                queue.append([*path, caller])
    return paths

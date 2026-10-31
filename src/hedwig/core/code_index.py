"""Tree-sitter code index: where a service imports and calls a package.

One small extractor per language turns a source file into imports, calls and variable bindings.
`CodeIndex.usage()` then resolves them for one package into call sites.
"""

import json
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_php
import tree_sitter_python
import tree_sitter_rust
from tree_sitter import Language, Node, Parser

from hedwig.core.advisories import norm_name
from hedwig.core.models import CallSite, Package

EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".java": "java",
    ".rs": "rust",
    ".php": "php",
}
SKIP_DIRS = {
    "node_modules", "target", "vendor", "dist", "build", "__pycache__", "venv",
    "test", "tests", "__tests__", "spec",
}  # fmt: skip
MAX_FILE_BYTES = 1_000_000
SEPARATORS = (".", "/", "::", "\\")

_SYMBOLS = json.loads((Path(__file__).with_name("symbols.json")).read_text(encoding="utf-8"))


@dataclass
class Import:
    module: str  # as written: yaml, lodash/fp, org.apache.X.Y, regex::Regex, A\B\C
    local: str | None  # the name it is bound to in this file
    symbol: str | None  # the member imported, or None for a whole module


@dataclass
class Call:
    line: int
    function: str
    chain: list[str]  # ["yaml", "load"] for yaml.load(...)
    fqn: str | None = None  # a fully qualified class name used without an import (PHP)


@dataclass
class FileFacts:
    path: str
    imports: list[Import] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    bindings: dict[str, str] = field(default_factory=dict)  # variable -> the type/module it holds


@dataclass
class Usage:
    imported: bool = False
    calls: list[CallSite] = field(default_factory=list)


@cache
def _parser(language: str) -> Parser:
    grammar = {
        "python": tree_sitter_python.language,
        "javascript": tree_sitter_javascript.language,
        "java": tree_sitter_java.language,
        "rust": tree_sitter_rust.language,
        "php": tree_sitter_php.language_php,
    }[language]
    return Parser(Language(grammar()))


# -- tree helpers -----------------------------------------------------------------------


def _text(node: Node | None) -> str:
    return node.text.decode("utf-8", errors="replace") if node and node.text else ""


def _walk(root: Node) -> Iterator[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


_IDENTIFIERS = {"identifier", "property_identifier", "field_identifier", "type_identifier", "name"}
_MEMBERS = {
    "attribute": ("object", "attribute"),
    "member_expression": ("object", "property"),
    "field_expression": ("value", "field"),
    "field_access": ("object", "field"),
    "scoped_identifier": ("path", "name"),
}


def _chain(node: Node | None) -> list[str] | None:
    """a.b.c / a::b::c as ["a", "b", "c"]. None for anything more complicated."""
    if node is None:
        return None
    if node.type in _IDENTIFIERS or node.type == "variable_name":
        return [_text(node)]
    spec = _MEMBERS.get(node.type)
    if spec:
        left = _chain(node.child_by_field_name(spec[0]))
        right = node.child_by_field_name(spec[1])
        if left and right:
            return [*left, _text(right)]
    return None


def _enclosing(node: Node, kinds: set[str]) -> str:
    """Name of the nearest enclosing function, for anonymous ones the variable they are held in."""
    current = node.parent
    while current:
        if current.type in kinds:
            name = current.child_by_field_name("name")
            if name:
                return _text(name)
        if current.type in ("arrow_function", "function_expression", "function"):
            holder = current.parent
            if holder and holder.type == "variable_declarator":
                return _text(holder.child_by_field_name("name"))
        current = current.parent
    return "<module>"


# -- extractors: (root node, FileFacts) -> fills the facts ------------------------------


def _python(root: Node, facts: FileFacts) -> None:
    kinds = {"function_definition"}
    for node in _walk(root):
        if node.type == "import_statement":
            for child in node.named_children:
                if child.type == "dotted_name":
                    module = _text(child)
                    facts.imports.append(Import(module, module.split(".")[0], None))
                elif child.type == "aliased_import":
                    module = _text(child.child_by_field_name("name"))
                    facts.imports.append(
                        Import(module, _text(child.child_by_field_name("alias")), None)
                    )
        elif node.type == "import_from_statement":
            module = _text(node.child_by_field_name("module_name"))
            if module.startswith("."):
                continue
            for child in node.children_by_field_name("name"):
                if child.type == "aliased_import":
                    symbol = _text(child.child_by_field_name("name"))
                    local = _text(child.child_by_field_name("alias"))
                else:
                    symbol = local = _text(child)
                facts.imports.append(Import(module, local, symbol))
        elif node.type == "call":
            chain = _chain(node.child_by_field_name("function"))
            if chain:
                facts.calls.append(Call(node.start_point[0] + 1, _enclosing(node, kinds), chain))


def _js_module(node: Node | None) -> str:
    return _text(node).strip("'\"`")


def _javascript(root: Node, facts: FileFacts) -> None:
    kinds = {"function_declaration", "generator_function_declaration", "method_definition"}
    for node in _walk(root):
        if node.type == "import_statement":
            module = _js_module(node.child_by_field_name("source"))
            clause = next((c for c in node.named_children if c.type == "import_clause"), None)
            if clause is None:
                facts.imports.append(Import(module, None, None))
                continue
            for child in clause.named_children:
                if child.type == "identifier":
                    facts.imports.append(Import(module, _text(child), "default"))
                elif child.type == "namespace_import":
                    facts.imports.append(Import(module, _text(child.named_children[0]), None))
                elif child.type == "named_imports":
                    for spec in child.named_children:
                        name = _text(spec.child_by_field_name("name"))
                        alias = spec.child_by_field_name("alias")
                        facts.imports.append(Import(module, _text(alias) or name, name))
        elif node.type == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if (
                function is not None
                and function.type == "identifier"
                and _text(function) == "require"
            ):
                first = (
                    arguments.named_children[0] if arguments and arguments.named_children else None
                )
                if first is not None and first.type == "string":
                    _js_require(node, _js_module(first), facts)
                continue
            chain = _chain(function)
            if chain:
                facts.calls.append(Call(node.start_point[0] + 1, _enclosing(node, kinds), chain))


def _js_require(call: Node, module: str, facts: FileFacts) -> None:
    holder = call.parent
    if holder is None or holder.type != "variable_declarator":
        facts.imports.append(Import(module, None, None))
        return
    target = holder.child_by_field_name("name")
    if target is not None and target.type == "identifier":
        facts.imports.append(Import(module, _text(target), None))
    elif target is not None and target.type == "object_pattern":
        for child in target.named_children:
            if child.type == "shorthand_property_identifier_pattern":
                facts.imports.append(Import(module, _text(child), _text(child)))
            elif child.type == "pair_pattern":
                key = _text(child.child_by_field_name("key"))
                facts.imports.append(Import(module, _text(child.child_by_field_name("value")), key))


def _java(root: Node, facts: FileFacts) -> None:
    kinds = {"method_declaration", "constructor_declaration"}
    for node in _walk(root):
        if node.type == "import_declaration":
            scoped = next((c for c in node.named_children if c.type == "scoped_identifier"), None)
            if scoped is None:
                continue
            module = _text(scoped)
            wildcard = any(c.type == "asterisk" for c in node.children)
            if wildcard:
                facts.imports.append(Import(module, None, "*"))
            else:
                name = module.rsplit(".", 1)[-1]
                facts.imports.append(Import(module, name, name))
        elif node.type in ("field_declaration", "local_variable_declaration"):
            kind = re.sub(r"<.*", "", _text(node.child_by_field_name("type")))
            for declarator in node.children_by_field_name("declarator"):
                facts.bindings[_text(declarator.child_by_field_name("name"))] = kind
        elif node.type == "formal_parameter":
            kind = re.sub(r"<.*", "", _text(node.child_by_field_name("type")))
            facts.bindings[_text(node.child_by_field_name("name"))] = kind
        elif node.type == "method_invocation":
            owner = node.child_by_field_name("object")
            name = _text(node.child_by_field_name("name"))
            head = _chain(owner) if owner is not None else []
            if head is not None:
                facts.calls.append(
                    Call(node.start_point[0] + 1, _enclosing(node, kinds), [*head, name])
                )


def _rust_uses(node: Node | None, prefix: list[str]) -> Iterator[Import]:
    if node is None:
        return
    if node.type in ("identifier", "crate", "self", "super"):
        path = [*prefix, _text(node)]
        yield Import("::".join(path), path[-1], path[-1] if len(path) > 1 else None)
    elif node.type == "scoped_identifier":
        path = [*prefix, *(_chain(node) or [])]
        yield Import("::".join(path), path[-1], path[-1])
    elif node.type == "use_as_clause":
        path = [*prefix, *(_chain(node.child_by_field_name("path")) or [])]
        alias = _text(node.child_by_field_name("alias"))
        yield Import("::".join(path), alias, path[-1])
    elif node.type == "scoped_use_list":
        head = [*prefix, *(_chain(node.child_by_field_name("path")) or [])]
        for child in node.child_by_field_name("list").named_children:
            yield from _rust_uses(child, head)


def _rust_origin(value: Node | None) -> str | None:
    """The type a `let` holds, from `Type::new(..)` possibly followed by .unwrap() or ?."""
    node = value
    while node is not None:
        if node.type == "try_expression":
            node = node.named_children[0]
        elif node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function is not None and function.type == "field_expression":
                node = function.child_by_field_name("value")
            else:
                chain = _chain(function)
                return chain[0] if chain and len(chain) > 1 else None
        else:
            return None
    return None


def _rust(root: Node, facts: FileFacts) -> None:
    kinds = {"function_item"}
    for node in _walk(root):
        if node.type == "use_declaration":
            facts.imports.extend(_rust_uses(node.child_by_field_name("argument"), []))
        elif node.type == "let_declaration":
            pattern = node.child_by_field_name("pattern")
            origin = _rust_origin(node.child_by_field_name("value"))
            if pattern is not None and pattern.type == "identifier" and origin:
                facts.bindings[_text(pattern)] = origin
        elif node.type == "call_expression":
            chain = _chain(node.child_by_field_name("function"))
            if chain:
                facts.calls.append(Call(node.start_point[0] + 1, _enclosing(node, kinds), chain))


def _php(root: Node, facts: FileFacts) -> None:
    kinds = {"function_definition", "method_declaration"}
    for node in _walk(root):
        if node.type == "namespace_use_clause":
            name, _, alias = _text(node).partition(" as ")
            module = name.strip().lstrip("\\")
            last = module.rsplit("\\", 1)[-1]
            facts.imports.append(Import(module, alias.strip() or last, last))
        elif node.type == "object_creation_expression":
            klass = next(
                (c for c in node.named_children if c.type in ("name", "qualified_name")), None
            )
            full = _text(klass).lstrip("\\")
            if full:
                last = full.rsplit("\\", 1)[-1]
                fqn = full if "\\" in full else None
                facts.calls.append(
                    Call(
                        node.start_point[0] + 1, _enclosing(node, kinds), [last, "__construct"], fqn
                    )
                )
        elif node.type in ("member_call_expression", "scoped_call_expression"):
            owner = node.child_by_field_name("object" if node.type[0] == "m" else "scope")
            head = _chain(owner)
            if head:
                name = _text(node.child_by_field_name("name"))
                facts.calls.append(
                    Call(node.start_point[0] + 1, _enclosing(node, kinds), [*head, name])
                )
        elif node.type == "assignment_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left is not None and left.type == "variable_name" and right is not None:
                if right.type == "object_creation_expression":
                    klass = next(
                        (c for c in right.named_children if c.type in ("name", "qualified_name")),
                        None,
                    )
                    if klass is not None:
                        facts.bindings[_text(left)] = _text(klass).lstrip("\\").rsplit("\\", 1)[-1]


EXTRACTORS = {
    "python": _python,
    "javascript": _javascript,
    "java": _java,
    "rust": _rust,
    "php": _php,
}


# -- resolving facts for one package ------------------------------------------------------


def module_names(package: Package) -> list[str]:
    """The module / namespace / crate names code uses to import this package."""
    key = f"{package.ecosystem}:{norm_name(package.ecosystem, package.name)}"
    known = _SYMBOLS["modules"].get(key)
    if known:
        return known
    if package.ecosystem == "PyPI":
        return [norm_name("PyPI", package.name).replace("-", "_")]
    if package.ecosystem == "Maven":
        return [package.name.split(":")[0]]
    if package.ecosystem == "crates.io":
        return [package.name.replace("-", "_")]
    if package.ecosystem == "Packagist":
        vendor, _, name = package.name.partition("/")
        camel = lambda part: "".join(w.capitalize() for w in re.split(r"[-_.]", part))  # noqa: E731
        return [f"{camel(vendor)}\\{camel(name)}"]
    return [package.name]


def hinted_symbols(package: Package) -> list[str]:
    key = f"{package.ecosystem}:{norm_name(package.ecosystem, package.name)}"
    return _SYMBOLS["dangerous"].get(key, [])


def _matches(module: str, names: list[str]) -> bool:
    return any(
        module == name or any(module.startswith(name + sep) for sep in SEPARATORS) for name in names
    )


class CodeIndex:
    """Parses a service folder once and answers usage questions about its packages."""

    def __init__(self, folder: Path) -> None:
        self.folder = folder
        self.warnings: list[str] = []
        self._files: list[FileFacts] | None = None

    def _source_files(self) -> Iterator[Path]:
        for current, dirs, names in os.walk(self.folder):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS]
            for name in names:
                if Path(name).suffix in EXTENSIONS and not re.search(
                    r"(\.test\.|\.spec\.|_test\.|^test_)", name
                ):
                    yield Path(current) / name

    def files(self) -> list[FileFacts]:
        if self._files is None:
            self._files = []
            for path in sorted(self._source_files()):
                relative = path.relative_to(self.folder).as_posix()
                try:
                    if path.stat().st_size > MAX_FILE_BYTES:
                        continue
                    source = path.read_bytes()
                    language = EXTENSIONS[path.suffix]
                    tree = _parser(language).parse(source)
                except OSError as err:
                    self.warnings.append(f"{relative}: skipped ({err.strerror})")
                    continue
                if tree.root_node.has_error:
                    self.warnings.append(f"{relative}: skipped, syntax error")
                    continue
                facts = FileFacts(relative)
                EXTRACTORS[language](tree.root_node, facts)
                self._files.append(facts)
        return self._files

    def usage(self, package: Package) -> Usage:
        names = module_names(package)
        result = Usage()
        for facts in self.files():
            local: dict[str, Import] = {}
            for item in facts.imports:
                if _matches(item.module, names):
                    result.imported = True
                    if item.local:
                        local[item.local] = item
            for call in facts.calls:
                root = facts.bindings.get(call.chain[0], call.chain[0])
                item = local.get(root)
                direct = item is None and _matches(call.fqn or root, names)
                if item is None and not direct:
                    continue
                result.imported = True
                rest = call.chain[1:]
                if item is None:
                    base = call.chain[0]
                elif item.symbol and item.symbol not in ("default", "*"):
                    base = item.symbol
                elif not rest and "/" in item.module:
                    base = item.module.rsplit("/", 1)[-1]  # require("lodash/template")
                else:
                    base = item.local or root
                symbol = ".".join([base, *rest]) if item else ".".join(call.chain)
                result.calls.append(
                    CallSite(file=facts.path, line=call.line, function=call.function, symbol=symbol)
                )
        return result

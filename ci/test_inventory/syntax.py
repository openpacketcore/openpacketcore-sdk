"""Small syntax-tree helpers; comments and string contents are never code."""

from functools import lru_cache
from dataclasses import dataclass
from bisect import bisect_right
from collections import namedtuple
import re

from tree_sitter import Language, Parser
import tree_sitter_go
import tree_sitter_rust

from .model import GuardError


PARSERS = {
    'rust': Parser(Language(tree_sitter_rust.language())),
    'go': Parser(Language(tree_sitter_go.language())),
}
COMMENTS = {'line_comment', 'block_comment', 'comment'}
STRINGS = {'string_literal', 'raw_string_literal', 'char_literal', 'interpreted_string_literal', 'rune_literal'}
Point = namedtuple('Point', 'row column')


class Node:
    """An immutable syntax node with an explicitly owned source buffer.

    Use byte offsets for text/locations. Native Node.text has crashed during
    garbage collection on large inventories (see py-tree-sitter issue #435).
    Source slicing also avoids allocating a native memoryview per token.
    """

    __slots__ = ('raw', 'owner')

    def __init__(self, raw, owner):
        self.raw, self.owner = raw, owner

    @property
    def type(self):
        return self.raw.type

    @property
    def text(self):
        return self.owner.data[self.raw.start_byte:self.raw.end_byte]

    @property
    def children(self):
        return [Node(child, self.owner) for child in self.raw.children]

    @property
    def named_children(self):
        return [Node(child, self.owner) for child in self.raw.named_children]

    @property
    def parent(self):
        parent = self.raw.parent
        return Node(parent, self.owner) if parent else None

    @property
    def start_point(self):
        offset = self.raw.start_byte
        row = bisect_right(self.owner.lines, offset) - 1
        return Point(row, offset - self.owner.lines[row])

    @property
    def has_error(self):
        return self.raw.has_error

    @property
    def is_missing(self):
        return self.raw.is_missing

    def child_by_field_name(self, name):
        child = self.raw.child_by_field_name(name)
        return Node(child, self.owner) if child else None

    def __eq__(self, other):
        return isinstance(other, Node) and self.owner is other.owner and self.raw == other.raw


@dataclass
class ParsedSource:
    data: bytes
    tree: object
    lines: list[int]

    @property
    def root_node(self):
        return Node(self.tree.root_node, self)


def attribute_end(data, start):
    """Find a balanced attribute boundary, treating literals/comments atomically."""
    index, brackets = start + 2, 1
    while index < len(data):
        if data[index:index + 2] == b'//':
            end = data.find(b'\n', index + 2)
            index = end if end >= 0 else len(data)
            continue
        if data[index:index + 2] == b'/*':
            depth, index = 1, index + 2
            while index < len(data) and depth:
                if data[index:index + 2] == b'/*':
                    depth, index = depth + 1, index + 2
                elif data[index:index + 2] == b'*/':
                    depth, index = depth - 1, index + 2
                else:
                    index += 1
            continue
        raw = re.match(rb'r(#{0,255})"', data[index:]) if data[index:index + 1] == b'r' else None
        if raw:
            terminator = b'"' + raw.group(1)
            end = data.find(terminator, index + raw.end())
            if end < 0:
                return None
            index = end + len(terminator)
            continue
        if data[index] == 34:
            index += 1
            while index < len(data) and data[index] != 34:
                index += 2 if data[index] == 92 else 1
            index += 1
            continue
        brackets += (data[index] == 91) - (data[index] == 93)
        index += 1
        if not brackets:
            return index
    return None


@lru_cache(maxsize=128)
def parse(language, text):
    data = text.encode()
    parsed = ParsedSource(data, PARSERS[language].parse(data), [0] + [i + 1 for i, value in enumerate(data) if value == 10])
    if language == 'rust' and parsed.tree.root_node.has_error:
        # tree-sitter-rust does not yet accept cfg attributes on destructured
        # fields. These are field attributes, never test/module declarations.
        # Mask only that recognized grammar gap, preserving byte/line offsets;
        # every remaining parse error is still fatal.
        masked = bytearray(data)
        for _ in range(3):
            gaps = []
            for node in walk(parsed.root_node):
                if not re.match(r'#\[\s*cfg(?:_attr)?\(', node.text.decode()):
                    continue
                field_attribute = node.type == 'ERROR' and node.raw.parent.type == 'struct_pattern'
                if node.type == 'attribute_item' and node.raw.prev_named_sibling:
                    previous = Node(node.raw.prev_named_sibling, parsed)
                    pattern_prefix = r'let\s+[A-Za-z_][A-Za-z_0-9:]*\s*\{(?:\s*(?:ref\s+)?(?:mut\s+)?[A-Za-z_]\w*\s*,)*\s*'
                    if previous.type == 'ERROR' and re.fullmatch(pattern_prefix, previous.text.decode().strip()):
                        field_attribute = True
                if field_attribute:
                    # The error node may cover only the start of cfg(any(...)).
                    # Locate its balanced boundary and validate the isolated
                    # attribute in item position before masking anything.
                    offset = node.raw.start_byte
                    end = attribute_end(data, offset)
                    if end:
                        fragment = data[offset:end] + b' fn inventory_attribute() {}'
                        tree = PARSERS[language].parse(fragment)
                        if not tree.root_node.has_error:
                            gaps.append((offset, end))
            if not gaps:
                break
            for start, end in gaps:
                for offset in range(start, end):
                    if masked[offset] != 10:
                        masked[offset] = 32
            parsed.tree = PARSERS[language].parse(bytes(masked))
    return parsed


def checked_parse(language, path, text):
    parsed = parse(language, text)
    root = parsed.root_node
    if root.has_error:
        errors = [n for n in walk(root) if n.type == 'ERROR' or n.is_missing]
        node = errors[0] if errors else root
        raise GuardError(f'{path}:{node.start_point.row + 1}: {language} parse error; refusing an incomplete inventory')
    return parsed


def text(node):
    return node.text.decode() if node else ''


def walk(node, stop=()):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        if current.type not in stop:
            stack.extend(reversed(current.named_children))


def tokens(node, literals=True):
    """Tokenize macro token trees too, without interpreting quoted Rust text."""
    if node.type in COMMENTS:
        return []
    if node.type in STRINGS:
        return [text(node)] if literals else []
    if not node.children:
        return [text(node)]
    return [token for child in node.children for token in tokens(child, literals)]


def compact(node):
    return ''.join(tokens(node))

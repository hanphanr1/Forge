"""Same-file Java source tracing for the FORGE android-api-map.

``trace_source`` maps the URL literal positions that the existing static scan found to
the enclosing method, field initializer or class scope in the *same* file, and reports
syntactic constructor-to-field bindings, same-class field reads and same-class caller
candidates around them.

Everything here is lexical: character positions, brace nesting and identifier patterns.
It is not a Java AST. Types, overloads, inheritance, reflection and cross-file callers
are never resolved, request markers only co-occur inside a method, and nothing proves
that a URL was built or contacted at runtime. Input that cannot be attributed lexically
stays explicit as ``context_kind`` ``unsupported``.
"""

from __future__ import annotations

import bisect
import re

# context_kind values.
KIND_METHOD = "method"
KIND_FIELD_INITIALIZER = "field_initializer"
KIND_CLASS_SCOPE = "class_scope"
KIND_COMMENT = "comment"
KIND_UNSUPPORTED = "unsupported"

# resolution values.
RESOLUTION_CONSTRUCTOR = "syntactic_constructor_binding"
RESOLUTION_FIELD_INITIALIZER = "direct_field_initializer"
RESOLUTION_FIELD_USE = "same_class_field_candidate"
RESOLUTION_CALLER = "same_class_name_candidate"

# marker_kind values.
MARKER_URL_CALL = "url_call"
MARKER_DISPATCH_CALL = "dispatch_call"
MARKER_RETROFIT_ANNOTATION = "retrofit_annotation"

# Call and annotation names that become lexical request markers. A match is a
# co-occurrence hint in the enclosing method, never a resolved network call.
URL_CALL_NAMES = frozenset({"url"})
DISPATCH_CALL_NAMES = frozenset({"execute", "enqueue", "newCall", "performRequest"})
RETROFIT_ANNOTATIONS = frozenset({
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "HTTP",
    "Streaming", "FormUrlEncoded", "Multipart", "Headers",
    "Body", "Field", "FieldMap", "Header", "HeaderMap", "Part", "PartMap",
    "Path", "Query", "QueryMap", "QueryName", "Tag", "Url",
})

_ASSIGNMENTS = frozenset({"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^="})
_TYPE_KEYWORDS = frozenset({"class", "interface", "enum", "record"})
_MODIFIERS = frozenset({
    "public", "protected", "private", "static", "final", "abstract", "native",
    "synchronized", "transient", "volatile", "strictfp", "default", "sealed",
})
_PRIMITIVES = frozenset({
    "boolean", "byte", "char", "double", "float", "int", "long", "short", "var", "void",
})
_KEYWORDS = frozenset("""
abstract assert boolean break byte case catch char class const continue default do double
else enum extends final finally float for goto if implements import instanceof int
interface long native new package private protected public return short static strictfp
super switch synchronized this throw throws transient try void volatile while
true false null var record yield sealed permits
""".split())
# Line breaks recognized by str.splitlines(), so literal coordinates line up.
_LINE_BREAKS = frozenset("\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")
# ">>", ">>>" and ">>=" stay split into single ">" tokens on purpose: generic nesting
# is counted from ">" tokens, and no member or initializer decision needs the shift form.
_OPERATORS = (
    "...", "<<=", "->", "::", "==", "!=", "<=", ">=", "&&", "||", "++", "--",
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<",
)
# Smali directives and Kotlin function declarations never describe Java methods.
_NON_JAVA = re.compile(
    r"(?m)^[ \t]*\.[ \t]*(?:class|method|field|annotation|super|implements|source|line|local|param|registers|prologue|epilogue)\b"
    r"|\bfun[ \t]+\w+[ \t]*\("
)


def _word_start(char):
    return char.isalpha() or char in "_$\\" or ord(char) > 127


def _word_part(char):
    return char.isalnum() or char in "_$\\"


def _line_starts(text):
    """Index of the first character of every line, matching str.splitlines breaks."""
    starts = [0]
    index, size = 0, len(text)
    while index < size:
        char = text[index]
        if char in _LINE_BREAKS:
            index += 1
            if char == "\r" and index < size and text[index] == "\n":
                index += 1
            starts.append(index)
        else:
            index += 1
    return starts


class _Positions:
    """1-based Unicode (line, column) positions for character indexes and back."""

    __slots__ = ("starts",)

    def __init__(self, text):
        self.starts = _line_starts(text)

    def at(self, index):
        starts = self.starts
        line = bisect.bisect_right(starts, index)
        return line, index - starts[line - 1] + 1

    def index(self, line, column):
        starts = self.starts
        if line < 1 or line > len(starts) or column < 1:
            return None
        return starts[line - 1] + column - 1


def _tokenize(text):
    """Split source into (kind, value, start, end) tokens; comments are tokens too.

    Strings, character literals, text blocks and comments are consumed whole, so no
    later step can see braces, calls or assignments inside them.
    """
    tokens = []
    append = tokens.append
    size = len(text)
    index = 0
    while index < size:
        char = text[index]
        if char.isspace() or char in _LINE_BREAKS:
            index += 1
            continue
        if char == "/" and index + 1 < size:
            following = text[index + 1]
            if following == "/":
                end = index + 2
                while end < size and text[end] not in _LINE_BREAKS:
                    end += 1
                append(("comment", text[index:end], index, end))
                index = end
                continue
            if following == "*":
                found = text.find("*/", index + 2)
                end = size if found < 0 else found + 2
                append(("comment", text[index:end], index, end))
                index = end
                continue
        if char == '"':
            if text.startswith('"""', index):
                found = text.find('"""', index + 3)
                end = size if found < 0 else found + 3
            else:
                end = index + 1
                while end < size:
                    char = text[end]
                    if char == "\\":
                        end += 2
                        continue
                    if char == '"' or char in _LINE_BREAKS:
                        break
                    end += 1
                if end >= size:
                    end = size
                elif text[end] == '"':
                    end += 1
            append(("string", text[index:end], index, end))
            index = end
            continue
        if char == "'":
            end = index + 1
            while end < size:
                char = text[end]
                if char == "\\":
                    end += 2
                    continue
                if char == "'" or char in _LINE_BREAKS:
                    break
                end += 1
            if end >= size:
                end = size
            elif text[end] == "'":
                end += 1
            append(("char", text[index:end], index, end))
            index = end
            continue
        if char.isdigit():
            end = index + 1
            while end < size and (text[end].isalnum() or text[end] in "._"):
                end += 1
            append(("number", text[index:end], index, end))
            index = end
            continue
        if _word_start(char):
            end = index + 1
            while end < size and _word_part(text[end]):
                end += 1
            append(("word", text[index:end], index, end))
            index = end
            continue
        for operator in _OPERATORS:
            if text.startswith(operator, index):
                append(("punct", operator, index, index + len(operator)))
                index += len(operator)
                break
        else:
            append(("punct", char, index, index + 1))
            index += 1
    return tokens


tokenize = _tokenize


class _Scope:
    """One nesting level: a type body, method body, initializer block, transparent
    statement block or an excluded class boundary (nested, local, anonymous)."""

    __slots__ = ("kind", "name", "type_kind", "decl_line", "span_start", "span_end",
                 "body_start", "body_end", "excluded", "parent", "owner", "params",
                 "static", "constructor", "locals", "markers", "constants_done")

    def __init__(self, kind, name, decl_line, span_start, excluded, parent, owner, type_kind=""):
        self.kind = kind
        self.name = name
        self.type_kind = type_kind
        self.decl_line = decl_line
        self.span_start = span_start
        self.span_end = span_start
        self.body_start = span_start
        self.body_end = span_start
        self.excluded = excluded
        self.parent = parent
        self.owner = owner
        self.params = ()
        self.static = False
        self.constructor = False
        self.locals = None
        self.markers = []
        self.constants_done = False


class _Field:
    """One declared field of the traced class."""

    __slots__ = ("name", "type_simple", "line", "init_start", "init_end", "static")

    def __init__(self, name, type_simple, line, init_start, init_end, static):
        self.name = name
        self.type_simple = type_simple
        self.line = line
        self.init_start = init_start
        self.init_end = init_end
        self.static = static


class _Budget:
    """Shared retention cap: every emitted object costs one item."""

    __slots__ = ("remaining", "items", "omitted", "truncated")

    def __init__(self, maximum):
        self.remaining = maximum
        self.items = 0
        self.omitted = 0
        self.truncated = False

    def spend(self, count):
        if count <= self.remaining:
            self.remaining -= count
            self.items += count
            return True
        self.omitted += count
        self.truncated = True
        return False


class _Parser:
    """Bounded lexical model of one Java source file."""

    def __init__(self, text):
        self.tokens = _tokenize(text)
        self.positions = _Positions(text)
        self.token_starts = [token[2] for token in self.tokens]
        self.code = [index for index, token in enumerate(self.tokens) if token[0] != "comment"]
        self.token_map = {token: position for position, token in enumerate(self.code)}
        self.scopes = []
        self.spans = []
        self.scope_starts = []
        self.root = None
        self.root_name = ""
        self.fields = []
        self.field_index = {}
        self.declared = {}
        self.declaration_names = set()
        self.constructors = []
        self.reads = {}
        self.calls = {}
        self.caller_cache = {}
        self.unbalanced = False
        self.broken = _NON_JAVA.search(text) is not None

    # -- token access ------------------------------------------------------------

    def kind(self, index):
        if 0 <= index < len(self.code):
            return self.tokens[self.code[index]][0]
        return ""

    def value(self, index):
        if 0 <= index < len(self.code):
            return self.tokens[self.code[index]][1]
        return ""

    def line(self, index):
        if 0 <= index < len(self.code):
            return self.positions.at(self.tokens[self.code[index]][2])[0]
        return 0

    def _match(self, index):
        """Index of the closing bracket matching the opener at index."""
        opener = self.value(index)
        closer = {"(": ")", "[": "]", "{": "}"}.get(opener)
        if closer is None:
            return index
        depth = 0
        size = len(self.code)
        while index < size:
            value = self.value(index)
            if value == opener:
                depth += 1
            elif value == closer:
                depth -= 1
                if depth == 0:
                    return index
            index += 1
        self.unbalanced = True
        return size - 1

    def _angle_close(self, index):
        depth = 0
        size = len(self.code)
        while index < size:
            value = self.value(index)
            if value == "<":
                depth += 1
            elif value == ">":
                depth -= 1
                if depth == 0:
                    return index
            index += 1
        return size - 1

    def _back_match(self, index):
        """Index of the opener matching the closer at index."""
        depth = 0
        while index >= 0:
            value = self.value(index)
            if value == ")":
                depth += 1
            elif value == "(":
                depth -= 1
                if depth == 0:
                    return index
            index -= 1
        return None

    def _skip_annotations(self, index):
        size = len(self.code)
        while index < size and self.value(index) == "@":
            if self.value(index + 1) == "interface":
                break
            index += 1
            if self.kind(index) == "word":
                index += 1
            while self.value(index) == "." and self.kind(index + 1) == "word":
                index += 2
            if self.value(index) == "(":
                index = self._match(index) + 1
        return index

    def _skip_type(self, index):
        """Skip a (possibly generic, array or qualified) type name."""
        size = len(self.code)
        while index < size:
            value = self.value(index)
            if self.kind(index) == "word":
                index += 1
            elif value == "<":
                index = self._angle_close(index) + 1
            elif value == "[":
                index = self._match(index) + 1
            elif value == ".":
                index += 1
            else:
                break
        return index

    def _construction(self, name_index):
        """True when the word at name_index is the type of a ``new ...`` expression."""
        cursor = name_index
        while cursor >= 1 and self.value(cursor - 1) == "." and self.kind(cursor - 2) == "word":
            cursor -= 2
        return self.value(cursor - 1) == "new"

    def _new_expression(self, index):
        """True when the token run ending at index starts a ``new Type...`` expression."""
        while index >= 0:
            value = self.value(index)
            if value == "new":
                return True
            if self.kind(index) == "word" or value in (".", "<", ">", "[", "]", ","):
                index -= 1
                continue
            return False
        return False

    # -- structure ---------------------------------------------------------------

    def parse(self):
        stack = []
        size = len(self.code)
        index = 0
        while index < size:
            value = self.value(index)
            if value == "}":
                if stack:
                    stack.pop().span_end = index
                else:
                    self.unbalanced = True
                index += 1
                continue
            if value == "{":
                stack.append(self._scope("block", None, index, index, stack))
                index += 1
                continue
            if value == ";":
                index += 1
                continue
            top = stack[-1] if stack else None
            if top is None or top.kind == "type":
                index = self._member(index, stack)
            else:
                index = self._body(index, stack)
        if stack:
            self.unbalanced = True
            for scope in stack:
                scope.span_end = size - 1
        self.spans.sort(key=lambda item: item[0])
        self.scope_starts = [item[0] for item in self.spans]

    def _scope(self, kind, name, span_start, header_start, stack, extra=False, type_kind=""):
        parent = stack[-1] if stack else None
        excluded = extra or (parent.excluded if parent is not None else False)
        owner = parent if (kind == "type" or parent is None) else parent.owner
        scope = _Scope(kind, name, self.line(header_start), span_start, excluded, parent, owner, type_kind)
        self.scopes.append(scope)
        self.spans.append((span_start, scope))
        return scope

    def _member(self, index, stack):
        if not stack:
            return self._top_level(index, stack)
        owner = stack[-1]
        if owner.type_kind == "enum" and not owner.constants_done:
            return self._enum_constants(index, owner)
        cursor = self._skip_annotations(index)
        probe = cursor
        while self.value(probe) in _MODIFIERS:
            probe += 1
        keyword = self.value(probe)
        if keyword == "@" and self.value(probe + 1) == "interface":
            keyword = "interface"
            probe += 1
        if keyword in _TYPE_KEYWORDS and self.value(probe - 1) != "." and self.kind(probe + 1) == "word":
            opened = self._type_declaration(index, keyword, probe, stack)
            if opened is not None:
                return opened
        return self._header(index, stack)

    def _top_level(self, index, stack):
        """Outside any type body only a type declaration starts a traced scope."""
        cursor = self._skip_annotations(index)
        probe = cursor
        while self.value(probe) in _MODIFIERS:
            probe += 1
        keyword = self.value(probe)
        if keyword == "@" and self.value(probe + 1) == "interface":
            keyword = "interface"
            probe += 1
        if keyword in _TYPE_KEYWORDS and self.value(probe - 1) != "." and self.kind(probe + 1) == "word":
            opened = self._type_declaration(index, keyword, probe, stack)
            if opened is not None:
                return opened
        return index + 1

    def _type_declaration(self, index, keyword, probe, stack):
        name = self.value(probe + 1)
        size = len(self.code)
        cursor = probe + 2
        while cursor < size:
            value = self.value(cursor)
            if value in ("(", "["):
                cursor = self._match(cursor) + 1
                continue
            if value == "{":
                break
            if value in (";", "}"):
                return None
            cursor += 1
        if cursor >= size:
            return None
        excluded = not (self.root is None and not stack)
        scope = self._scope("type", name, index, index, stack, extra=excluded, type_kind=keyword)
        if not excluded:
            self.root = scope
            self.root_name = name
        stack.append(scope)
        return cursor + 1

    def _enum_constants(self, index, owner):
        """Consume an enum constant list; its arguments are class-level code."""
        size = len(self.code)
        cursor = index
        while cursor < size:
            value = self.value(cursor)
            if value in ("(", "[", "{"):
                cursor = self._match(cursor) + 1
                continue
            if value == ";":
                owner.constants_done = True
                return cursor + 1
            if value == "}":
                owner.constants_done = True
                return cursor
            cursor += 1
        owner.constants_done = True
        self.unbalanced = True
        return size

    def _body(self, index, stack):
        value = self.value(index)
        if value == "new":
            cursor = self._skip_type(index + 1)
            if self.value(cursor) == "(" and self.value(self._match(cursor) + 1) == "{":
                opened = self._match(cursor) + 1
                stack.append(self._scope("excluded", None, opened, opened, stack, extra=True))
                return opened + 1
            return index + 1
        if value in _TYPE_KEYWORDS and self.kind(index + 1) == "word" and self.value(index - 1) != ".":
            opened = self._type_declaration(index, value, index, stack)
            if opened is not None:
                return opened
        return index + 1

    def _header(self, index, stack):
        """Parse one member declaration at type level."""
        owner = stack[-1]
        size = len(self.code)
        start = self._skip_annotations(index)
        cursor = start
        flat = []
        paren = None
        seen_assignment = False
        while cursor < size:
            value = self.value(cursor)
            if value == "(":
                end = self._match(cursor)
                if paren is None and cursor > start and self.kind(cursor - 1) == "word" \
                        and self.value(cursor - 1) not in _KEYWORDS and not self._construction(cursor - 1):
                    paren = (cursor - 1, cursor, end)
                flat.append(cursor)
                cursor = end + 1
                continue
            if value == "[":
                flat.append(cursor)
                cursor = self._match(cursor) + 1
                continue
            if value == "{":
                if paren is not None or (not seen_assignment and self._header_is_modifiers(index, cursor)):
                    if paren is None:
                        scope = self._scope("init", None, index, index, stack)
                        scope.body_start = cursor + 1
                        scope.body_end = self._match(cursor)
                        stack.append(scope)
                    else:
                        self._method(index, owner, paren, cursor, flat, stack)
                    return cursor + 1
                if self._anonymous_body(cursor):
                    stack.append(self._scope("excluded", None, cursor, cursor, stack, extra=True))
                    return cursor + 1
                cursor = self._match(cursor) + 1
                continue
            if value == "=":
                seen_assignment = True
                flat.append(cursor)
                cursor += 1
                continue
            if value == ";":
                if paren is not None:
                    self._method(index, owner, paren, None, flat, stack, cursor)
                else:
                    self._fields(owner, flat, cursor, index)
                return cursor + 1
            if value == "}":
                self.unbalanced = True
                return cursor
            flat.append(cursor)
            cursor += 1
        self.unbalanced = True
        return size

    def _header_is_modifiers(self, index, cursor):
        """True when the member header before cursor holds only modifiers/annotations."""
        probe = self._skip_annotations(index)
        while probe < cursor:
            if self.value(probe) not in _MODIFIERS:
                return False
            probe += 1
        return True

    def _anonymous_body(self, index):
        """True when the ``{`` at index opens an anonymous class body."""
        if self.value(index - 1) != ")":
            return False
        opener = self._back_match(index - 1)
        return opener is not None and opener > 0 and self._new_expression(opener - 1)

    def _method(self, index, owner, paren, body, flat, stack, terminator=None):
        name_index, opener, closer = paren
        name = self.value(name_index)
        scope = self._scope("method", name, index, index, stack)
        scope.params = self._parameters(opener, closer)
        scope.static = "static" in (self.value(item) for item in flat)
        scope.constructor = name == owner.name and self._is_constructor(index, name_index)
        if body is None:
            # Abstract and interface declarations have no body to walk.
            scope.span_end = terminator
            scope.body_start = scope.body_end = terminator
        else:
            scope.body_start = body + 1
            scope.body_end = self._match(body)
            stack.append(scope)
        if owner is self.root:
            self.declared[name] = self.declared.get(name, 0) + 1
            self.declaration_names.add(name_index)
            if scope.constructor:
                self.constructors.append(scope)

    def _is_constructor(self, index, name_index):
        """True when a member header carries no return type before its name."""
        probe = self._skip_annotations(index)
        while probe < name_index:
            value = self.value(probe)
            if value == "@":
                probe = self._skip_annotations(probe)
                continue
            if value == "<" or (self.kind(probe) == "word" and value not in _MODIFIERS):
                return False
            probe += 1
        return True

    def _parameters(self, opener, closer):
        names = []
        for start, end in self._arguments(opener, closer):
            for cursor in range(end - 1, start - 1, -1):
                if self.kind(cursor) == "word":
                    names.append(self.value(cursor))
                    break
        return tuple(names)

    def _arguments(self, opener, closer):
        """Top-level comma ranges between opener and closer (nested groups skipped)."""
        arguments = []
        depth = 0
        start = opener + 1
        cursor = opener + 1
        while cursor < closer:
            value = self.value(cursor)
            if value in ("(", "[", "{"):
                depth += 1
            elif value in (")", "]", "}"):
                depth -= 1
            elif value == "<":
                closed = self._angle_close(cursor)
                if closed < closer:
                    # A balanced angle group inside the list is a generic, not a split.
                    cursor = closed
            elif value == "," and depth == 0:
                arguments.append((start, cursor))
                start = cursor + 1
            cursor += 1
        if start < closer:
            arguments.append((start, closer))
        return arguments

    def _fields(self, owner, flat, terminator, index):
        line = self.line(index)
        for chunk, delimiter in self._chunks(flat, terminator):
            offset = None
            for position, item in enumerate(chunk):
                if self.value(item) == "=":
                    offset = position
                    break
            name_offset = (offset - 1) if offset is not None else len(chunk) - 1
            if name_offset < 0 or self.kind(chunk[name_offset]) != "word":
                continue
            name_index = chunk[name_offset]
            angle = 0
            type_simple = ""
            for item in chunk[:name_offset]:
                value = self.value(item)
                if value == "<":
                    angle += 1
                elif value == ">":
                    angle = max(0, angle - 1)
                elif angle == 0 and self.kind(item) == "word":
                    type_simple = value
            field = _Field(self.value(name_index), type_simple, line,
                           chunk[offset] + 1 if offset is not None else 0,
                           delimiter if offset is not None else 0,
                           any(self.value(item) == "static" for item in chunk[:name_offset]))
            if owner is not self.root:
                continue
            self.fields.append(field)
            self.field_index.setdefault(field.name, field)

    def _chunks(self, flat, terminator):
        """Split a declaration header into declarators on top-level commas."""
        chunks = []
        current = []
        position = 0
        size = len(flat)
        while position < size:
            item = flat[position]
            value = self.value(item)
            if value == "<":
                closed = self._angle_close(item)
                if closed < terminator:
                    while position < size and flat[position] <= closed:
                        current.append(flat[position])
                        position += 1
                    continue
            elif value == ",":
                if current:
                    chunks.append((current, item))
                    current = []
                position += 1
                continue
            current.append(item)
            position += 1
        if current:
            chunks.append((current, terminator))
        return chunks

    # -- same-class facts --------------------------------------------------------

    def analyze(self):
        spans = self.spans
        pointer = 0
        stack = []
        for index in range(len(self.code)):
            while pointer < len(spans) and spans[pointer][0] <= index:
                stack.append(spans[pointer][1])
                pointer += 1
            while stack and stack[-1].span_end < index:
                stack.pop()
            scope = stack[-1] if stack else None
            while scope is not None and scope.kind == "block":
                scope = scope.parent
            if scope is None or scope.excluded:
                continue
            self._inspect(index, scope)
        for scope in self.scopes:
            if scope.markers:
                scope.markers.sort()

    def _inspect(self, index, scope):
        if self.value(index) == "@":
            if scope.kind == "method" and self.value(index + 1) in RETROFIT_ANNOTATIONS:
                self._mark(scope, index, MARKER_RETROFIT_ANNOTATION)
            return
        if self.kind(index) != "word" or scope.kind != "method":
            return
        name = self.value(index)
        following = self.value(index + 1)
        if following == "(":
            if name in URL_CALL_NAMES:
                self._mark(scope, index, MARKER_URL_CALL)
            elif name in DISPATCH_CALL_NAMES:
                self._mark(scope, index, MARKER_DISPATCH_CALL)
        if name in _KEYWORDS or index in self.declaration_names:
            return
        previous = self.value(index - 1)
        if following == "(":
            if previous == ".":
                receiver = self.value(index - 2)
                if receiver == self.root_name and self.value(index - 3) == ".":
                    return
                if receiver != "this" and receiver != self.root_name:
                    return
            elif previous == "new":
                return
            self.calls.setdefault(name, []).append((self.line(index), scope))
            return
        if name not in self.field_index:
            return
        if previous == ".":
            receiver = self.value(index - 2)
            if receiver == "this":
                start = index - 2
            elif receiver == self.root_name and self.value(index - 3) != ".":
                start = index - 2
            else:
                return
        else:
            if self.kind(index - 1) == "word" and previous not in _KEYWORDS and previous not in _PRIMITIVES:
                return
            if previous in ("]", ">"):
                return
            if scope.static and not self.field_index[name].static:
                return
            if name in self._locals(scope):
                return
            start = index
        if self.value(start - 1) in ("++", "--") or following in _ASSIGNMENTS or following in ("++", "--"):
            return
        self.reads.setdefault(name, []).append((self.line(start), scope))

    def _mark(self, scope, index, marker_kind):
        entry = (self.line(index), marker_kind)
        if entry not in scope.markers:
            scope.markers.append(entry)

    def _locals(self, scope):
        if scope.locals is None:
            names = set(scope.params)
            for index in range(scope.body_start, scope.body_end):
                if self.kind(index) != "word":
                    continue
                if self.value(index + 1) not in ("=", ";", ",", ":", ")"):
                    continue
                previous = self.value(index - 1)
                if self.kind(index - 1) == "word" and (previous not in _KEYWORDS or previous in _PRIMITIVES):
                    names.add(self.value(index))
                elif previous in ("]", ">"):
                    names.add(self.value(index))
            scope.locals = names
        return scope.locals

    def _use_sites(self, name):
        sites = self.reads.get(name)
        if not sites:
            return []
        seen = set()
        unique = []
        for line, scope in sites:
            key = (line, scope.span_start)
            if key in seen:
                continue
            seen.add(key)
            unique.append((line, scope))
        return unique

    def _callers(self, name):
        cached = self.caller_cache.get(name)
        if cached is None:
            overloads = self.declared.get(name, 0)
            seen = set()
            cached = []
            for line, scope in self.calls.get(name, ()):
                key = (line, scope.span_start)
                if key in seen:
                    continue
                seen.add(key)
                cached.append({"line": line, "method_name": scope.name, "method_line": scope.decl_line,
                               "resolution": RESOLUTION_CALLER, "overload_count": overloads})
            self.caller_cache[name] = cached
        return [dict(item) for item in cached]

    def _uses(self, name):
        uses = []
        for line, scope in self._use_sites(name):
            uses.append({
                "line": line, "method_name": scope.name, "method_line": scope.decl_line,
                "resolution": RESOLUTION_FIELD_USE,
                "request_markers": [{"line": marker_line, "marker_kind": marker_kind}
                                    for marker_line, marker_kind in scope.markers],
                "callers": self._callers(scope.name),
            })
        return uses

    # -- binding and traces ------------------------------------------------------

    def _arguments_of(self, index):
        """Argument ranges of the innermost construction call containing index."""
        depth = 0
        cursor = index - 1
        while cursor >= 0:
            value = self.value(cursor)
            if value == ")":
                depth += 1
            elif value == "(":
                if depth == 0:
                    name_index = cursor - 1
                    if self.kind(name_index) != "word" or self.value(name_index - 1) != "new":
                        return None
                    return self.value(name_index), self._arguments(cursor, self._match(cursor))
                depth -= 1
            elif value in (";", "{", "}") and depth == 0:
                return None
            cursor -= 1
        return None

    def _constructor_link(self, index):
        """Literal -> constructor parameter -> ``this.field = parameter`` binding."""
        found = self._arguments_of(index)
        if found is None:
            return None
        name, arguments = found
        if name != self.root_name:
            return None
        for position, (start, end) in enumerate(arguments, 1):
            if start == index and end - start == 1:
                argument_index = position
                break
        else:
            return None
        candidates = [scope for scope in self.constructors if len(scope.params) == len(arguments)]
        if len(candidates) != 1:
            return None
        constructor = candidates[0]
        if argument_index > len(constructor.params):
            return None
        parameter = constructor.params[argument_index - 1]
        assignments = self._parameter_assignments(constructor, parameter)
        if not assignments or len({field for field, _ in assignments}) != 1:
            return None
        field_name, assignment_line = assignments[0]
        return {"field_name": field_name, "constructor_line": constructor.decl_line,
                "parameter_name": parameter, "argument_index": argument_index,
                "assignment_line": assignment_line, "resolution": RESOLUTION_CONSTRUCTOR}

    def _parameter_assignments(self, constructor, parameter):
        assignments = []
        cursor = constructor.body_start
        end = constructor.body_end
        while cursor + 5 <= end:
            if self._region(cursor) is constructor and self.value(cursor) == "this" and self.value(cursor + 1) == "." \
                    and self.kind(cursor + 2) == "word" and self.value(cursor + 3) == "=" \
                    and self.kind(cursor + 4) == "word" and self.value(cursor + 4) == parameter \
                    and self.value(cursor + 5) == ";":
                assignments.append((self.value(cursor + 2), self.line(cursor)))
                cursor += 6
                continue
            cursor += 1
        return assignments

    def _attach(self, root, link, budget):
        """Attach a link and its uses, or count the whole link as an omission."""
        sites = self._use_sites(link["field_name"])
        cost = 1
        for _line, scope in sites:
            cost += 1 + len(scope.markers) + len(self._callers(scope.name))
        if not budget.spend(cost):
            return
        link["uses"] = self._uses(link["field_name"])
        root["field_links"].append(link)

    def _plain(self, kind, line, column, budget):
        budget.spend(1)
        return {"literal_line": line, "literal_column": column, "context_kind": kind}

    def _locate(self, line, column):
        index = self.positions.index(line, column)
        if index is None:
            return None
        position = bisect.bisect_right(self.token_starts, index) - 1
        if position < 0 or index >= self.tokens[position][3]:
            return None
        if self.tokens[position][0] == "comment":
            return ("comment", None)
        code_index = self.token_map.get(position)
        return ("code", code_index) if code_index is not None else None

    def _innermost(self, index):
        position = bisect.bisect_right(self.scope_starts, index) - 1
        while position >= 0:
            scope = self.spans[position][1]
            if scope.span_end >= index:
                return scope
            position -= 1
        return None

    def _region(self, index):
        scope = self._innermost(index)
        while scope is not None and scope.kind == "block":
            scope = scope.parent
        return scope

    def _field_at(self, index):
        for field in self.fields:
            if field.init_start <= index < field.init_end:
                return field
        return None

    def root_trace(self, line, column, budget):
        """One trace root for one literal position, or None when the cap blocked it."""
        located = self._locate(line, column)
        if located is None:
            return self._plain(KIND_UNSUPPORTED, line, column, budget)
        kind, index = located
        if kind == "comment":
            return self._plain(KIND_COMMENT, line, column, budget)
        if self.broken or self.unbalanced or self.root is None:
            return self._plain(KIND_UNSUPPORTED, line, column, budget)
        scope = self._region(index)
        if scope is None or scope.excluded:
            return self._plain(KIND_UNSUPPORTED, line, column, budget)
        if scope.kind == "method":
            return self._method_trace(line, column, index, scope, budget)
        field = self._field_at(index) if scope.kind == "type" else None
        if field is None:
            return self._scope_trace(line, column, index, KIND_CLASS_SCOPE, budget)
        return self._scope_trace(line, column, index, KIND_FIELD_INITIALIZER, budget, field)

    def _method_trace(self, line, column, index, scope, budget):
        link = self._constructor_link(index)
        budget.spend(1)
        root = {"literal_line": line, "literal_column": column, "context_kind": KIND_METHOD,
                "method_name": scope.name, "method_line": scope.decl_line,
                "method_end_line": self.line(scope.span_end), "field_links": [],
                "request_markers": [], "callers": []}
        if link is not None:
            self._attach(root, link, budget)
        for marker_line, marker_kind in scope.markers:
            if budget.spend(1):
                root["request_markers"].append({"line": marker_line, "marker_kind": marker_kind})
        for caller in self._callers(scope.name):
            if budget.spend(1):
                root["callers"].append(caller)
        return root

    def _scope_trace(self, line, column, index, kind, budget, field=None):
        link = None
        field_name = None
        if field is not None:
            direct = field.init_start == index and field.init_end - field.init_start == 1 \
                and self.kind(index) == "string" and field.type_simple == "String"
            if direct:
                field_name = field.name
                link = {"field_name": field.name, "resolution": RESOLUTION_FIELD_INITIALIZER}
            else:
                link = self._constructor_link(index)
        else:
            link = self._constructor_link(index)
        budget.spend(1)
        root = {"literal_line": line, "literal_column": column, "context_kind": kind}
        if field_name is not None:
            root["field_name"] = field_name
        root["field_links"] = []
        root["request_markers"] = []
        root["callers"] = []
        if link is not None:
            self._attach(root, link, budget)
        return root

    def trace(self, literals, max_items):
        budget = _Budget(max_items)
        seen = set()
        occurrences = []
        for key, positions in literals.items():
            for position in positions:
                line, column = position
                identity = (key, line, column)
                if identity in seen:
                    continue
                seen.add(identity)
                occurrences.append((line, column, key))
        occurrences.sort()
        traces = {}
        for position, (line, column, key) in enumerate(occurrences):
            if budget.remaining <= 0:
                # Lower bound: remaining literals are counted as roots only.
                budget.omitted += len(occurrences) - position
                budget.truncated = True
                break
            trace = self.root_trace(line, column, budget)
            if trace is not None:
                traces.setdefault(key, []).append(trace)
        return {"traces": traces, "items": budget.items, "omitted": budget.omitted,
                "truncated": budget.truncated}


def trace_source(text, literals, max_items):
    """Trace URL literal positions back to same-file Java constructs.

    text: decoded Java source. literals: mapping of opaque URL candidate key to a list
    of 1-based (line, column) positions inside a URL string in that source. max_items:
    shared retention cap counted in emitted objects (trace roots, field links, field
    uses, callers and request markers). Returns
    ``{traces, items, omitted, truncated}``; ``omitted`` counts objects a cap or an
    early stop prevented and is a lower bound once tracing stops. Every emitted value
    is a lexical candidate: context comes from the same file only, and no type,
    overload, inheritance, reflection or runtime behaviour is resolved.
    """
    parser = _Parser(text)
    parser.parse()
    parser.analyze()
    return parser.trace(literals, max_items)

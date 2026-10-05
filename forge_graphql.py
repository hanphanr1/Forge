"""Bounded executable-document parsing without retaining GraphQL values."""
from __future__ import annotations

import bisect
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import parse_qsl, urlsplit

from forge_core import ForgeError, scrub_text

MAX_FILE_BYTES = 1024 * 1024
MAX_DOCUMENT_CHARACTERS = 262144
MAX_TOTAL_CHARACTERS = 4 * 1024 * 1024
MAX_TOKENS = 20000
MAX_DEPTH = 32
MAX_DOCUMENTS = 100
MAX_RECORDS = 2000
MAX_EVIDENCE = 100
_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_JS_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}


class ParseFailure(Exception):
    def __init__(self, code, offset):
        self.code = code
        self.offset = offset


def _string_end(text, start):
    block = text.startswith('"""', start)
    i = start + (3 if block else 1)
    while i < len(text):
        if block:
            if text.startswith('\\"""', i):
                i += 4
            elif text.startswith('"""', i):
                return i + 3
            elif ord(text[i]) < 32 and text[i] not in '\t\r\n':
                raise ParseFailure("invalid_string_character", i)
            else:
                i += 1
        elif text[i] == '"':
            return i + 1
        elif text[i] == '\\':
            if i + 1 >= len(text):
                break
            escape = text[i + 1]
            if escape in '"\\/bfnrt':
                i += 2
            elif escape == 'u':
                if i + 2 < len(text) and text[i + 2] == '{':
                    end = text.find('}', i + 3)
                    digits = text[i + 3:end] if end >= 0 else ''
                    if (not re.fullmatch(r'[0-9a-fA-F]{1,6}', digits) or int(digits, 16) > 0x10ffff
                            or 0xd800 <= int(digits, 16) <= 0xdfff):
                        raise ParseFailure("invalid_string_escape", i)
                    i = end + 1
                elif re.fullmatch(r'[0-9a-fA-F]{4}', text[i + 2:i + 6]):
                    codepoint = int(text[i + 2:i + 6], 16)
                    if 0xd800 <= codepoint <= 0xdbff:
                        low = text[i + 8:i + 12]
                        if (text[i + 6:i + 8] != '\\u' or not re.fullmatch(r'[0-9a-fA-F]{4}', low)
                                or not 0xdc00 <= int(low, 16) <= 0xdfff):
                            raise ParseFailure("invalid_string_escape", i)
                        i += 12
                    elif 0xdc00 <= codepoint <= 0xdfff:
                        raise ParseFailure("invalid_string_escape", i)
                    else:
                        i += 6
                else:
                    raise ParseFailure("invalid_string_escape", i)
            else:
                raise ParseFailure("invalid_string_escape", i)
        elif ord(text[i]) < 32 and text[i] != '\t':
            raise ParseFailure("invalid_string_character", i)
        else:
            i += 1
    raise ParseFailure("unterminated_string", start)


def _line_end(text, start):
    match = re.compile(r'[\r\n]').search(text, start)
    return match.end() if match else len(text)


def _lex(text):
    tokens = []
    i = 0
    while i < len(text):
        char = text[i]
        if char in ' \t\r\n,\ufeff':
            i += 1
            continue
        if char == '#':
            i = _line_end(text, i)
            continue
        start = i
        if char == '"':
            i = _string_end(text, i)
            kind, value = 'literal', None
        elif text.startswith('...', i):
            kind = value = '...'
            i += 3
        elif char in '!$():=@[]{|}&':
            kind = value = char
            i += 1
        else:
            match = _NAME.match(text, i)
            if match:
                kind, value = 'name', match.group()
                i = match.end()
            else:
                match = _NUMBER.match(text, i)
                if not match:
                    raise ParseFailure("invalid_character", i)
                i = match.end()
                if i < len(text) and (text[i] in '.0123456789' or _NAME.match(text, i)):
                    raise ParseFailure("invalid_number", start)
                kind, value = 'literal', None
        if len(tokens) >= MAX_TOKENS:
            raise ParseFailure("token_limit", start)
        tokens.append((kind, value, start))
    tokens.append(('eof', None, len(text)))
    return tokens


class _Parser:
    def __init__(self, text, position):
        self.tokens = _lex(text)
        self.index = 0
        self.position = position

    def token(self):
        return self.tokens[self.index]

    def fail(self, code="invalid_structure"):
        raise ParseFailure(code, self.token()[2])

    def take(self, kind):
        if self.token()[0] != kind:
            self.fail()
        token = self.token()
        self.index += 1
        return token

    def accept(self, kind):
        if self.token()[0] == kind:
            return self.take(kind)
        return None

    def depth(self, depth):
        if depth > MAX_DEPTH:
            self.fail("depth_limit")

    def type(self, depth=0):
        self.depth(depth)
        if self.accept('['):
            result = '[' + self.type(depth + 1)
            self.take(']')
            result += ']'
        else:
            result = self.take('name')[1]
        if self.accept('!'):
            result += '!'
        return result

    def value(self, depth=0, constant=False):
        self.depth(depth)
        if self.accept('$'):
            if constant:
                self.fail()
            self.take('name')
        elif self.accept('['):
            while not self.accept(']'):
                self.value(depth + 1, constant)
        elif self.accept('{'):
            while not self.accept('}'):
                self.take('name')
                self.take(':')
                self.value(depth + 1, constant)
        elif self.token()[0] in {'literal', 'name'}:
            self.index += 1
        else:
            self.fail()

    def arguments(self):
        if not self.accept('('):
            return
        count = 0
        while not self.accept(')'):
            self.take('name')
            self.take(':')
            self.value()
            count += 1
        if not count:
            self.fail()

    def directives(self, constant=False):
        while self.accept('@'):
            self.take('name')
            if constant and self.accept('('):
                count = 0
                while not self.accept(')'):
                    self.take('name')
                    self.take(':')
                    self.value(constant=True)
                    count += 1
                if not count:
                    self.fail()
            else:
                self.arguments()

    def selections(self, fields, spreads, path=(), response=(), depth=0):
        self.depth(depth)
        self.take('{')
        count = 0
        while not self.accept('}'):
            count += 1
            if self.accept('...'):
                start = self.tokens[self.index - 1][2]
                condition = None
                if self.token()[0] == 'name' and self.token()[1] != 'on':
                    name = self.take('name')[1]
                    spreads.append({"name": name, "path": list(path), "position": self.position(start)})
                    self.directives()
                    continue
                if self.token()[1] == 'on':
                    self.take('name')
                    condition = self.take('name')[1]
                spreads.append({"name": None, "type_condition": condition, "path": list(path),
                                "position": self.position(start)})
                self.directives()
                self.selections(fields, spreads, path, response, depth + 1)
                continue
            first = self.take('name')
            alias = None
            name = first[1]
            if self.accept(':'):
                alias = name
                name = self.take('name')[1]
            child = path + (name,)
            response_child = response + (alias or name,)
            fields.append({"name": name, "alias": alias, "path": list(child),
                           "response_path": list(response_child), "position": self.position(first[2])})
            self.arguments()
            self.directives()
            if self.token()[0] == '{':
                self.selections(fields, spreads, child, response_child, depth + 1)
        if not count:
            self.fail()

    def document(self):
        operations, fragments = [], []
        while self.token()[0] != 'eof':
            start = self.token()[2]
            fields, spreads, variables = [], [], []
            if self.token()[0] == '{':
                kind, name = 'query', None
            else:
                kind = self.take('name')[1]
                if kind == 'fragment':
                    name = self.take('name')[1]
                    if name == 'on' or self.take('name')[1] != 'on':
                        self.fail()
                    condition = self.take('name')[1]
                    self.directives()
                    self.selections(fields, spreads)
                    fragments.append({"name": name, "type_condition": condition, "fields": fields,
                                      "spreads": spreads, "position": self.position(start)})
                    continue
                if kind not in {'query', 'mutation', 'subscription'}:
                    self.fail("unsupported_definition")
                name = self.take('name')[1] if self.token()[0] == 'name' else None
                if self.accept('('):
                    while not self.accept(')'):
                        variable = self.take('$')
                        variable_name = self.take('name')[1]
                        self.take(':')
                        variable_type = self.type()
                        variables.append({"name": variable_name, "type": variable_type,
                                          "position": self.position(variable[2])})
                        if self.accept('='):
                            self.value(constant=True)
                        self.directives(constant=True)
                    if not variables:
                        self.fail()
                self.directives()
            self.selections(fields, spreads)
            operations.append({"kind": kind, "name": name, "variables": variables, "fields": fields,
                               "spreads": spreads, "position": self.position(start)})
        if not operations and not fragments:
            self.fail("empty_document")
        return {"operations": operations, "fragments": fragments}


def _positioner(text, base_line=1, base_column=1, offsets=None):
    line_starts = [0] + [match.end() for match in re.finditer(r'\r\n|\r|\n', text)]

    def position(offset):
        if offsets is not None:
            offset = offsets[min(offset, len(offsets) - 1)]
        line = bisect.bisect_right(line_starts, offset) - 1
        column = offset - line_starts[line] + (1 if line else base_column)
        return {"offset": offset, "line": base_line + line, "column": column}

    return position


def _path(store, value):
    if not isinstance(value, str) or not value or '\x00' in value:
        raise ForgeError("GraphQL input path must be a nonempty string")
    path = Path(value)
    if not path.is_absolute():
        path = store.root / path
    try:
        path = path.resolve()
        path.relative_to(store.root)
    except (ValueError, RuntimeError):
        raise ForgeError("GraphQL inputs must remain inside the project directory") from None
    if not path.is_file():
        raise ForgeError("GraphQL input must be an existing regular project file")
    return path


def _read_file(path):
    with path.open('rb') as handle:
        raw = handle.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ForgeError("GraphQL source/index exceeds the 1048576-byte file limit")
    try:
        return raw.decode('utf-8-sig'), hashlib.sha256(raw).hexdigest(), len(raw)
    except UnicodeError:
        raise ForgeError("GraphQL source/index must be UTF-8") from None


def _js_strings(text):
    """Scan strings, never interpret JavaScript expressions or template substitutions."""
    i, previous = 0, None
    warnings = []
    strings = []
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        if text.startswith('//', i):
            i = _line_end(text, i)
            continue
        if text.startswith('/*', i):
            end = text.find('*/', i + 2)
            if end < 0:
                warnings.append(("unterminated_js_comment", i))
                break
            i = end + 2
            continue
        if text[i] == '/':
            # Distinguishing regular expressions from division needs a JS parser.
            warnings.append(("unsupported_js_slash_remaining_source_omitted", i))
            break
        if text[i] in "\"'`":
            start, quote = i, text[i]
            tagged = quote == '`' and previous in {'gql', 'graphql'}
            i += 1
            chars, offsets = [], []
            unsupported = None
            while i < len(text) and text[i] != quote:
                if quote == '`' and text.startswith('${', i):
                    warnings.append(("template_interpolation_remaining_source_omitted", start))
                    return strings, warnings
                if text[i] == '\\':
                    escape_start = i
                    i += 1
                    if i >= len(text):
                        break
                    escapes = {'n': '\n', 'r': '\r', 't': '\t', 'b': '\b', 'f': '\f',
                               'v': '\v', '0': '\0', '\\': '\\', '"': '"', "'": "'", '`': '`', '$': '$'}
                    if text[i] in escapes:
                        chars.append(escapes[text[i]])
                        offsets.append(escape_start)
                        i += 1
                    elif text[i] in '\r\n':
                        if text[i:i + 2] == '\r\n':
                            i += 1
                        i += 1
                    elif text[i] in {'u', 'x'}:
                        length = 4 if text[i] == 'u' else 2
                        digits = text[i + 1:i + 1 + length]
                        if not re.fullmatch(r'[0-9a-fA-F]{%d}' % length, digits):
                            unsupported = "unsupported_js_escape"
                            i += 1
                        else:
                            chars.append(chr(int(digits, 16)))
                            offsets.append(escape_start)
                            i += length + 1
                    else:
                        unsupported = "unsupported_js_escape"
                        i += 1
                elif text[i] in '\r\n' and quote != '`':
                    unsupported = "invalid_js_string"
                    i += 1
                else:
                    chars.append(text[i])
                    offsets.append(i)
                    i += 1
            if i >= len(text):
                warnings.append(("unterminated_js_string", start))
                break
            offsets.append(i)
            i += 1
            value = ''.join(chars)
            candidate = tagged or bool(re.match(r'\s*(?:#graphql\b|(?:query|mutation|subscription|fragment)\b)', value))
            if unsupported:
                warnings.append((unsupported, start))
            elif quote == '`' and not tagged:
                warnings.append(("untagged_template_omitted", start))
            elif candidate:
                strings.append((value, offsets, start))
            previous = None
            continue
        match = _NAME.match(text, i)
        if match:
            previous = match.group()
            i = match.end()
        else:
            previous = None
            i += 1
    return strings, warnings


class _Analysis:
    def __init__(self):
        self.documents = []
        self.warnings = []
        self.total = 0
        self.attempted = 0
        self.omitted = False

    def warn(self, code, citation, position=None):
        self.omitted = True
        if len(self.warnings) < MAX_RECORDS:
            item = {"code": code, "citation": citation}
            if position is not None:
                item['position'] = position
            self.warnings.append(item)

    def document(self, text, citation, position=None, operation_name=None, persisted=None):
        if self.attempted >= MAX_DOCUMENTS:
            self.warn("document_limit", citation)
            return
        self.attempted += 1
        result = {"citation": citation, "operation_name": operation_name, "persisted_query": persisted,
                  "document_available": isinstance(text, str), "operations": [], "fragments": []}
        self.documents.append(result)
        if not isinstance(text, str):
            result['status'] = 'document_absent'
            return
        if len(text) > MAX_DOCUMENT_CHARACTERS or self.total + len(text) > MAX_TOTAL_CHARACTERS:
            result['status'] = 'omitted'
            self.warn("document_size_limit" if len(text) > MAX_DOCUMENT_CHARACTERS else "total_size_limit", citation)
            return
        self.total += len(text)
        position = position or _positioner(text)
        try:
            result.update(_Parser(text, position).document())
        except ParseFailure as error:
            result['status'] = 'parse_failed'
            result['failure'] = {"code": error.code, "position": position(error.offset)}
            self.omitted = True
            return
        result['status'] = 'parsed'
        names = [operation['name'] for operation in result['operations']]
        result['operation_name_matches'] = operation_name in names if operation_name else None
        defined = {fragment['name'] for fragment in result['fragments']}
        result['undefined_fragment_names'] = sorted({spread['name'] for owner in
            result['operations'] + result['fragments'] for spread in owner['spreads']
            if spread['name'] is not None and spread['name'] not in defined})

    def envelope(self, value, citation, batch=False):
        if isinstance(value, list):
            if batch:
                self.warn("nested_request_batch_omitted", citation)
                return
            if len(value) > MAX_DOCUMENTS:
                self.warn("batch_document_limit", citation)
            for index, item in enumerate(value[:MAX_DOCUMENTS]):
                self.envelope(item, {**citation, "batch_index": index}, batch=True)
            return
        if not isinstance(value, dict):
            self.warn("invalid_request_envelope", citation)
            return
        if not any(key in value for key in ('query', 'operationName', 'extensions')):
            self.warn("no_graphql_request_metadata", citation)
            return
        name = value.get('operationName')
        if name is not None and (not isinstance(name, str) or len(name) > MAX_DOCUMENT_CHARACTERS
                                 or not _NAME.fullmatch(name)):
            self.warn("invalid_operation_name_omitted", citation)
            name = None
        extensions = value.get('extensions')
        if isinstance(extensions, str) and len(extensions) > MAX_FILE_BYTES:
            self.warn("extensions_size_limit", citation)
            extensions = None
        if isinstance(extensions, str):
            try:
                extensions = json.loads(extensions)
            except (ValueError, RecursionError):
                extensions = None
                self.warn("invalid_extensions_omitted", citation)
        persisted = extensions.get('persistedQuery') if isinstance(extensions, dict) else None
        metadata = None
        if isinstance(persisted, dict):
            metadata = {"present": True, "sha256_hash": None, "version": None, "document_recovered": False}
            digest = persisted.get('sha256Hash')
            if isinstance(digest, str) and re.fullmatch(r'[0-9a-fA-F]{64}', digest):
                metadata['sha256_hash'] = digest.lower()
            elif digest is not None:
                self.warn("invalid_persisted_hash_omitted", citation)
            if type(persisted.get('version')) is int and 0 <= persisted['version'] <= 2147483647:
                metadata['version'] = persisted['version']
        text = value.get('query')
        if text is not None and not isinstance(text, str):
            self.warn("invalid_query_type_omitted", citation)
            text = None
        self.document(text, citation, operation_name=name, persisted=metadata)

    def content(self, text, citation, suffix, base_line=1, base_column=1):
        position = _positioner(text, base_line, base_column)
        if suffix in _JS_SUFFIXES:
            self.warn("js_extraction_limited_to_strings_and_gql_graphql_tags", citation)
            strings, warnings = _js_strings(text)
            for code, offset in warnings:
                self.warn(code, citation, position(offset))
            for value, offsets, start in strings:
                self.document(value, {**citation, "string_position": position(start)},
                              _positioner(text, base_line, base_column, offsets))
        elif suffix == '.json':
            try:
                value = json.loads(text)
            except (ValueError, RecursionError):
                self.warn("invalid_json_envelope", citation)
                return
            self.envelope(value, citation)
        elif suffix in {'.graphql', '.gql', '.txt'}:
            self.document(text, citation, position)
        else:
            self.warn("unsupported_source_format", citation)


def _citation(record, location=None):
    citation = {"evidence_id": record['id'], "kind": record['kind'], "created_at": record['created_at']}
    if location:
        citation['location'] = {key: scrub_text(value) if isinstance(value, str) else value
                                for key, value in location.items() if key in
                                {'source', 'member', 'line', 'column', 'byte_offset', 'encoding', 'index_source', 'kind'}
                                and isinstance(value, (str, int))}
    return citation


def _static(analysis, record, store):
    data = record['data']
    citation = _citation(record)
    analysis.warn("static_records_are_redacted_partial_observations", citation)
    if data.get('truncated'):
        analysis.warn("underlying_static_input_truncated", citation)
    if record['kind'] == 'analysis':
        path = _path(store, data.get('path', ''))
        text, digest, size = _read_file(path)
        recorded_hash = data.get('index_sha256')
        if 'index_sha256' in data:
            if not isinstance(recorded_hash, str) or not re.fullmatch(r'[0-9a-f]{64}', recorded_hash):
                raise ForgeError("GraphQL static index has invalid recorded SHA256")
            if recorded_hash != digest:
                raise ForgeError("GraphQL static index SHA256 does not match its evidence")
        else:
            analysis.warn("legacy_static_index_identity_unverified", citation)
        if 'index_size' in data and (type(data['index_size']) is not int or data['index_size'] < 0
                                     or data['index_size'] != size):
            raise ForgeError("GraphQL static index size does not match its evidence")
        citation.update(index_sha256=digest, index_size=size,
                        index_recorded_identity_verified='index_sha256' in data,
                        index_recorded_size_verified='index_size' in data)
        rows = text.splitlines()
        if len(rows) > MAX_RECORDS:
            analysis.warn("static_record_limit", citation)
        items = []
        for row in rows[:MAX_RECORDS]:
            if len(row) > 128 * 1024:
                analysis.warn("index_record_size_limit", citation)
                continue
            try:
                item = json.loads(row)
            except (ValueError, RecursionError):
                analysis.warn("invalid_index_record", citation)
                continue
            items.append(item)
    else:
        items = data.get('matches', [])
        if not isinstance(items, list):
            raise ForgeError("GraphQL search evidence has invalid matches")
        if len(items) > MAX_RECORDS:
            analysis.warn("static_record_limit", citation)
        items = items[:MAX_RECORDS]
    group, location, last, group_size = [], None, None, 0

    def flush():
        if group:
            suffix = Path(str(location.get('member', location.get('source', '')))).suffix.lower()
            analysis.content('\n'.join(group), {**citation, **_citation(record, location)}, suffix,
                             location.get('line', 1), location.get('column', 1))

    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get('text'), str):
            analysis.warn("invalid_static_record", citation)
            last = None
            continue
        if any(key in item and (type(item[key]) is not int or item[key] < 1) for key in ('line', 'column')):
            analysis.warn("invalid_static_position", citation)
            last = None
            continue
        if len(item['text']) > 4096:
            analysis.warn("static_text_chunk_limit", _citation(record, item))
            last = None
            continue
        identity = (item.get('source'), item.get('member'), item.get('encoding'))
        contiguous = (last is not None and identity == last[0] and type(item.get('line')) is int
                      and item['line'] == last[1] + 1 and item.get('column', 1) == 1)
        if group and (not contiguous or group_size + len(item['text']) + 1 > MAX_DOCUMENT_CHARACTERS):
            if contiguous:
                analysis.warn("static_contiguous_group_size_limit", citation)
            flush()
            group = []
            group_size = 0
        if not group:
            location = item
        group.append(item['text'])
        group_size += len(item['text']) + 1
        last = (identity, item.get('line')) if type(item.get('line')) is int else None
    flush()


def _http(analysis, record):
    data = record['data']
    expected = 'har_import' if record['kind'] == 'har_exchange' else 'live_probe'
    request, response = data.get('request'), data.get('response')
    if (data.get('source') != expected or not isinstance(request, dict) or not isinstance(response, dict)
            or not isinstance(request.get('url'), str) or not isinstance(request.get('method'), str)):
        raise ForgeError("GraphQL HTTP evidence has invalid request/provenance")
    status = response.get('status')
    citation = {**_citation(record), "observation": 'captured_http' if expected == 'har_import' else 'live_http',
                "response_observed": type(status) is int and 100 <= status <= 599,
                "request_success_not_inferred": True, "stored_redacted_observation": True}
    body = request.get('body')
    headers = request.get('headers', {})
    content_type = next((str(value).lower().split(';', 1)[0].strip() for key, value in headers.items()
                         if str(key).lower() == 'content-type'), '') if isinstance(headers, dict) else ''
    if isinstance(body, str):
        if len(body) > MAX_FILE_BYTES:
            analysis.warn("request_body_size_limit", citation)
        elif content_type == 'application/graphql':
            analysis.document(body, {**citation, "request_location": 'body'})
        else:
            try:
                value = dict(parse_qsl(body, keep_blank_values=True, max_num_fields=MAX_RECORDS)) if (
                    content_type == 'application/x-www-form-urlencoded') else json.loads(body)
            except (ValueError, RecursionError):
                analysis.warn("unparsed_request_body", citation)
            else:
                analysis.envelope(value, {**citation, "request_location": 'body'})
    elif isinstance(body, (dict, list)):
        analysis.envelope(body, {**citation, "request_location": 'body'})
    url = request.get('url')
    if isinstance(url, str):
        if len(url) > MAX_FILE_BYTES:
            analysis.warn("request_url_size_limit", citation)
            return
        try:
            pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True, max_num_fields=MAX_RECORDS)
        except ValueError:
            analysis.warn("unparsed_request_url", citation)
            return
        envelope = {key: value for key, value in pairs if key in {'query', 'operationName', 'extensions'}}
        if envelope:
            analysis.envelope(envelope, {**citation, "request_location": 'url_query'})


def graphql_analyze(args, store):
    ids = list(dict.fromkeys(args.evidence))
    if not args.source and not ids:
        raise ForgeError("graphql-analyze requires an explicit source file and/or --evidence ID")
    if len(ids) > MAX_EVIDENCE:
        raise ForgeError("graphql-analyze accepts at most 100 evidence IDs")
    analysis = _Analysis()
    if args.source:
        path = _path(store, args.source)
        try:
            text, digest, _ = _read_file(path)
        except OSError:
            raise ForgeError("Cannot read GraphQL source file") from None
        citation = {"source": scrub_text(path.relative_to(store.root).as_posix()), "sha256": digest,
                    "observation": "explicit_source", "offset_space": "decoded_source_characters"}
        analysis.content(text, citation, path.suffix.lower())
    for evidence_id in ids:
        record = store.get(evidence_id)
        if not isinstance(record.get('data'), dict):
            raise ForgeError("GraphQL evidence data must be an object")
        if record['kind'] in {'http_probe', 'har_exchange'}:
            _http(analysis, record)
        elif record['kind'] == 'search' or (record['kind'] == 'analysis' and record['data'].get('tool') == 'static_index'):
            try:
                _static(analysis, record, store)
            except OSError:
                raise ForgeError("Cannot read cited GraphQL static index") from None
        else:
            raise ForgeError("GraphQL evidence must be HTTP, search, or static_index")
    return store.add('analysis', {"schema_version": 1, "tool": "graphql_analyze", "evidence_ids": ids,
        "documents": analysis.documents, "warnings": analysis.warnings, "omissions": analysis.omitted,
        "empty": not analysis.documents, "schema_inferred": False, "network_performed": False,
        "values_exported": False, "fragment_expansion_performed": False,
        "limits": {"file_bytes": MAX_FILE_BYTES, "document_characters": MAX_DOCUMENT_CHARACTERS,
                   "total_document_characters": MAX_TOTAL_CHARACTERS, "lexical_items_per_document": MAX_TOKENS,
                   "structural_depth": MAX_DEPTH, "documents": MAX_DOCUMENTS,
                   "static_records_per_evidence": MAX_RECORDS, "warnings": MAX_RECORDS,
                   "evidence_ids": MAX_EVIDENCE}})


def register(subparsers):
    parser = subparsers.add_parser('graphql-analyze', help='Parse explicit GraphQL source or stored requests without exporting values')
    parser.add_argument('source', nargs='?', help='Explicit project-relative UTF-8 source/document/envelope file')
    parser.add_argument('--evidence', action='append', default=[], metavar='ID', help='Stored HTTP, static_index, or search evidence; repeatable')
    parser.set_defaults(handler=graphql_analyze)

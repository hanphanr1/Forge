"""Cross-file Java caller-name candidates for the FORGE android-caller-map.

``android_caller_map`` searches one cited JADX output tree for the token ``NAME(`` and
reports, per candidate, the file, the enclosing class name derived from the path, the
receiver shape read from the preceding tokens, and, for unqualified calls, the classes
that file imports or shares a package with.

Everything here is lexical. The Java tokenizer is shared with ``forge_java_trace``, so
comments, strings, character literals and text blocks are single tokens and can never
produce a candidate. Declarations of ``NAME`` in the scanned file are excluded by a
conservative "type/modifier run before the name" rule, and shapes that rule cannot
decide are emitted with ``declaration_ambiguous`` instead of being dropped. Overloads,
generics, inheritance, interfaces, implicit receivers, lambdas, method references and
reflection are never resolved and ``resolution`` stays ``cross_file_name_candidate``.
"""

from __future__ import annotations

import bisect
import hashlib
import os
import re
from pathlib import Path

from forge_artifacts import _input, _positive, _relative
from forge_core import ForgeError
from forge_java_trace import tokenize

SCHEMA = "forge.android-caller-map/v1"
TOOL = "android"
ACTION = "caller-map"
RESOLUTION = "cross_file_name_candidate"
JAVA_SUFFIX = ".java"
KOTLIN_SUFFIX = ".kt"
SOURCE_SUFFIXES = (JAVA_SUFFIX, KOTLIN_SUFFIX)
# Hard bound on the source listing that feeds possible-owner inference.
MAX_TREE_SOURCES = 500000
# Owner candidates reported for one unqualified call.
MAX_POSSIBLE_OWNERS = 8
MAX_METHOD_LENGTH = 256
MAX_CLASS_LENGTH = 512
MAX_ITEMS = 100000
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILES = 500000

_WORD = r"[A-Za-z_$\u0080-\uffff][A-Za-z0-9_$\u0080-\uffff]*"
_IDENTIFIER = re.compile(_WORD + r"\Z")
_CLASS_NAME = re.compile(_WORD + r"(?:\." + _WORD + r")*\Z")
# Line breaks recognized by str.splitlines(), so line numbers match the source text.
_LINE_BREAKS = frozenset("\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")

# receiver_kind values. "this" covers this. and super., which both name the enclosing
# instance; "expression" is a receiver the tokens cannot name (call result, index,
# literal); "constructor" is new NAME( rather than a method call.
BARE = "bare"
THIS = "this"
OWNER_CLASS = "owner_class"
NAMED_RECEIVER = "named_receiver"
EXPRESSION = "expression"
CONSTRUCTOR = "constructor"
RECEIVER_KINDS = (BARE, THIS, OWNER_CLASS, NAMED_RECEIVER, EXPRESSION, CONSTRUCTOR)
SKIP_DECLARATION = "declaration"
SKIP_ANNOTATION = "annotation"

# Words that end a statement or open an expression, so a following word is a call name.
_CALL_WORDS = frozenset({"return", "throw", "do", "else", "case", "yield", "assert",
                         "instanceof", "break", "continue"})
# A statement cannot continue across these, which bounds the generic-run scan.
_STATEMENT_BOUNDARIES = frozenset({";", "{", "}", "(", ")"})

SCOPE = ("Lexical name matching only: a file whose text contains the name followed by '(' is a candidate "
         "caller, not a resolved call graph edge. Overloads, generics, inheritance, interfaces, implicit "
         "receivers, lambdas, method references and reflection are not resolved; possible owners are classes "
         "the file imports or shares a package with, not classes known to declare the name, and class names "
         "come from the output path, so nested and anonymous classes are attributed to their file. A missing "
         "candidate is not proof of absence, because item/file/byte caps, unparsed Kotlin, excluded "
         "declarations and ambiguous sites all hide text. Confirm a candidate against decompiled context or "
         "captured/live HTTP before treating it as a dispatch.")


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


def _simple(class_name):
    return class_name.rpartition(".")[2]


def _package(class_name):
    return class_name.rpartition(".")[0]


def _generic_head(tokens, code, position):
    """Code index of the token before the balanced ``<...>`` run ending at `position`."""
    depth = 0
    index = position
    while index >= 0:
        value = tokens[code[index]][1]
        if value == ">":
            depth += 1
        elif value == "<":
            depth -= 1
            if depth == 0:
                return index - 1
            if depth < 0:
                return None
        elif value in _STATEMENT_BOUNDARIES:
            return None
        index -= 1
    return None


def _receiver_from_chain(tokens, code, last, tree_simple):
    """Receiver shape from the dotted chain whose last word sits at code index `last`."""
    parts = []
    index = last
    while index >= 0:
        token = tokens[code[index]]
        if token[0] != "word":
            break
        parts.append(token[1])
        index -= 1
        if index < 0:
            break
        token = tokens[code[index]]
        if token[0] != "punct" or token[1] != ".":
            break
        index -= 1
    if not parts:
        return EXPRESSION, None, False
    parts.reverse()
    head = tokens[code[index]][1] if index >= 0 else ""
    name = ".".join(parts)
    if parts[-1] in ("this", "super"):
        return THIS, name, False
    if head == "new":
        return CONSTRUCTOR, None, False
    if parts[-1][:1].isupper() or parts[-1] in tree_simple:
        return OWNER_CLASS, name, False
    return NAMED_RECEIVER, name, False


def _classify(tokens, code, position, tree_simple):
    """Receiver shape for a call name at code index `position`.

    Returns a ``(receiver_kind, receiver, declaration_ambiguous)`` triple; the kind is
    SKIP_DECLARATION for the scanned file's own method signatures and SKIP_ANNOTATION for
    ``@NAME(...)`` uses. Only a preceding identifier or type run makes a declaration: an
    operator, separator or keyword before the name always leaves a call.
    """
    if position == 0:
        return BARE, None, False
    token = tokens[code[position - 1]]
    kind, value = token[0], token[1]
    if kind == "word":
        if value in ("new", "this", "super"):
            return CONSTRUCTOR, None, False
        if value in _CALL_WORDS:
            return BARE, None, False
        return SKIP_DECLARATION, None, False
    if kind != "punct":
        return BARE, None, False
    if value == ".":
        return _receiver_from_chain(tokens, code, position - 2, tree_simple)
    if value == "@":
        return SKIP_ANNOTATION, None, False
    if value == "]":
        return SKIP_DECLARATION, None, False
    if value in ("<", ">"):
        head = _generic_head(tokens, code, position - 1)
        if head is None or head < 0:
            return BARE, None, True
        token = tokens[code[head]]
        if token[0] == "word":
            if token[1] == "new":
                return CONSTRUCTOR, None, False
            return SKIP_DECLARATION, None, False
        if token[0] == "punct" and token[1] == ".":
            return _receiver_from_chain(tokens, code, head - 1, tree_simple)
        return BARE, None, True
    return BARE, None, False


def _imports(tokens, code):
    """Imported qualified names, simple names and wildcard packages of one file."""
    exact, simple, wildcard = set(), set(), set()
    for position in range(len(code)):
        token = tokens[code[position]]
        if token[0] != "word" or token[1] != "import":
            continue
        cursor = position + 1
        is_static = cursor < len(code) and tokens[code[cursor]][1] == "static"
        if is_static:
            cursor += 1
        parts = []
        while cursor < len(code):
            token = tokens[code[cursor]]
            if token[0] == "word":
                parts.append(token[1])
            elif token[1] == "*":
                parts.append("*")
            elif token[1] != ".":
                break
            cursor += 1
        if not parts:
            continue
        if parts[-1] == "*":
            wildcard.add(".".join(parts[:-1]))
            continue
        if is_static and len(parts) > 1:
            parts.pop()
        exact.add(".".join(parts))
        simple.add(parts[-1])
    return exact, simple, wildcard


def _possible_owners(tree_classes, by_package, by_simple, file_package, exact, simple, wildcard):
    """Bounded classes this file could name for an unqualified call."""
    names = set(by_package.get(file_package, ()))
    for package in wildcard:
        names.update(by_package.get(package, ()))
    names.update(name for name in exact if name in tree_classes)
    for name in simple:
        names.update(by_simple.get(name, ()))
    ordered = sorted(names)
    return ordered[:MAX_POSSIBLE_OWNERS], len(ordered) > MAX_POSSIBLE_OWNERS


def _owner_match(owner, name):
    """--class attribution compares simple names, all this tool matches on."""
    return bool(name) and _simple(name) == _simple(owner)


def _attributed(owner, kind, receiver, class_name, owners, method_name):
    """Whether one candidate can name ``owner`` under the lexical receiver rules."""
    if kind == THIS:
        return _owner_match(owner, class_name)
    if kind == OWNER_CLASS:
        return _owner_match(owner, receiver)
    if kind == CONSTRUCTOR:
        return _owner_match(owner, method_name)
    if kind == BARE:
        return any(_owner_match(owner, name) for name in owners)
    return False


def android_caller_map(args, store):
    for name, value, maximum in (("max-items", args.max_items, MAX_ITEMS),
                                 ("max-files", args.max_files, MAX_FILES),
                                 ("max-file-bytes", args.max_file_bytes, MAX_FILE_BYTES),
                                 ("max-total-bytes", args.max_total_bytes, MAX_TOTAL_BYTES)):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ForgeError(f"--{name} must be an integer from 1 to {maximum}")
    method_name = args.method.strip()
    if len(method_name) > MAX_METHOD_LENGTH or not _IDENTIFIER.fullmatch(method_name):
        raise ForgeError("--method must be one Java identifier (letters, digits, _ or $, not starting with a digit)")
    owner = (getattr(args, "owner_class", None) or "").strip().replace("/", ".")
    if owner.endswith(JAVA_SUFFIX):
        owner = owner[:-len(JAVA_SUFFIX)]
    if len(owner) > MAX_CLASS_LENGTH or (owner and not _CLASS_NAME.fullmatch(owner)):
        raise ForgeError("--class must be a dotted Java class name")
    jadx_record = store.get(args.jadx_evidence)
    jadx_data = jadx_record["data"] if isinstance(jadx_record.get("data"), dict) else {}
    if jadx_record["kind"] != "analysis" or jadx_data.get("tool") != "jadx" or \
            jadx_data.get("status") not in {"success", "partial"}:
        raise ForgeError("--jadx-evidence must cite a successful or partial JADX analysis record")
    output_path = jadx_data.get("output_path")
    if not isinstance(output_path, str) or not output_path:
        raise ForgeError("JADX evidence output directory is unavailable")
    output_root = _input(store, output_path, local=True)
    if not output_root.is_dir():
        raise ForgeError("JADX evidence output directory is unavailable")
    source_root = output_root / "sources" if (output_root / "sources").is_dir() else output_root
    sources = []
    tree_classes, by_package, by_simple = set(), {}, {}
    tree_simple = set()
    skipped_kt = files_omitted = 0
    truncated = False
    for directory, dirs, files in os.walk(source_root, followlinks=False):
        kept_dirs = []
        for name in sorted(dirs):
            child = Path(directory) / name
            attributes = getattr(child.lstat(), "st_file_attributes", 0) if child.exists() else 0
            if child.is_symlink() or attributes & 0x400:
                continue
            kept_dirs.append(name)
        dirs[:] = kept_dirs
        for name in sorted(files):
            suffix = Path(name).suffix.lower()
            if suffix not in SOURCE_SUFFIXES:
                continue
            path = Path(directory) / name
            if path.is_symlink():
                files_omitted += 1
                continue
            if len(sources) >= MAX_TREE_SOURCES:
                truncated = True
                break
            class_name = path.relative_to(source_root).with_suffix("").as_posix().replace("/", ".")
            sources.append((path, suffix, class_name))
            tree_classes.add(class_name)
            by_package.setdefault(_package(class_name), []).append(class_name)
            by_simple.setdefault(_simple(class_name), []).append(class_name)
            tree_simple.add(_simple(class_name))
            skipped_kt += suffix == KOTLIN_SUFFIX
        if truncated:
            break
    candidates = []
    candidate_count = candidates_omitted = candidates_filtered = 0
    declarations_skipped = annotation_uses_skipped = 0
    files_scanned = bytes_scanned = bytes_omitted = 0
    for path, suffix, class_name in sources:
        if suffix != JAVA_SUFFIX:
            continue
        if files_scanned >= args.max_files:
            files_omitted += 1
            truncated = True
            break
        try:
            size = path.stat().st_size
        except OSError:
            files_omitted += 1
            continue
        if size > args.max_file_bytes:
            files_omitted += 1
            bytes_omitted += size
            truncated = True
            continue
        if bytes_scanned + size > args.max_total_bytes:
            files_omitted += 1
            bytes_omitted += size
            truncated = True
            break
        try:
            content = path.read_bytes()
        except OSError:
            files_omitted += 1
            continue
        files_scanned += 1
        bytes_scanned += len(content)
        relative = _relative(store, path)
        digest = None
        owners = None
        text = content.decode("utf-8", "replace")
        tokens = tokenize(text)
        code = [index for index, token in enumerate(tokens) if token[0] != "comment"]
        starts = _line_starts(text)
        for position in range(len(code)):
            token = tokens[code[position]]
            if token[0] != "word" or token[1] != method_name:
                continue
            if position + 1 >= len(code) or tokens[code[position + 1]][1] != "(":
                continue
            kind, receiver, ambiguous = _classify(tokens, code, position, tree_simple)
            if kind == SKIP_DECLARATION:
                declarations_skipped += 1
                continue
            if kind == SKIP_ANNOTATION:
                annotation_uses_skipped += 1
                continue
            if kind == BARE:
                if owners is None:
                    owners = _possible_owners(tree_classes, by_package, by_simple, _package(class_name),
                                              *_imports(tokens, code))
                possible, owners_omitted = owners
            else:
                possible, owners_omitted = [], False
            if owner and not _attributed(owner, kind, receiver, class_name, possible, method_name):
                candidates_filtered += 1
                continue
            if candidate_count >= args.max_items:
                candidates_omitted += 1
                truncated = True
                continue
            if digest is None:
                digest = hashlib.sha256(content).hexdigest()
            candidates.append({
                "file": relative, "class_name": class_name,
                "line": bisect.bisect_right(starts, token[2]),
                "receiver_kind": kind, "receiver": receiver, "possible_owners": possible,
                "possible_owners_omitted": owners_omitted,
                "declaration_ambiguous": ambiguous, "source_sha256": digest})
            candidate_count += 1
    return store.add("analysis", {
        "schema": SCHEMA, "tool": TOOL, "action": ACTION, "success": True,
        "method_name": method_name, "owner_class": owner,
        "jadx_evidence_id": jadx_record["id"], "evidence_ids": [jadx_record["id"]],
        "source_root": _relative(store, source_root),
        "resolution": RESOLUTION, "overload_aware": False,
        "candidate_count": candidate_count, "candidates_omitted": candidates_omitted,
        "candidates_filtered": candidates_filtered, "declarations_skipped": declarations_skipped,
        "annotation_uses_skipped": annotation_uses_skipped,
        "files_enumerated": len(sources), "files_scanned": files_scanned,
        "files_skipped_kt": skipped_kt, "files_omitted": files_omitted,
        "bytes_scanned": bytes_scanned, "bytes_omitted": bytes_omitted,
        "caps": {"max_items": args.max_items, "max_files": args.max_files,
                 "max_file_bytes": args.max_file_bytes, "max_total_bytes": args.max_total_bytes,
                 "max_possible_owners": MAX_POSSIBLE_OWNERS},
        "candidates": candidates, "truncated": truncated, "scope": SCOPE})


def register(subparsers):
    parser = subparsers.add_parser("android-caller-map",
                                   help="Find cross-file caller-name candidates for one Java method in cited JADX output")
    parser.add_argument("--jadx-evidence", required=True, help="Successful or partial JADX evidence")
    parser.add_argument("--method", required=True, help="Java method name to search for")
    parser.add_argument("--class", dest="owner_class",
                        help="Optional dotted owner class: keep only candidates that can name it")
    parser.add_argument("--max-items", type=_positive, default=500, help="Maximum retained caller candidates")
    parser.add_argument("--max-files", type=_positive, default=50000, help="Maximum Java sources whose content is scanned")
    parser.add_argument("--max-file-bytes", type=_positive, default=16 * 1024 * 1024)
    parser.add_argument("--max-total-bytes", type=_positive, default=128 * 1024 * 1024)
    parser.set_defaults(handler=android_caller_map)

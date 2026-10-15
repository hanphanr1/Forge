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

``--cache`` (the default) memoizes one file's lexical fragments under
``.forge/cache/callers/<sha256>.json``, keyed by the source content digest and reached through
``index.json``, which records the store-relative path, size, nanosecond mtime and method name an
entry was written for; a hit therefore needs no source read, and ``a changed file re-parses``.
Fragments hold only text-derived facts, so tree-level owner inference and lowercase-receiver
promotion are recomputed against the live tree each run and a changed sibling cannot stale them.
Entries are size-bounded (oldest first) and a file edited to the same size and mtime is the one
pattern that can be served from a previous parse; pass ``--no-cache`` to re-read every source.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import tempfile
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

CACHE_SCHEMA = "forge.android-caller-map-cache/v1"
CACHE_INDEX_SCHEMA = "forge.android-caller-map-cache-index/v1"
CACHE_INDEX_NAME = "index.json"
CACHE_DIRECTORY = ("cache", "callers")
# Global bound on the cache directory; the oldest entry files are evicted first.
CACHE_CAP_BYTES = 512 * 1024 * 1024
# One entry holds a small record per call site, so its bytes must stay far below this multiple
# of the source size; a larger entry file is treated as corrupt instead of loaded.
CACHE_ENTRY_RATIO = 24
CACHE_ENTRY_FLOOR = 4096
_CACHE_FRAGMENT_KEYS = frozenset({"line", "receiver_kind", "receiver", "declaration_ambiguous"})
_CACHE_IMPORT_KEYS = ("exact", "simple", "wildcard")
_CACHE_SKIP_KEYS = ("declarations", "annotations")
_CACHE_PAYLOAD_FIELDS = ("candidates", "imports", "skipped", "method")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")

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


def _promote(kind, receiver, tree_simple):
    """Name a lowercase receiver as the owner class when the tree declares that class."""
    if kind == NAMED_RECEIVER and _simple(receiver or "") in tree_simple:
        return OWNER_CLASS
    return kind


def _parse_source(text, method_name):
    """Tree-independent lexical fragments of one Java source.

    Receiver classification runs without the tree's simple class names, so the result depends
    only on the text and the method name; ``_promote`` applies the tree-dependent half later.
    """
    tokens = tokenize(text)
    code = [index for index, token in enumerate(tokens) if token[0] != "comment"]
    starts = _line_starts(text)
    fragments = []
    declarations = annotations = 0
    for position in range(len(code)):
        token = tokens[code[position]]
        if token[0] != "word" or token[1] != method_name:
            continue
        if position + 1 >= len(code) or tokens[code[position + 1]][1] != "(":
            continue
        kind, receiver, ambiguous = _classify(tokens, code, position, frozenset())
        if kind == SKIP_DECLARATION:
            declarations += 1
            continue
        if kind == SKIP_ANNOTATION:
            annotations += 1
            continue
        fragments.append({"line": bisect.bisect_right(starts, token[2]), "receiver_kind": kind,
                          "receiver": receiver, "declaration_ambiguous": ambiguous})
    if any(fragment["receiver_kind"] == BARE for fragment in fragments):
        exact, simple, wildcard = _imports(tokens, code)
        imports = {"exact": sorted(exact), "simple": sorted(simple), "wildcard": sorted(wildcard)}
    else:
        imports = {"exact": [], "simple": [], "wildcard": []}
    return fragments, imports, {"declarations": declarations, "annotations": annotations}


def _cache_directory(store):
    """The cache directory inside the project, created only when an entry is written."""
    path = store.directory.joinpath(*CACHE_DIRECTORY)
    _relative(store, path)
    return path


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _publish(path, data):
    """Replace one cache file atomically, so a reader never sees a partial entry."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".forge-cache-", dir=str(path.parent))
    except OSError as error:
        raise ForgeError(f"Cannot write the caller-map cache at {path}: {error}; "
                         "pass --no-cache to scan without caching") from error
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class _CallerCache:
    """Per-file parse results keyed by source SHA-256 under ``.forge/cache/callers``.

    ``index.json`` maps a store-relative source path to the digest, size, nanosecond mtime and
    method name an entry was written for, so a lookup needs no source read; every other case is
    a miss that re-parses and republishes. Entry files over ``CACHE_CAP_BYTES`` in total are
    evicted oldest first, and dead index keys are pruned with them.
    """

    def __init__(self, store, enabled, cap=None):
        self.enabled = enabled
        self.cap = CACHE_CAP_BYTES if cap is None else cap
        self.directory = _cache_directory(store)
        self.hits = self.misses = self.writes = self.invalid = 0
        self.evicted = self.evicted_bytes = self.reused_bytes = self.bytes = 0
        self._index = None
        self._dirty = False

    def _load_index(self):
        if self._index is not None:
            return self._index
        self._index = {}
        try:
            document = json.loads((self.directory / CACHE_INDEX_NAME).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return self._index
        if not isinstance(document, dict) or document.get("schema") != CACHE_INDEX_SCHEMA:
            return self._index
        entries = document.get("entries")
        if not isinstance(entries, dict):
            return self._index
        for key, value in entries.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                continue
            digest, method = value.get("sha256"), value.get("method")
            size, mtime = value.get("size"), value.get("mtime_ns")
            if not isinstance(digest, str) or not _DIGEST.fullmatch(digest) or not isinstance(method, str):
                continue
            if type(size) is not int or type(mtime) is not int or size < 0 or mtime < 0:
                continue
            self._index[key] = {"sha256": digest, "size": size, "mtime_ns": mtime, "method": method}
        return self._index

    def _read_entry(self, digest, size, method):
        path = self.directory / (digest + ".json")
        try:
            if path.stat().st_size > max(CACHE_ENTRY_FLOOR, size * CACHE_ENTRY_RATIO):
                return None
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(document, dict) or document.get("schema") != CACHE_SCHEMA:
            return None
        if document.get("sha256") != digest or document.get("size") != size:
            return None
        if any(name not in document for name in _CACHE_PAYLOAD_FIELDS):
            return None
        payload = {name: document[name] for name in _CACHE_PAYLOAD_FIELDS}
        digests = document.get("digests")
        if not isinstance(digests, dict) or digests.get("source_sha256") != digest:
            return None
        if digests.get("payload_sha256") != _digest(payload):
            return None
        if payload["method"] != method:
            return None
        fragments, imports, skipped = payload["candidates"], payload["imports"], payload["skipped"]
        if not isinstance(fragments, list) or not isinstance(imports, dict) or not isinstance(skipped, dict):
            return None
        if set(imports) != set(_CACHE_IMPORT_KEYS) or set(skipped) != set(_CACHE_SKIP_KEYS):
            return None
        for name in _CACHE_IMPORT_KEYS:
            values = imports[name]
            if not isinstance(values, list):
                return None
            if any(not isinstance(value, str) or len(value) > MAX_CLASS_LENGTH for value in values):
                return None
        for name in _CACHE_SKIP_KEYS:
            if type(skipped[name]) is not int or skipped[name] < 0:
                return None
        for fragment in fragments:
            if not isinstance(fragment, dict) or set(fragment) != _CACHE_FRAGMENT_KEYS:
                return None
            if type(fragment["line"]) is not int or fragment["line"] < 1:
                return None
            if fragment["receiver_kind"] not in RECEIVER_KINDS:
                return None
            if fragment["receiver"] is not None and not isinstance(fragment["receiver"], str):
                return None
            if type(fragment["declaration_ambiguous"]) is not bool:
                return None
        return digest, fragments, imports, skipped

    def lookup(self, key, size, mtime_ns, method):
        """``(sha256, fragments, imports, skipped)`` for one source, or ``None`` on a miss."""
        if not self.enabled:
            return None
        record = self._load_index().get(key)
        if record is None or record["size"] != size or record["mtime_ns"] != mtime_ns or \
                record["method"] != method:
            self.misses += 1
            return None
        loaded = self._read_entry(record["sha256"], size, method)
        if loaded is None:
            self.invalid += 1
            self.misses += 1
            return None
        self.hits += 1
        self.reused_bytes += size
        return loaded

    def record(self, key, digest, size, mtime_ns, method, fragments, imports, skipped):
        """Publish one parse result and point the index at it."""
        if not self.enabled:
            return
        payload = {"candidates": fragments, "imports": imports, "skipped": skipped, "method": method}
        document = {"schema": CACHE_SCHEMA, "sha256": digest, "size": size,
                    "digests": {"source_sha256": digest, "payload_sha256": _digest(payload)}}
        document.update(payload)
        path = self.directory / (digest + ".json")
        data = _canonical(document)
        try:
            # Identical content at another path, or a rebuilt entry, publishes nothing.
            unchanged = path.read_bytes() == data
        except OSError:
            unchanged = False
        if not unchanged:
            _publish(path, data)
            self.writes += 1
        self._load_index()[key] = {"sha256": digest, "size": size, "mtime_ns": mtime_ns, "method": method}
        self._dirty = True

    def _write_index(self, index):
        data = _canonical({"schema": CACHE_INDEX_SCHEMA, "entries": index})
        path = self.directory / CACHE_INDEX_NAME
        try:
            if path.read_bytes() == data:
                return
        except OSError:
            pass
        _publish(path, data)

    def finish(self):
        """Evict the oldest entries over the cap, prune dead index keys, publish the index."""
        if not self.enabled or not self.directory.is_dir():
            return
        entries = []
        for child in self.directory.iterdir():
            name = child.name
            if name.startswith(".forge-cache-"):
                # A partial entry from an interrupted run is never readable; drop it here.
                try:
                    child.unlink()
                except OSError:
                    pass
                continue
            if name == CACHE_INDEX_NAME or not name.endswith(".json"):
                continue
            if not _DIGEST.fullmatch(name[:-len(".json")]):
                continue
            try:
                info = child.stat()
            except OSError:
                continue
            entries.append((info.st_mtime_ns, name, info.st_size))
        entries.sort()
        present = {name for _, name, _ in entries}
        index = self._load_index()
        for key in [key for key, value in index.items() if value["sha256"] + ".json" not in present]:
            del index[key]
            self._dirty = True
        total = len(_canonical({"schema": CACHE_INDEX_SCHEMA, "entries": index})) + \
            sum(size for _, _, size in entries)
        while entries and total > self.cap:
            _, name, size = entries.pop(0)
            try:
                (self.directory / name).unlink()
            except OSError:
                continue
            for key in [key for key, value in index.items() if value["sha256"] + ".json" == name]:
                del index[key]
            total -= size
            self.evicted += 1
            self.evicted_bytes += size
            self._dirty = True
        if self._dirty:
            self._write_index(index)
        self.bytes = len(_canonical({"schema": CACHE_INDEX_SCHEMA, "entries": index})) + \
            sum(size for _, _, size in entries)


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
    path_filters = []
    for value in getattr(args, "path_filter", []) or []:
        normalized = value.strip().replace("\\", "/")
        if normalized.endswith(JAVA_SUFFIX):
            normalized = normalized[:-len(JAVA_SUFFIX)]
        normalized = normalized.strip("/")
        if not normalized or len(normalized) > 512:
            raise ForgeError("--path-filter must be a non-empty source path/class substring up to 512 characters")
        path_filters.append(normalized.casefold())
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
            if path_filters:
                posix = class_name.replace(".", "/")
                if not any(term in posix.casefold() or term in class_name.casefold() for term in path_filters):
                    continue
            sources.append((path, suffix, class_name))
            tree_classes.add(class_name)
            by_package.setdefault(_package(class_name), []).append(class_name)
            by_simple.setdefault(_simple(class_name), []).append(class_name)
            tree_simple.add(_simple(class_name))
            skipped_kt += suffix == KOTLIN_SUFFIX
        if truncated:
            break
    cache = _CallerCache(store, bool(getattr(args, "cache", True)))
    candidates = []
    candidate_count = candidates_omitted = candidates_filtered = 0
    declarations_skipped = annotation_uses_skipped = 0
    files_scanned = bytes_scanned = bytes_omitted = 0
    for path, suffix, class_name in sources:
        if suffix != JAVA_SUFFIX:
            continue
        # A cached file is one whose content this run accounts for, so the caps count it and a
        # bounded rerun walks exactly the same files as the first run did.
        if files_scanned + cache.hits >= args.max_files:
            files_omitted += 1
            truncated = True
            break
        try:
            attributes = path.stat()
        except OSError:
            files_omitted += 1
            continue
        size = attributes.st_size
        if size > args.max_file_bytes:
            files_omitted += 1
            bytes_omitted += size
            truncated = True
            continue
        if bytes_scanned + cache.reused_bytes + size > args.max_total_bytes:
            files_omitted += 1
            bytes_omitted += size
            truncated = True
            break
        relative = _relative(store, path)
        parsed = cache.lookup(relative, size, attributes.st_mtime_ns, method_name)
        if parsed is None:
            try:
                content = path.read_bytes()
            except OSError:
                files_omitted += 1
                continue
            files_scanned += 1
            bytes_scanned += len(content)
            digest = hashlib.sha256(content).hexdigest()
            fragments, imports, skipped = _parse_source(content.decode("utf-8", "replace"), method_name)
            cache.record(relative, digest, size, attributes.st_mtime_ns, method_name,
                         fragments, imports, skipped)
        else:
            digest, fragments, imports, skipped = parsed
        declarations_skipped += skipped["declarations"]
        annotation_uses_skipped += skipped["annotations"]
        owners = None
        for fragment in fragments:
            kind = _promote(fragment["receiver_kind"], fragment["receiver"], tree_simple)
            if kind == BARE:
                if owners is None:
                    owners = _possible_owners(tree_classes, by_package, by_simple, _package(class_name),
                                              set(imports["exact"]), set(imports["simple"]),
                                              set(imports["wildcard"]))
                possible, owners_omitted = owners
            else:
                possible, owners_omitted = [], False
            if owner and not _attributed(owner, kind, fragment["receiver"], class_name, possible, method_name):
                candidates_filtered += 1
                continue
            if candidate_count >= args.max_items:
                candidates_omitted += 1
                truncated = True
                continue
            candidates.append({
                "file": relative, "class_name": class_name, "line": fragment["line"],
                "receiver_kind": kind, "receiver": fragment["receiver"], "possible_owners": possible,
                "possible_owners_omitted": owners_omitted,
                "declaration_ambiguous": fragment["declaration_ambiguous"], "source_sha256": digest})
            candidate_count += 1
    cache.finish()
    return store.add("analysis", {
        "schema": SCHEMA, "tool": TOOL, "action": ACTION, "success": True,
        "method_name": method_name, "owner_class": owner, "path_filter": path_filters,
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
        "cache_enabled": cache.enabled, "cache_dir": _relative(store, cache.directory),
        "cache_hits": cache.hits, "cache_misses": cache.misses, "cache_writes": cache.writes,
        "cache_invalid": cache.invalid, "cache_evicted": cache.evicted,
        "cache_evicted_bytes": cache.evicted_bytes, "cache_bytes": cache.bytes,
        "cache_bytes_reused": cache.reused_bytes, "cache_cap_bytes": cache.cap,
        "candidates": candidates, "truncated": truncated, "scope": SCOPE})


def register(subparsers):
    parser = subparsers.add_parser("android-caller-map",
                                   help="Find cross-file caller-name candidates for one Java method in cited JADX output")
    parser.add_argument("--jadx-evidence", required=True, help="Successful or partial JADX evidence")
    parser.add_argument("--method", required=True, help="Java method name to search for")
    parser.add_argument("--class", dest="owner_class",
                        help="Optional dotted owner class: keep only candidates that can name it")
    parser.add_argument("--path-filter", action="append", default=[],
                        help="Optional source path/class substring to scope the walk; repeatable, for example "
                             "com/example or e5/c.java")
    parser.add_argument("--max-items", type=_positive, default=500, help="Maximum retained caller candidates")
    parser.add_argument("--max-files", type=_positive, default=50000,
                        help="Maximum Java sources whose content is parsed or reused from the cache")
    parser.add_argument("--max-file-bytes", type=_positive, default=16 * 1024 * 1024)
    parser.add_argument("--max-total-bytes", type=_positive, default=128 * 1024 * 1024)
    parser.add_argument("--cache", dest="cache", action="store_true", default=True,
                        help="Reuse per-file parse results keyed by source SHA-256 under .forge/cache/callers; "
                             "a hit re-reads no source and the directory is kept under 512 MiB, oldest first")
    parser.add_argument("--no-cache", dest="cache", action="store_false",
                        help="Re-parse every source and write no cache entry; use after editing sources in place")
    parser.set_defaults(handler=android_caller_map)

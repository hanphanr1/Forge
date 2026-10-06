"""Artifact acquisition and bounded, source-located static analysis."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
import zlib

from forge_core import ForgeError, redact, scrub_text, utc_now
from forge_toolchain import find_tool, java_environment

CHUNK = 64 * 1024
ARCHIVES = {".zip", ".apk", ".apks", ".xapk", ".whl"}
TEXT_SUFFIXES = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".jsonl",
    ".xml", ".html", ".htm", ".css", ".txt", ".csv", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".properties", ".java", ".kt", ".smali",
    ".py", ".sh", ".sql", ".md", ".svg", ".map", ".graphql", ".proto",
}
ENDPOINT = re.compile(r"https?://[^\s\"'<>\\]+|/(?:api|auth|oauth|login|signin|session|v[0-9]+)(?:/[A-Za-z0-9._~!$&()*+,;=:@%/?#-]*)?", re.I)


def _positive(value):
    try:
        result = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if result < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return result


def _seconds(value):
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive number") from exc
    if not 0 < result <= 86400:
        raise argparse.ArgumentTypeError("must be greater than zero and at most 86400")
    return result


def _relative(store, path):
    try:
        return path.resolve().relative_to(store.root.resolve()).as_posix()
    except ValueError as exc:
        raise ForgeError("Output must remain inside the project directory") from exc


def _area(store, name):
    path = store.directory / name
    _relative(store, path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _input(store, value, *, local=False):
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = store.root / path
    path = path.resolve()
    if local:
        _relative(store, path)
    if not path.exists():
        raise ForgeError(f"Artifact path does not exist: {value}")
    if not path.is_file() and not path.is_dir():
        raise ForgeError("Only regular files and explicitly supplied directories are supported")
    if path.is_dir() and (path == store.root.resolve() or path == store.directory.resolve()):
        raise ForgeError("Supply a specific artifact or analysis directory, not the project/evidence root")
    return path


def _expected(value):
    if value is None:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ForgeError("--sha256 must contain exactly 64 hexadecimal characters")
    return value.lower()


def _count_java(root, cap=500000):
    if not root.is_dir():
        return 0
    total = 0
    for _ in root.rglob("*.java"):
        total += 1
        if total >= cap:
            break
    return total


def _publish(temp, destination, expected_sha256=None, expected_size=None):
    # A same-filesystem hard link publishes complete bytes without overwriting an existing blob.
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(temp, destination)
    except FileExistsError:
        if destination.is_symlink() or not destination.is_file():
            raise ForgeError("Existing artifact destination is not a regular file; it was not overwritten")
        if expected_sha256 is not None:
            if destination.stat().st_size != expected_size:
                raise ForgeError("Existing content-addressed artifact is corrupt; it was not overwritten")
            digest = hashlib.sha256()
            with destination.open("rb") as existing:
                while block := existing.read(CHUNK):
                    digest.update(block)
            if digest.hexdigest() != expected_sha256:
                raise ForgeError("Existing content-addressed artifact is corrupt; it was not overwritten")
        else:
            raise ForgeError("Output already exists; it was not overwritten")
    except OSError as exc:
        raise ForgeError(f"Atomic artifact publication requires hard-link support: {exc}") from exc


def _save_stream(store, source, max_bytes, expected=None, deadline=None, declared_size=None):
    temp = None
    digest = hashlib.sha256()
    size = 0
    try:
        with tempfile.NamedTemporaryFile(dir=_area(store, "tmp"), delete=False) as output:
            temp = Path(output.name)
            while True:
                if deadline is not None and time.monotonic() >= deadline:
                    raise ForgeError("Download exceeded --timeout; increase it explicitly")
                block = source.read(min(CHUNK, max_bytes - size + 1))
                if not block:
                    break
                size += len(block)
                if size > max_bytes:
                    raise ForgeError(f"Artifact exceeds --max-bytes ({max_bytes}); no artifact was published")
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        if declared_size is not None and size != declared_size:
            raise ForgeError(f"Incomplete download: received {size} bytes, expected {declared_size}; no artifact was published")
        sha256 = digest.hexdigest()
        if expected and sha256 != expected:
            raise ForgeError(f"SHA256 mismatch: expected {expected}, received {sha256}; no artifact was published")
        destination = store.blob_path(sha256)
        relative = _relative(store, destination)
        _publish(temp, destination, sha256, size)
        return {"sha256": sha256, "size": size, "path": relative}
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def artifact_add(args, store):
    source = _input(store, args.path)
    if not source.is_file():
        raise ForgeError("artifact-add imports one file; use artifact-index for an explicit directory")
    expected = _expected(args.sha256)
    try:
        with source.open("rb") as handle:
            blob = _save_stream(store, handle, args.max_bytes, expected)
    except OSError as exc:
        raise ForgeError(f"Cannot import artifact: {exc}") from exc
    return store.add("artifact", {
        **blob, "origin": "local_import", "source_path": str(source),
        "filename": source.name, "source_url": args.source_url, "final_url": None,
        "version": args.version, "platform": args.platform, "expected_sha256": expected,
    })


def _http_url(url):
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise ForgeError(f"Invalid HTTP(S) URL: {scrub_text(str(exc))}") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ForgeError("Only explicit HTTP(S) URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ForgeError("URL user-info credentials are not accepted")
    try:
        parsed.port
    except ValueError as exc:
        raise ForgeError(f"Invalid URL port: {exc}") from exc
    return url


class _Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, limit):
        super().__init__()
        self.limit = limit
        self.hops = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _http_url(newurl)
        if len(self.hops) >= self.limit:
            raise ForgeError(f"Redirect limit exceeded ({self.limit})")
        self.hops.append({"from_url": req.full_url, "to_url": newurl, "status": code})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def artifact_fetch(args, store):
    url = _http_url(args.url)
    expected = _expected(args.sha256)
    redirects = _Redirects(args.max_redirects)
    opener = urllib.request.build_opener(redirects)
    request = urllib.request.Request(url, headers={"User-Agent": "FORGE-artifacts/1", "Accept-Encoding": "identity"})
    started = time.monotonic()
    try:
        with opener.open(request, timeout=args.timeout) as response:
            length = response.headers.get("Content-Length")
            declared_size = int(length) if length and length.isdecimal() else None
            if declared_size is not None and declared_size > args.max_bytes:
                raise ForgeError(f"Content-Length exceeds --max-bytes ({args.max_bytes})")
            blob = _save_stream(store, response, args.max_bytes, expected, started + args.timeout, declared_size)
            final_url = response.geturl()
            metadata = {
                "final_url": final_url, "status": response.status,
                "content_type": response.headers.get("Content-Type"),
                "content_encoding": response.headers.get("Content-Encoding"),
                "etag": response.headers.get("ETag"),
                "last_modified": response.headers.get("Last-Modified"),
            }
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        raise ForgeError(f"Artifact download failed: {scrub_text(str(exc))}") from exc
    return store.add("artifact", {
        **blob, **metadata, "origin": "http_download", "source_url": url,
        "filename": Path(urllib.parse.unquote(urllib.parse.urlsplit(final_url).path)).name,
        "redirects": redirects.hops, "version": args.version, "platform": args.platform,
        "expected_sha256": expected, "elapsed_ms": round((time.monotonic() - started) * 1000),
        "transport": "urllib", "retrieved_at": utc_now(),
    })


class _Budget:
    def __init__(self, args):
        self.args = args
        self.entries = 0
        self.bytes = 0
        self.records = 0
        self.skipped = []
        self.truncated = False

    def skip(self, source, reason):
        if len(self.skipped) < 100:
            self.skipped.append({"source": source, "reason": reason})
        self.truncated = True

    def consume(self, size, source):
        if size > self.args.max_file_bytes:
            self.skip(source, "exceeds --max-file-bytes")
            return False
        if self.bytes + size > self.args.max_total_bytes:
            self.skip(source, "exceeds --max-total-bytes")
            return False
        self.bytes += size
        return True


def _files(path, budget):
    if path.is_file():
        yield path
        return
    directories = 0
    for directory, dirs, files in os.walk(path, followlinks=False):
        directories += 1
        if directories > budget.args.max_entries:
            budget.skip(str(path), "directory traversal reached --max-entries")
            return
        dirs[:] = sorted(name for name in dirs if name.lower() not in
                         {".forge", ".git", ".venv", "venv", "node_modules", "results", "__pycache__"}
                         and not (Path(directory) / name).is_symlink())
        for name in sorted(files):
            if name.lower() in {"accounts", "accounts.txt", "proxies.txt", "keys.txt"}:
                budget.skip(str(Path(directory) / name), "credential data excluded from directory indexing")
                continue
            source = Path(directory) / name
            if source.is_symlink():
                budget.skip(str(source), "symlink not followed")
                continue
            if not source.is_file():
                continue
            yield source
            if budget.entries >= budget.args.max_entries:
                budget.skip(str(path), "reached --max-entries")
                return


def _safe_member(name):
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return not (path.is_absolute() or ".." in path.parts or "\x00" in name or re.match(r"^[A-Za-z]:", normalized))


def _zip_entries(path, maximum):
    # Read the bounded EOCD before ZipFile allocates its complete central-directory listing.
    with path.open("rb") as source:
        source.seek(0, os.SEEK_END)
        size = source.tell()
        source.seek(max(0, size - 65557))
        ending = source.read(65557)
    marker = ending.rfind(b"PK\x05\x06")
    fields = None
    while marker >= 0:
        if marker + 22 <= len(ending):
            candidate = struct.unpack_from("<4s4H2LH", ending, marker)
            if marker + 22 + candidate[7] == len(ending):
                fields = candidate
                break
        marker = ending.rfind(b"PK\x05\x06", 0, marker)
    if fields is None:
        raise ForgeError(f"Corrupt ZIP artifact: {path.name}; invalid or missing ZIP footer")
    if fields[1] or fields[2] or fields[3] != fields[4]:
        raise ForgeError("Multi-disk ZIP archives are not supported; supply a single complete archive")
    if fields[4] == 65535 or fields[5] == 0xFFFFFFFF or fields[6] == 0xFFFFFFFF:
        raise ForgeError("ZIP64 archive indexing is not supported by the bounded reader")
    if fields[4] > maximum:
        raise ForgeError(f"ZIP contains {fields[4]} entries, exceeding --max-entries ({maximum})")


def _decode(data, name):
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace"), "utf-16"
    if b"\x00" in data[:8192]:
        return None, None
    sample = data[:8192]
    if sample and sum(byte < 32 and byte not in (9, 10, 13) for byte in sample) / len(sample) > 0.02:
        return None, None
    try:
        return data.decode("utf-8-sig"), "utf-8"
    except UnicodeDecodeError:
        if Path(name).suffix.lower() in TEXT_SUFFIXES:
            return data.decode("utf-8", errors="replace"), "utf-8-lossy"
        return None, None


def _record(location, text, encoding, **position):
    return redact({**location, **position, "encoding": encoding, "text": scrub_text(text)})


def _content_records(data, name, location, budget):
    if data.startswith((b"\x7fELF", b"MZ", b"dex\n", b"cdex")):
        minimum = budget.args.min_string_length
        patterns = [
            (re.compile(rb"[\x20-\x7e]{%d,}" % minimum), "ascii"),
            (re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum), "utf-16-le"),
            (re.compile(rb"(?:\x00[\x20-\x7e]){%d,}" % minimum), "utf-16-be"),
        ]
        for pattern, encoding in patterns:
            for match in pattern.finditer(data):
                raw = match.group()
                step = 4096 if encoding == "ascii" else 8192
                for offset in range(0, len(raw), step):
                    yield _record(location, raw[offset:offset + step].decode(encoding), encoding,
                                  byte_offset=match.start() + offset, kind="binary_string")
        return
    text, encoding = _decode(data, name)
    if text is None:
        budget.skip(location, "not recognized as text, DEX, ELF, or PE")
        return
    for number, line in enumerate(text.splitlines(), 1):
        for column in range(0, max(1, len(line)), 4096):
            yield _record(location, line[column:column + 4096], encoding,
                          line=number, column=column + 1, kind="text")


def _archive_records(path, source_name, budget):
    _zip_entries(path, budget.args.max_entries - budget.entries + 1)
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                budget.entries += 1
                location = {"source": source_name, "member": info.filename,
                            "member_header_offset": info.header_offset, "member_crc32": f"{info.CRC:08x}"}
                if budget.entries > budget.args.max_entries:
                    budget.skip(location, "reached --max-entries")
                    return
                if not _safe_member(info.filename):
                    budget.skip(location, "unsafe member path; never extracted")
                    continue
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    budget.skip(location, "archive symlink not read")
                    continue
                if info.flag_bits & 1:
                    budget.skip(location, "encrypted member; supply a decrypted artifact")
                    continue
                if info.file_size > max(1, info.compress_size) * 200:
                    budget.skip(location, "compression ratio exceeds 200:1")
                    continue
                if not budget.consume(info.file_size, location):
                    continue
                with archive.open(info) as member:
                    data = member.read(budget.args.max_file_bytes + 1)
                if len(data) != info.file_size:
                    raise ForgeError(f"Corrupt ZIP member: {info.filename}; size mismatch")
                yield from _content_records(data, info.filename, location, budget)
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, zlib.error) as exc:
        raise ForgeError(f"Cannot index ZIP artifact {path.name}: {exc}; re-import a complete supported archive") from exc


def _indexed_records(path, source_name, budget):
    with path.open("rb") as source:
        for number, raw in enumerate(source, 1):
            if len(raw) > 128 * 1024:
                raise ForgeError(f"Index record {number} exceeds the safe record size")
            try:
                item = json.loads(raw)
            except (ValueError, UnicodeError) as exc:
                raise ForgeError(f"Invalid index JSON on line {number}") from exc
            if not isinstance(item, dict) or not isinstance(item.get("text"), str):
                raise ForgeError(f"Invalid index record on line {number}: expected a text string")
            item["text"] = scrub_text(item["text"][:4096])
            item = redact(item)
            item["index_source"] = source_name
            yield item


def _gzip_records(path, source_name, budget):
    location = {"source": source_name, "compression": "gzip", "offset_space": "decompressed"}
    try:
        with gzip.open(path, "rb") as source:
            data = source.read(budget.args.max_file_bytes + 1)
    except (OSError, EOFError, zlib.error) as error:
        raise ForgeError(f"Cannot decode gzip artifact {path.name}: {error}") from error
    if budget.consume(len(data), location):
        yield from _content_records(data, path.stem, location, budget)


def _scan(paths, store, budget):
    for path in paths:
        for source in _files(path, budget):
            budget.entries += 1
            if budget.entries > budget.args.max_entries:
                budget.skip(str(source), "reached --max-entries")
                return
            source_name = _relative(store, source)
            size = source.stat().st_size
            with source.open("rb") as handle:
                magic = handle.read(4)
            if source.suffix.lower() in ARCHIVES or magic.startswith(b"PK"):
                records = _archive_records(source, source_name, budget)
            elif magic.startswith(b"\x1f\x8b"):
                records = _gzip_records(source, source_name, budget)
            elif source.name == "index.jsonl":
                if not budget.consume(size, source_name):
                    continue
                records = _indexed_records(source, source_name, budget)
            else:
                if not budget.consume(size, source_name):
                    continue
                with source.open("rb") as handle:
                    data = handle.read(budget.args.max_file_bytes + 1)
                if len(data) > budget.args.max_file_bytes:
                    budget.skip(source_name, "file grew beyond --max-file-bytes")
                    continue
                records = _content_records(data, source.name, {"source": source_name}, budget)
            for record in records:
                if budget.records >= budget.args.max_records:
                    budget.skip(source_name, "reached --max-records")
                    return
                budget.records += 1
                yield record


def _candidates(record):
    for match in ENDPOINT.finditer(record["text"]):
        yield {"value": match.group()[:2048], "classification": "observed_string",
               "proven_live": False, "proven_auth_path": False,
               "location": {key: value for key, value in record.items() if key != "text"}}


def artifact_index(args, store):
    path = _input(store, args.path, local=True)
    budget = _Budget(args)
    output_dir = _area(store, "indexes") / uuid.uuid4().hex
    output_dir.mkdir()
    temp = output_dir / "index.tmp"
    output = output_dir / "index.jsonl"
    candidates = []
    written = 0
    saved_records = 0
    index_hash = hashlib.sha256()
    index_size = 0
    try:
        with temp.open("x", encoding="utf-8", newline="\n") as handle:
            for record in _scan([path], store, budget):
                serialized = json.dumps(record, ensure_ascii=True) + "\n"
                encoded = serialized.encode("utf-8")
                written += len(encoded)
                if written > args.max_index_bytes:
                    budget.skip(str(path), "reached --max-index-bytes")
                    break
                handle.write(serialized)
                index_hash.update(encoded)
                index_size += len(encoded)
                saved_records += 1
                for candidate in _candidates(record):
                    if len(candidates) < 100:
                        candidates.append(candidate)
            handle.flush()
            os.fsync(handle.fileno())
        _publish(temp, output)
    except (OSError, UnicodeError) as exc:
        raise ForgeError(f"Static indexing failed: {exc}") from exc
    finally:
        temp.unlink(missing_ok=True)
        if not output.exists():
            output_dir.rmdir()
    return store.add("analysis", {
        "tool": "static_index", "input": _relative(store, path), "path": _relative(store, output),
        "index_sha256": index_hash.hexdigest(), "index_size": index_size,
        "records": saved_records, "entries": budget.entries, "bytes_read_budget": budget.bytes,
        "truncated": budget.truncated, "skipped": budget.skipped, "endpoint_candidates": candidates,
        "endpoint_note": "Candidates are observed strings, not verified live endpoints or authentication paths.",
    })


def search(args, store):
    if not args.query:
        raise ForgeError("Search query must not be empty")
    if args.regex and len(args.query) > 512:
        raise ForgeError("Regex patterns are limited to 512 characters")
    paths = [_input(store, value, local=True) for value in args.paths]
    try:
        pattern = re.compile(args.query, re.I if args.ignore_case else 0) if args.regex else None
    except re.error as exc:
        raise ForgeError(f"Invalid search regex: {exc}") from exc
    needle = args.query.casefold() if args.ignore_case else args.query
    budget = _Budget(args)
    matches = []
    try:
        for record in _scan(paths, store, budget):
            text = record["text"]
            found = pattern.search(text) if pattern else needle in (text.casefold() if args.ignore_case else text)
            if not found:
                continue
            matches.append({**record, "endpoint_candidates": list(_candidates(record))[:20]})
            if len(matches) >= args.max_matches:
                budget.truncated = True
                break
    except OSError as exc:
        raise ForgeError(f"Cannot search supplied artifact paths: {exc}") from exc
    return store.add("search", {
        "query": args.query, "regex": args.regex, "ignore_case": args.ignore_case,
        "paths": [_relative(store, path) for path in paths], "matches": matches,
        "truncated": budget.truncated, "skipped": budget.skipped, "records_scanned": budget.records,
        "endpoint_note": "Candidates are observed strings, not verified live endpoints or authentication paths.",
    })


def jadx(args, store):
    source = _input(store, args.path, local=True)
    if not source.is_file():
        raise ForgeError("jadx requires one APK, DEX, JAR, or other JADX-supported artifact file")
    tool = find_tool("jadx")
    launcher = tool["path"]
    if not tool["available"]:
        evidence = store.add("analysis", {"tool": "jadx", "input": _relative(store, source),
                                         "status": "unavailable", "error": tool["setup"], "source": tool["source"]})
        raise ForgeError(f"JADX is unavailable: {tool['setup']}. Evidence: {evidence['id']}")
    environment = java_environment()
    output = _area(store, "analysis") / ("jadx-" + uuid.uuid4().hex)
    output.mkdir()
    command = [launcher, "-d", str(output / "output"), "-j", str(args.jobs)]
    if args.deobf:
        command.append("--deobf")
    if args.single_class:
        command += ["--single-class", args.single_class]
    command.append(str(source))
    log = bytearray()
    log_size = 0
    read_errors = []
    started = time.monotonic()
    status = "failed"
    returncode = None
    error = None
    process = None

    def drain(pipe):
        nonlocal log_size
        try:
            while True:
                block = pipe.read(CHUNK)
                if not block:
                    break
                log_size += len(block)
                remaining = args.max_log_bytes - len(log)
                if remaining > 0:
                    log.extend(block[:remaining])
        except OSError as exc:
            read_errors.append(str(exc))
        finally:
            pipe.close()

    try:
        options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        process = subprocess.Popen(command, cwd=store.root, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **options)
        reader = threading.Thread(target=drain, args=(process.stdout,), daemon=True)
        reader.start()
        try:
            returncode = process.wait(timeout=args.timeout)
            status = "success" if returncode == 0 else "failed"
        except subprocess.TimeoutExpired:
            status = "timeout"
            error = f"JADX exceeded --timeout ({args.timeout} seconds)"
            if os.name == "nt":
                try:
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                if process.poll() is None:
                    process.kill()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            returncode = process.wait()
        reader.join(timeout=5)
        if reader.is_alive():
            error = "JADX descendant retained its log pipe; captured log is incomplete"
            status = "failed" if status == "success" else status
        elif read_errors:
            error = "JADX log capture failed: " + "; ".join(read_errors)
            status = "failed" if status == "success" else status
    except OSError as exc:
        error = str(exc)
    log_path = output / "jadx.log"
    log_temp = output / "jadx.log.tmp"
    log_text = scrub_text(bytes(log).decode("utf-8", errors="replace"))
    try:
        with log_temp.open("x", encoding="utf-8") as handle:
            handle.write(log_text)
            handle.flush()
            os.fsync(handle.fileno())
        _publish(log_temp, log_path)
    finally:
        log_temp.unlink(missing_ok=True)
    produced = _count_java(output / "output")
    reported = re.search(r"finished with errors, count:\s*(\d+)", log_text)
    error_count = int(reported.group(1)) if reported else None
    if status == "failed" and produced:
        status = "partial"
    java_files = produced
    warning = None
    if status == "partial":
        warning = (f"JADX reported {error_count if error_count is not None else 'some'} decompile errors; "
                   f"{produced} source files are still usable at {_relative(store, output / 'output')}")
    evidence = store.add("analysis", {
        "tool": "jadx", "input": _relative(store, source), "status": status,
        "executable": launcher, "tool_source": tool["source"], "output_path": _relative(store, output / "output"),
        "log_path": _relative(store, log_path), "returncode": returncode,
        "error": error if status != "partial" else None, "warning": warning,
        "log_truncated": log_size > args.max_log_bytes,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "java_files": java_files, "error_count": error_count, "partial": status == "partial",
    })
    if status != "success" and status != "partial":
        raise ForgeError(f"JADX {status}: {scrub_text(error or 'see the JADX log for dependency or malformed-artifact errors')}. Log: {_relative(store, log_path)}. Evidence: {evidence['id']}")
    return evidence


def _metadata(parser):
    parser.add_argument("--version", help="Caller-supplied client version metadata")
    parser.add_argument("--platform", help="Caller-supplied target platform metadata")
    parser.add_argument("--sha256", help="Require this SHA256 before publishing the artifact")
    parser.add_argument("--max-bytes", type=_positive, default=256 * 1024 * 1024)


def _limits(parser):
    parser.add_argument("--max-file-bytes", type=_positive, default=16 * 1024 * 1024)
    parser.add_argument("--max-total-bytes", type=_positive, default=128 * 1024 * 1024)
    parser.add_argument("--max-entries", type=_positive, default=10000)
    parser.add_argument("--max-records", type=_positive, default=100000)
    parser.add_argument("--min-string-length", type=_positive, default=4)


def register(subparsers):
    parser = subparsers.add_parser("artifact-add", help="Import one file without changing the original")
    parser.add_argument("path")
    parser.add_argument("--source-url", help="Optional provenance URL (not fetched)")
    _metadata(parser)
    parser.set_defaults(handler=artifact_add)

    parser = subparsers.add_parser("artifact-fetch", help="Download an explicit HTTP(S) artifact URL")
    parser.add_argument("url")
    parser.add_argument("--timeout", type=_seconds, default=120.0)
    parser.add_argument("--max-redirects", type=_positive, default=10)
    _metadata(parser)
    parser.set_defaults(handler=artifact_fetch)

    parser = subparsers.add_parser("artifact-index", help="Index explicit project-local files or artifact directories")
    parser.add_argument("path")
    parser.add_argument("--max-index-bytes", type=_positive, default=64 * 1024 * 1024)
    _limits(parser)
    parser.set_defaults(handler=artifact_index)

    parser = subparsers.add_parser("search", help="Search explicit project-local artifact, index, or JADX output paths")
    parser.add_argument("query")
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--regex", action="store_true")
    parser.add_argument("--ignore-case", action="store_true")
    parser.add_argument("--max-matches", type=_positive, default=100)
    _limits(parser)
    parser.set_defaults(handler=search)

    parser = subparsers.add_parser("jadx", help="Run installed JADX with project-local output and saved execution evidence")
    parser.add_argument("path")
    parser.add_argument("--timeout", type=_seconds, default=300.0)
    parser.add_argument("--jobs", type=_positive, default=2)
    parser.add_argument("--deobf", action="store_true", help="Ask JADX to deobfuscate names")
    parser.add_argument("--single-class", help="Restrict output to one class name")
    parser.add_argument("--max-log-bytes", type=_positive, default=1024 * 1024)
    parser.set_defaults(handler=jadx)

from __future__ import annotations

from collections import Counter
import heapq
import hashlib
import json
import math
import re
import time

from forge_core import ForgeError, scrub_text
from forge_execution import _capture
from forge_tasks import _file_fact
from forge_toolchain import executable

MAX_OUTPUT = 16 * 1024 * 1024
MAX_ITEMS = 100000
_ADDRESS = re.compile(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)\Z")
_LIMITATIONS = [
    "Static radare2 observations, not execution or authentication evidence.",
    "Disassembly depends on backend architecture and analysis heuristics; no decompiler guarantee.",
    "Function graph membership uses capped backend basic blocks; unresolved or overlapping memberships remain explicit. Indirect calls and tail calls may be absent.",
    "Only whitelisted backend fields are retained; unsupported fields are omitted.",
    "Before/after hashes detect endpoint changes, not transient changes during analysis.",
]


def _address(value):
    if value is None:
        return None
    if type(value) is int:
        number = value
    elif isinstance(value, str) and _ADDRESS.fullmatch(value):
        number = int(value, 16 if value.lower().startswith("0x") else 10)
    else:
        raise ForgeError("--address must be a decimal or 0x hexadecimal unsigned address")
    if not 0 <= number <= 0xffffffffffffffff:
        raise ForgeError("--address must fit an unsigned 64-bit address")
    return number


def _parameters(args):
    if args.action not in {"disasm", "xrefs", "callgraph"}:
        raise ForgeError("Unsupported native analysis action")
    address = _address(getattr(args, "address", None))
    timeout = args.timeout
    if type(timeout) not in {int, float} or not math.isfinite(timeout) or not 0 < timeout <= 3600:
        raise ForgeError("--timeout must be finite, greater than zero, and at most 3600 seconds")
    output = getattr(args, "max_output", 1024 * 1024)
    items = getattr(args, "max_items", 1000)
    if type(output) is not int or not 1 <= output <= MAX_OUTPUT:
        raise ForgeError("--max-output must be an integer from 1 to 16777216 bytes")
    if type(items) is not int or not 1 <= items <= MAX_ITEMS:
        raise ForgeError("--max-items must be an integer from 1 to 100000")
    return address, timeout, output, items


def _unsigned(value):
    return type(value) is int and 0 <= value <= 0xffffffffffffffff


def _duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("nonfinite JSON value")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite JSON number")
    return number


def _json(raw):
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_duplicates,
                           parse_constant=_reject_constant, parse_float=_finite_float)
    except (ValueError, UnicodeError, RecursionError):
        raise ForgeError("radare2 did not return strict UTF-8 JSON") from None
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ForgeError("radare2 JSON must be an array of objects")
    return value


def _json_documents(raw, count):
    decoder = json.JSONDecoder(object_pairs_hook=_duplicates, parse_constant=_reject_constant,
                               parse_float=_finite_float)
    documents, position = [], 0
    try:
        text = raw.decode("utf-8", "strict")
        for _ in range(count):
            while position < len(text) and text[position] in " \t\r\n":
                position += 1
            value, position = decoder.raw_decode(text, position)
            if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
                raise ValueError("expected object array")
            documents.append(value)
        if text[position:].strip():
            raise ValueError("unexpected trailing output")
    except (ValueError, UnicodeError, RecursionError):
        raise ForgeError("radare2 block batch must return exactly one strict JSON array per query") from None
    return documents


def _backend_address(row, field, alternate):
    present = [key for key in (field, alternate) if key in row]
    if not present or any(not _unsigned(row[key]) for key in present):
        raise ForgeError(f"radare2 lacks a valid {field}/{alternate} address")
    if len(present) == 2 and row[field] != row[alternate]:
        raise ForgeError(f"radare2 returned conflicting {field}/{alternate} addresses")
    return row[present[0]]


def _instructions(rows):
    result = []
    for row in rows:
        offset = _backend_address(row, "offset", "addr")
        if type(row.get("size")) is not int or row["size"] <= 0:
            raise ForgeError("radare2 instruction lacks a valid size")
        if not isinstance(row.get("opcode"), str):
            raise ForgeError("radare2 instruction lacks an observed opcode")
        item = {"offset": offset, "size": row["size"], "opcode": row["opcode"]}
        if "addr" in row:
            item["backend_address_field"] = "addr"
        for key in ("bytes", "type", "mnemonic"):
            if key in row:
                if not isinstance(row[key], str):
                    raise ForgeError("radare2 instruction text field has an invalid type")
                item[key] = row[key]
        for key in ("jump", "fail"):
            if key in row:
                if not _unsigned(row[key]):
                    raise ForgeError("radare2 instruction target has an invalid type")
                item[key] = row[key]
        result.append(item)
    return result


def _xrefs(rows, direction=None, calls_only=False, address=None):
    result = []
    for row in rows:
        target_from_addr = "addr" in row
        if target_from_addr:
            row = {**row, "to": _backend_address(row, "to", "addr")}
        endpoint = "to" if direction == "incoming" else "from"
        from_query = direction is not None and endpoint not in row
        if from_query:
            row = {**row, endpoint: address}
        if not _unsigned(row.get("from")) or not _unsigned(row.get("to")) or not isinstance(row.get("type"), str):
            raise ForgeError("radare2 xref lacks valid from, to, or type fields")
        if calls_only and row["type"].upper() != "CALL":
            continue
        item = {key: row[key] for key in ("from", "to", "type")}
        if target_from_addr:
            item["backend_target_field"] = "addr"
        if direction is not None:
            item["direction"] = direction
        if from_query:
            item["endpoint_from_query"] = endpoint
        result.append(item)
    return result


def _functions(rows):
    result = []
    for row in rows:
        offset = _backend_address(row, "offset", "addr")
        if type(row.get("size")) is not int or row["size"] < 0:
            raise ForgeError("radare2 function lacks valid size")
        item = {"offset": offset, "size": row["size"]}
        if "addr" in row:
            item["backend_address_field"] = "addr"
        if "name" in row:
            if not isinstance(row["name"], str):
                raise ForgeError("radare2 function name has an invalid type")
            item["name"] = row["name"]
        result.append(item)
    return result


def _blocks(rows, function):
    result = []
    for row in rows:
        if not _unsigned(row.get("addr")) or type(row.get("size")) is not int or row["size"] <= 0:
            raise ForgeError("radare2 basic block lacks valid addr or size")
        result.append({"function": function, "address": row["addr"], "size": row["size"]})
    return result


def _function_graph(calls, nodes, blocks):
    entries = {node["offset"] for node in nodes}

    ordered_blocks = sorted(blocks, key=lambda block: block["address"])
    active, counts, memberships, position = [], Counter(), {}, 0
    for address in sorted({call[key] for call in calls for key in ("from", "to")}):
        while position < len(ordered_blocks) and ordered_blocks[position]["address"] <= address:
            block = ordered_blocks[position]
            heapq.heappush(active, (block["address"] + block["size"], block["function"]))
            counts[block["function"]] += 1
            position += 1
        while active and active[0][0] <= address:
            _, function = heapq.heappop(active)
            counts[function] -= 1
            if not counts[function]:
                del counts[function]
        if len(counts) == 1:
            memberships[address] = next(iter(counts)), "observed_basic_block"
        else:
            memberships[address] = None, "ambiguous_blocks" if counts else "unresolved_in_observed_scope"

    def membership(address):
        return memberships[address]

    annotated, edges = [], {}
    for call in calls:
        caller, caller_basis = membership(call["from"])
        if call["to"] in entries:
            target, target_basis = call["to"], "observed_function_entry"
        else:
            target, target_basis = membership(call["to"])
        annotated.append({**call, "caller_function": caller, "target_function": target,
                          "caller_basis": caller_basis, "target_basis": target_basis})
        key = (caller, target, call["from"] if caller is None else None,
               call["to"] if target is None else None)
        if key not in edges:
            edges[key] = {"caller_function": caller, "target_function": target,
                          "caller_basis": caller_basis, "target_basis": target_basis,
                          "unresolved_callsite": call["from"] if caller is None else None,
                          "unresolved_target": call["to"] if target is None else None, "observed_calls": 0}
        edges[key]["observed_calls"] += 1
    return annotated, list(edges.values())


def inspect(args, store):
    address, timeout, max_output, max_items = _parameters(args)
    try:
        before = _file_fact(store, args.path)
    except (OSError, RuntimeError, UnicodeError) as error:
        raise ForgeError("Native input must be a safe regular nonsecret project file") from error
    binary = str(store.root / before["path"])
    tool = executable("r2")
    data = {"schema": "forge.native.v1", "tool": {"name": "radare2", "executable": tool, "version": None},
            "action": args.action, "binary_before": before, "binary_after": None,
            "binary_unchanged": False, "parameters": {"requested_address": address, "selected_address": address,
            "address_source": "explicit" if address is not None else None, "timeout": timeout,
            "max_output": max_output, "max_items": max_items, "analysis": "aaa"},
            "processes": [], "instructions": [], "xrefs": [], "call_edges": [],
            "function_nodes": [], "function_blocks": [], "function_edges": [],
            "caps": {"output_bytes": max_output, "items": max_items, "items_omitted": 0,
                     "items_limit_reached": False, "output_truncated": False},
            "limitations": _LIMITATIONS, "errors": [], "success": False}
    deadline = time.monotonic() + timeout
    retained = 0

    def run(label, command=None):
        nonlocal retained
        remaining = deadline - time.monotonic()
        budget = max_output - retained
        if remaining <= 0 or budget <= 0:
            raise ForgeError("Native analysis exhausted its timeout or combined output budget")
        argv = [tool, "-v"] if command is None else [tool, "-N", "-q", "-e", "scr.color=0", "-c", command, binary]
        capture = _capture(argv, store.root, remaining, min(budget, 16384) if command is None else budget)
        retained += len(capture["stdout"]) + len(capture["stderr"])
        facts = {key: value for key, value in capture.items() if key not in {"stdout", "stderr"}}
        facts.update(label=label, command=command, stderr=scrub_text(capture["stderr"].decode("utf-8", "replace")))
        facts.update(stdout_preview=scrub_text(capture["stdout"][:4096].decode("utf-8", "replace")),
                     stdout_preview_truncated=len(capture["stdout"]) > 4096,
                     retained_stdout_sha256=hashlib.sha256(capture["stdout"]).hexdigest())
        data["processes"].append(facts)
        data["caps"]["output_truncated"] |= capture["truncated"]
        if capture["error"] or capture["timed_out"] or capture["exit_code"] != 0 or capture["truncated"]:
            raise ForgeError(f"radare2 {label} failed, timed out, or exceeded its capture cap")
        return capture["stdout"]

    def retain(key, rows):
        available = max_items - sum(len(data[name]) for name in
                                   ("instructions", "xrefs", "call_edges", "function_nodes", "function_blocks", "function_edges"))
        data[key].extend(rows[:available])
        data["caps"]["items_omitted"] += max(0, len(rows) - available)
        data["caps"]["items_limit_reached"] |= len(rows) >= available

    try:
        raw_version = run("version")
        try:
            version = raw_version.decode("utf-8", "strict").strip()
        except UnicodeError:
            raise ForgeError("radare2 version is not UTF-8") from None
        if not version:
            raise ForgeError("radare2 returned no version identity")
        data["tool"]["version"] = scrub_text(version)
        if address is None and args.action != "callgraph":
            entries = _json(run("entrypoints", "iej"))
            if not entries or not _unsigned(entries[0].get("vaddr")):
                raise ForgeError("No observed radare2 entrypoint; provide --address explicitly")
            address = entries[0]["vaddr"]
            data["parameters"].update(selected_address=address, address_source="first_backend_entrypoint")
        normalized = f"0x{address:x}" if address is not None else None
        if args.action == "disasm":
            retain("instructions", _instructions(_json(run("disassembly", f"aaa;pdj {max_items} @ {normalized}"))))
        elif args.action == "xrefs":
            retain("xrefs", _xrefs(_json(run("incoming_xrefs", f"aaa;axtj @ {normalized}")), "incoming", address=address))
            retain("xrefs", _xrefs(_json(run("outgoing_xrefs", f"aaa;axfj @ {normalized}")), "outgoing", address=address))
        else:
            command = "aaa;axlj" if address is None else f"aaa;axfj @ {normalized}"
            calls = _xrefs(_json(run("call_xrefs", command)),
                           direction="outgoing" if address is not None else None,
                           calls_only=True, address=address)
            nodes = _functions(_json(run("functions", "aaa;aflj")))
            node_budget = max_items // 4
            data["function_nodes"] = nodes[:node_budget]
            data["caps"]["items_omitted"] += len(nodes) - len(data["function_nodes"])
            block_budget = max_items // 4
            commands, queried_nodes, command_size = [], [], 3
            for node in data["function_nodes"][:block_budget]:
                command = f"afbj @ 0x{node['offset']:x}"
                if command_size + len(command) + 1 > 12000:
                    break
                commands.append(command)
                queried_nodes.append(node)
                command_size += len(command) + 1
            if commands:
                documents = _json_documents(run("function_blocks", "aaa;" + ";".join(commands)), len(commands))
                for node, rows in zip(queried_nodes, documents):
                    blocks = _blocks(rows, node["offset"])
                    available = block_budget - len(data["function_blocks"])
                    data["function_blocks"].extend(blocks[:available])
                    data["caps"]["items_omitted"] += max(0, len(blocks) - available)
            data["caps"]["block_functions_unqueried"] = len(nodes) - len(queried_nodes)
            data["caps"]["block_command_characters"] = command_size
            call_budget = (max_items - len(data["function_nodes"]) - len(data["function_blocks"]) + 1) // 2
            observed_calls = calls[:call_budget]
            data["caps"]["items_omitted"] += len(calls) - len(observed_calls)
            annotated, edges = _function_graph(observed_calls, data["function_nodes"], data["function_blocks"])
            retain("call_edges", annotated)
            retain("function_edges", edges)
            data["caps"]["items_limit_reached"] |= data["caps"]["items_omitted"] > 0
            data["parameters"]["function_membership"] = "observed_afbj_basic_blocks"
            data["parameters"]["function_scope"] = "capped_backend_aflj_order"
    except ForgeError as error:
        data["errors"].append(str(error))
    try:
        data["binary_after"] = _file_fact(store, before["path"], relative_only=True)
        data["binary_unchanged"] = before == data["binary_after"]
        if not data["binary_unchanged"]:
            data["errors"].append("Native input changed during analysis")
    except (ForgeError, OSError, RuntimeError, UnicodeError):
        data["errors"].append("Native input could not be safely hashed after analysis")
    data["success"] = not data["errors"]
    record = store.add("analysis", data)
    if not data["success"]:
        raise ForgeError(f"radare2 analysis failed; see evidence {record['id']}: {'; '.join(data['errors'])}")
    return record

"""Read-only, bounded collection of local Thunderbolt prerequisite evidence.

A complete result describes evidence, not DMA execution, ACS isolation or a P2P
path. Capture receipts are trusted local research provenance, not attestation.
"""

import hashlib
import json
from pathlib import Path
import re
import struct
import time


_LINE_LIMIT = 64 * 1024
_FILE_LIMIT = 16 * 1024 * 1024
_RECORD_LIMIT = 100000
_U32 = (1 << 32) - 1
_U64 = (1 << 64) - 1
_BDF = re.compile(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", re.ASCII)
_HEX_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", re.ASCII)
_XD_NAME = re.compile(r"([0-9]{1,10})-([0-9a-f]{1,16})", re.ASCII)
_MARKER = re.compile(
    r"XDEV_EXT_XDOMAIN_PATH phase=(BEGIN|END) scope=([0-9]{1,20}) "
    r"token=([0-9]{1,20}) local_inc=([0-9]{1,20}) "
    r"remote_inc=([0-9]{1,20}) xdomain=([0-9]{1,10}-[0-9a-f]{1,16}) "
    r"role=(data|control) channel=([0-9]{1,10})(?: result=(-?[0-9]{1,11}))?",
    re.ASCII,
)
_CREDIT = re.compile(
    r"([0-9a-f]{1,16}):([0-9]{1,10}): reserving ([0-9]{1,10}) credits for DMA path",
    re.ASCII,
)
_EXPECTED_KEYS = {"identity", "nhi_bdf", "domain", "link_token", "channel", "max_log_age_ms"}
_IDENTITY_KEYS = {"version", "run_id", "sha", "role", "case", "direction", "epoch", "request_id"}
_RECEIPT_KEYS = {
    "version", "identity", "boot_id", "kernel_build_id", "nhi_bdf", "domain",
    "cursor_seq", "begin_ns", "end_ns", "captured_monotonic_ns", "complete",
    "kmsg_lost", "log_sha256",
}
_RECORD_KEYS = {"seq", "monotonic_ns", "message", "raw"}


class _Invalid(ValueError):
    pass


def _require(condition, reason):
    if not condition:
        raise _Invalid(reason)


def _uint(value, maximum, name):
    _require(type(value) is int and 0 <= value <= maximum, "invalid " + name)
    return value


def _keys(value, keys, name):
    _require(type(value) is dict and set(value) == keys, "invalid " + name + " keys")


def _text(value, name, limit=128):
    _require(type(value) is str and value and "\0" not in value, "invalid " + name)
    _require(len(value.encode("utf-8")) <= limit, "oversized " + name)
    return value


def _identity(value):
    _keys(value, _IDENTITY_KEYS, "identity")
    _require(type(value["version"]) is int and value["version"] == 1, "identity version")
    for key in ("run_id", "sha", "role", "case", "direction"):
        _text(value[key], "identity " + key)
    _require(_HEX_ID.fullmatch(value["sha"]) is not None, "identity SHA")
    _require(value["role"] in ("tx", "rx"), "identity role")
    _require(value["direction"] in ("a-to-b", "b-to-a"), "identity direction")
    _uint(value["epoch"], _U64, "identity epoch")
    _uint(value["request_id"], _U64, "identity request_id")


def _pairs(pairs):
    obj = {}
    for key, value in pairs:
        _require(key not in obj, "duplicate JSON key")
        obj[key] = value
    return obj


def _constant(_value):
    raise _Invalid("nonfinite JSON number")


def _json(data):
    return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)


def _read(path, limit):
    # Read one byte beyond the explicit limit, never a whole arbitrary file.
    with open(path, "rb") as stream:
        data = stream.read(limit + 1)
    _require(len(data) <= limit, "oversized evidence file: " + str(path))
    return data


def _within(path, parent):
    return path == parent or parent in path.parents


def _resolve(path, root):
    value = path.resolve(strict=True)
    _require(_within(value, root), "sysfs evidence escapes root")
    return value


def _build_id(notes):
    # /sys/kernel/notes is the native-endian ELF note stream, not an ELF file.
    pos = 0
    ids = []
    while pos < len(notes):
        _require(len(notes) - pos >= 12, "truncated kernel build notes")
        namesz, descsz, kind = struct.unpack_from("=III", notes, pos)
        pos += 12
        name_end = pos + namesz
        desc_start = pos + ((namesz + 3) & ~3)
        desc_end = desc_start + descsz
        next_pos = desc_start + ((descsz + 3) & ~3)
        _require(next_pos <= len(notes), "truncated kernel build note")
        if notes[pos:name_end] == b"GNU\0" and kind == 3:
            _require(0 < descsz <= 128, "invalid GNU build ID length")
            ids.append(notes[desc_start:desc_end].hex())
        pos = next_pos
    _require(len(ids) == 1, "missing or ambiguous running GNU build ID")
    return ids[0]


def _pci_acs(path):
    config = _read(path / "config", 4096)
    _require(len(config) >= 260, "unknown extended capabilities: unreadable or truncated PCI config")
    capability = control = None
    offset = 0x100
    visited = set()
    while offset < len(config):
        _require(offset >= 0x100 and offset % 4 == 0 and offset + 4 <= len(config),
                 "invalid PCI extended capability offset")
        _require(offset not in visited, "PCI extended capability loop")
        visited.add(offset)
        header = int.from_bytes(config[offset:offset + 4], "little")
        kind = header & 0xffff
        if kind in (0, 0xffff):
            break
        if kind == 0x000d:
            _require(capability is None and offset + 8 <= len(config),
                     "ambiguous or truncated PCI ACS capability")
            capability = int.from_bytes(config[offset + 4:offset + 6], "little")
            control = int.from_bytes(config[offset + 6:offset + 8], "little")
        following = header >> 20
        if following == 0:
            break
        _require(following >= 0x100 and following % 4 == 0 and following + 4 <= len(config),
                 "invalid PCI extended capability chain")
        offset = following
    return {"bdf": path.name, "capability": capability, "control": control,
            "raw_config_hex": config.hex()}


def _topology(root, bdf, domain, result):
    root = root.resolve(strict=True)
    nhi = _resolve(root / "bus/pci/devices" / bdf, root)
    _require(nhi.is_dir() and nhi.name == bdf, "NHI sysfs device mismatch")
    domain_path = _resolve(root / "bus/thunderbolt/devices" / ("domain" + str(domain)), root)
    _require(domain_path.is_dir() and domain_path.name == "domain" + str(domain)
             and nhi in domain_path.parents, "Thunderbolt domain/NHI ancestry mismatch")

    group_link = nhi / "iommu_group"
    _require(group_link.is_symlink(), "unknown IOMMU group: missing actual symlink")
    group_path = _resolve(group_link, root)
    groups_root = _resolve(root / "kernel/iommu_groups", root)
    _require(group_path.parent == groups_root and group_path.name.isascii()
             and group_path.name.isdecimal(), "invalid IOMMU group ancestry")
    raw = _read(group_path / "type", _LINE_LIMIT).decode("utf-8")
    group_type = raw.strip()
    _require(bool(group_type) and "\0" not in group_type, "unknown IOMMU type")
    result["iommu"] = {"group": group_path.name, "type": group_type, "raw": raw}

    # Only actual PCI device directories on this NHI's ancestry are observations.
    for path in (nhi, *nhi.parents):
        if path == root:
            break
        if _BDF.fullmatch(path.name):
            result["acs"].append(_pci_acs(path))
    _require(bool(result["acs"]), "unknown PCI ancestry")
    return root, nhi, domain_path


def _routes(name, domain, topology):
    root, nhi, domain_path = topology
    match = _XD_NAME.fullmatch(name)
    _require(match is not None and int(match[1]) == domain, "XDomain domain mismatch")
    _uint(int(match[1]), _U32, "XDomain domain")
    path = _resolve(root / "bus/thunderbolt/devices" / name, root)
    _require(path.is_dir() and path.name == name and domain_path in path.parents
             and nhi in path.parents, "XDomain actual ancestry mismatch")
    routes = set()
    for parent in path.parents:
        if parent == domain_path:
            break
        router = _XD_NAME.fullmatch(parent.name)
        if router is not None:
            _require(int(router[1]) == domain, "router domain mismatch")
            bus_path = _resolve(root / "bus/thunderbolt/devices" / parent.name, root)
            _require(bus_path == parent, "router actual ancestry mismatch")
            routes.add(int(router[2], 16))
    _require(bool(routes), "missing actual ancestor router")
    return routes


def _raw_record(record):
    _keys(record, _RECORD_KEYS, "kmsg record")
    _uint(record["seq"], _U64, "kmsg sequence")
    _uint(record["monotonic_ns"], _U64, "kmsg monotonic time")
    _require(type(record["message"]) is str and type(record["raw"]) is str,
             "invalid kmsg text")
    raw = record["raw"]
    _require(";" in raw and raw.endswith("\n") and "\0" not in raw, "malformed raw kmsg")
    header, body = raw.split(";", 1)
    fields = header.split(",")
    _require(len(fields) in (4, 5), "malformed raw kmsg header")
    if len(fields) == 5:
        caller = re.fullmatch(r"caller=[CT]([0-9]{1,10})", fields[4], re.ASCII)
        _require(caller is not None, "malformed raw kmsg caller")
        _uint(int(caller[1]), (1 << 31) - 1, "raw kmsg caller")
    for field in fields[:3]:
        _require(1 <= len(field) <= 20 and field.isascii() and field.isdecimal(),
                 "malformed raw kmsg number")
    priority, sequence, usec = map(int, fields[:3])
    _uint(priority, 191, "kmsg priority")
    _uint(sequence, _U64, "raw kmsg sequence")
    _uint(usec, _U64 // 1000, "raw kmsg timestamp")
    _require(fields[3] in ("-", "c"), "invalid raw kmsg flags")
    # Device dictionary lines follow the printk message. Retain them verbatim.
    lines = body[:-1].split("\n")
    _require(all(line.startswith(" ") and "=" in line for line in lines[1:]),
             "malformed raw kmsg dictionary")
    _require(sequence == record["seq"] and usec * 1000 == record["monotonic_ns"]
             and lines[0] == record["message"], "raw/JSON kmsg disagreement")


def _log(path, receipt):
    digest = hashlib.sha256()
    records = []
    seen = set()
    total = 0
    previous = None
    postcursor = receipt["cursor_seq"]
    with open(path, "rb") as stream:
        while True:
            line = stream.readline(_LINE_LIMIT + 1)
            if not line:
                break
            total += len(line)
            _require(len(line) <= _LINE_LIMIT and line.endswith(b"\n"),
                     "oversized or truncated JSONL line")
            _require(total <= _FILE_LIMIT, "oversized kmsg capture")
            _require(len(records) < _RECORD_LIMIT, "too many kmsg records")
            digest.update(line)
            record = _json(line)
            _raw_record(record)
            _require(record["monotonic_ns"] <= receipt["captured_monotonic_ns"],
                     "kmsg timestamp after receipt capture")
            sequence = record["seq"]
            _require(sequence not in seen, "duplicate kmsg sequence")
            _require(previous is None or sequence > previous, "out-of-order kmsg sequence")
            if sequence > receipt["cursor_seq"]:
                _require(sequence == postcursor + 1, "missing postcursor kmsg sequence")
                postcursor = sequence
            seen.add(sequence)
            previous = sequence
            records.append(record)
    log_hash = digest.hexdigest()
    _require(log_hash == receipt["log_sha256"], "capture hash mismatch")
    return records, log_hash


def _scoped(records, receipt, expected, topology, result):
    prefix = "thunderbolt " + expected["nhi_bdf"] + ": "
    cm_records = []
    active = None
    scopes = set()
    latest = {}
    expected_devices = set()
    routes_cache = {}
    for record in records:
        message = record["message"]
        if not message.startswith(prefix):
            continue
        body = message[len(prefix):]
        if body in ("using software connection manager", "using firmware connection manager"):
            cm_records.append(record)
            continue
        marker = _MARKER.fullmatch(body)
        credit = _CREDIT.fullmatch(body)
        if body.startswith("XDEV_EXT_XDOMAIN_PATH"):
            _require(marker is not None, "malformed XDomain path marker")
        if marker is None and credit is None:
            continue
        _require(record["seq"] > receipt["cursor_seq"]
                 and receipt["begin_ns"] <= record["monotonic_ns"] <= receipt["end_ns"],
                 "path/credit outside current capture window or cursor")
        if marker is not None:
            phase, scope, token, local, remote, name, role, channel, outcome = marker.groups()
            scope = _uint(int(scope), _U64, "scope")
            token = _uint(int(token), _U64, "path token")
            local = _uint(int(local), _U64, "local incarnation")
            remote = _uint(int(remote), _U64, "remote incarnation")
            channel = _uint(int(channel), _U32, "path channel")
            _require((phase == "END") == (outcome is not None), "path result/phase mismatch")
            if outcome is not None:
                outcome = int(outcome)
                _require(-(1 << 31) <= outcome < (1 << 31), "path result overflow")
            if name not in routes_cache:
                routes_cache[name] = _routes(name, expected["domain"], topology)
            key = (scope, token, local, remote, name, role, channel)
            if phase == "BEGIN":
                _require(active is None and scope not in scopes,
                         "nested/interleaved or reused path scope")
                scopes.add(scope)
                active = {"key": key, "begin": record["seq"], "credits": [],
                          "routes": routes_cache[name]}
            else:
                _require(active is not None and active["key"] == key,
                         "unmatched or inconsistent path END")
                active["end"] = record["seq"]
                active["result"] = outcome
                relevant_channel = (role == "control" and channel == 0) or (
                    role == "data" and channel == expected["channel"])
                if relevant_channel:
                    # Device/role/channel select the current attempt. A token
                    # change on that same device cannot resurrect old success.
                    latest[(name, role, channel)] = active
                    if token == expected["link_token"]:
                        expected_devices.add(name)
                active = None
        elif active is not None:
            route, port, reserved = credit.groups()
            route = int(route, 16)
            port = _uint(int(port), _U32, "reservation port")
            reserved = _uint(int(reserved), _U32, "reserved credits")
            _require(route in active["routes"], "credit router not in actual XDomain ancestry")
            active["credits"].append((record["seq"], port, reserved))
    _require(active is None, "unmatched latest path BEGIN")
    result["software_cm"]["records"] = cm_records
    _require(bool(cm_records) and cm_records[-1]["message"] == prefix + "using software connection manager",
             "missing exact-NHI software connection manager or latest is firmware")
    result["software_cm"]["proved"] = True
    _require(len(expected_devices) == 1, "missing or ambiguous expected-token XDomain")
    device = next(iter(expected_devices))
    data = latest.get((device, "data", expected["channel"]))
    control = latest.get((device, "control", 0))
    _require(data is not None and control is not None, "missing current data/control path scopes")
    _require(data["key"][1] == expected["link_token"]
             and control["key"][1] == expected["link_token"], "latest same-device path token mismatch")
    _require(data["result"] == 0 and control["result"] == 0, "latest path invocation failed")
    _require(data["end"] < control["begin"], "latest data END must precede latest control BEGIN")
    _require(data["key"][1:5] == control["key"][1:5], "cross-role token/incarnation/XDomain mismatch")
    for scoped in (data, control):
        _require(any(reserved > 0 for _, _, reserved in scoped["credits"]),
                 "missing positive actual reservation in selected path scope")
        scope, _, _, _, _, role, channel = scoped["key"]
        for sequence, port, reserved in scoped["credits"]:
            result["credits"].append({"scope": scope, "role": role, "channel": channel,
                                      "port": port, "reserved": reserved,
                                      "begin_seq": scoped["begin"], "end_seq": scoped["end"],
                                      "record_seq": sequence})


def collect_platform_facts(log_path, receipt_path, expected, *, sysfs_root="/sys", proc_root="/proc"):
    """Return the exact C1 evidence schema; invalid or unavailable facts fail closed."""
    source = expected if type(expected) is dict else {}
    result = {
        "status": "incomplete", "reason": "collection not completed",
        "identity": {"run": source.get("identity"), "boot_id": None,
                     "kernel_build_id": None, "nhi_bdf": source.get("nhi_bdf"),
                     "domain": source.get("domain"), "link_token": source.get("link_token"),
                     "channel": source.get("channel")},
        "software_cm": {"proved": False, "records": []}, "credits": [],
        "iommu": {"group": None, "type": None, "raw": ""}, "acs": [],
        "evidence": {"log_path": str(log_path), "receipt_path": str(receipt_path),
                     "log_sha256": None},
    }
    try:
        _keys(expected, _EXPECTED_KEYS, "expected")
        _identity(expected["identity"])
        _require(type(expected["nhi_bdf"]) is str and _BDF.fullmatch(expected["nhi_bdf"]) is not None,
                 "invalid expected NHI BDF")
        _uint(expected["domain"], _U32, "expected domain")
        _uint(expected["channel"], _U32, "expected channel")
        _uint(expected["link_token"], _U64, "expected link token")
        _uint(expected["max_log_age_ms"], 120000, "max log age")
        _require(expected["max_log_age_ms"] >= 1, "max log age below one ms")
        receipt = _json(_read(receipt_path, _LINE_LIMIT))
        _keys(receipt, _RECEIPT_KEYS, "receipt")
        _require(type(receipt["version"]) is int and receipt["version"] == 1, "receipt version")
        _identity(receipt["identity"])
        _require(receipt["identity"] == expected["identity"], "receipt identity mismatch")
        _uint(receipt["domain"], _U32, "receipt domain")
        _require(receipt["nhi_bdf"] == expected["nhi_bdf"] and receipt["domain"] == expected["domain"],
                 "receipt NHI/domain mismatch")
        for key in ("cursor_seq", "begin_ns", "end_ns", "captured_monotonic_ns", "kmsg_lost"):
            _uint(receipt[key], _U64, "receipt " + key)
        _require(receipt["complete"] is True and receipt["kmsg_lost"] == 0,
                 "incomplete or lost kmsg capture")
        _require(type(receipt["log_sha256"]) is str
                 and re.fullmatch(r"[0-9a-f]{64}", receipt["log_sha256"], re.ASCII) is not None,
                 "invalid capture SHA256")
        now = time.monotonic_ns()
        _require(receipt["begin_ns"] <= receipt["end_ns"] <= receipt["captured_monotonic_ns"] <= now,
                 "invalid capture chronology or future receipt")
        _require(now - receipt["captured_monotonic_ns"] <= expected["max_log_age_ms"] * 1000000,
                 "stale capture receipt")
        boot = _read(Path(proc_root) / "sys/kernel/random/boot_id", _LINE_LIMIT).decode("ascii").strip()
        _require(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                             boot, re.ASCII) is not None, "invalid current boot ID")
        build = _build_id(_read(Path(sysfs_root) / "kernel/notes", _FILE_LIMIT))
        result["identity"]["boot_id"] = boot
        result["identity"]["kernel_build_id"] = build
        _require(receipt["boot_id"] == boot and receipt["kernel_build_id"] == build,
                 "capture boot/build does not match running kernel")
        records, log_hash = _log(log_path, receipt)
        result["evidence"]["log_sha256"] = log_hash
        topology = _topology(Path(sysfs_root), expected["nhi_bdf"], expected["domain"], result)
        _scoped(records, receipt, expected, topology, result)
        result["status"] = "complete"
        result["reason"] = "complete prerequisite evidence; physical execution and isolation are not certified"
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RuntimeError, struct.error) as error:
        result["reason"] = str(error)[:1024] or type(error).__name__
    return result

#!/usr/bin/env python3
"""Inspect installed GRUB kernels; explicitly request an orderly normal kexec.

No bootloader or device configuration is changed.  A successful request is
not evidence that the new kernel booted, that devices reset, or that panic
recovery works.  See docs/guides/kernel-switch.md before using --execute.
"""

import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


CONFIG = "/boot/grub/grub.cfg"
ENVIRONMENT = "/boot/grub/grubenv"
NORMAL_LOADED = "/sys/kernel/kexec_loaded"
CRASH_LOADED = "/sys/kernel/kexec_crash_loaded"
LOCK = "/run/lock/xdev-kernel-switch.lock"
_RELEASE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+\-]*\Z")
_ID = re.compile(r"[A-Za-z0-9_.:+/\-]+\Z")
_UUID = r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"


class SwitchError(Exception):
    def __init__(self, state, message, exit_code=3):
        super().__init__(message)
        self.state = state
        self.exit_code = exit_code


def _reject(message, state="preflight-rejected", exit_code=3):
    raise SwitchError(state, message, exit_code)


def _words(line):
    if len(line) > 16384:
        _reject("GRUB line exceeds the supported size")
    try:
        return shlex.split(line, comments=True, posix=True)
    except ValueError as error:
        _reject(f"Cannot parse GRUB line: {error}")


def _brace_delta(line):
    """Count script braces, excluding quoted text and ${parameter} syntax."""
    quote = None
    escaped = False
    variable = 0
    delta = 0
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
        elif char == "#":
            break
        elif char == "{" and index and line[index - 1] == "$":
            variable += 1
        elif variable:
            if char == "}":
                variable -= 1
        elif char == "{":
            delta += 1
        elif char == "}":
            delta -= 1
    return delta


def _entry_id(words):
    found = []
    for index, word in enumerate(words):
        if word in ("--id", "$menuentry_id_option", "${menuentry_id_option}"):
            if index + 1 < len(words):
                found.append(words[index + 1])
        elif word.startswith("--id="):
            found.append(word[5:])
    if len(found) != 1 or not _ID.fullmatch(found[0]):
        _reject("Only explicit, unique GRUB entry IDs are supported")
    return found[0]


def _parse_entry(entry, lines):
    linux = []
    initrds = []
    roots = set()
    unsafe = list(entry.get("unsafe", []))
    args = []
    allowed = {"recordfail", "load_video", "gfxmode", "insmod", "echo", "if",
               "then", "else", "fi", "[", "}", "{"}
    for line in lines:
        words = _words(line)
        if not words:
            continue
        command = words[0]
        if command == "linux":
            if len(words) < 2:
                unsafe.append("linux command has no image")
            else:
                linux.append(words[1])
                args = words[2:]
        elif command == "initrd":
            initrds.extend(words[1:])
        elif command == "search":
            if "--fs-uuid" not in words or "--set=root" not in words:
                unsafe.append("search does not select a literal filesystem UUID")
            elif words[-1].startswith("-") or not re.fullmatch(r"[A-Za-z0-9\-]+", words[-1]):
                unsafe.append("search filesystem UUID is not literal")
            else:
                roots.add(words[-1].lower())
        elif command == "set":
            assignment = " ".join(words[1:])
            if assignment.startswith("root="):
                if roots:
                    unsafe.append("root reassigned after filesystem search")
            elif not assignment.startswith("gfxpayload="):
                unsafe.append("entry changes unsupported GRUB state")
        elif command not in allowed:
            unsafe.append(f"unsupported entry command: {command}")
    if len(linux) != 1 or len(initrds) != 1:
        unsafe.append("exactly one linux image and one initrd are required")
    if len(roots) != 1:
        unsafe.append("entry must select exactly one literal filesystem UUID")
    for value in linux + initrds + args:
        if any(char in value for char in ("$", "`", "\x00", "\n", "\r")):
            unsafe.append("entry contains dynamic substitutions")
    entry.update(linux=linux[0] if len(linux) == 1 else "",
                 initrd=initrds[0] if len(initrds) == 1 else "", args=args,
                 root_uuid=next(iter(roots)) if len(roots) == 1 else "",
                 unsafe=sorted(set(unsafe)))
    return entry


def _header_condition(words):
    # Header conditions may inspect facts, not invoke a custom state-changing
    # function or regexp --set. Standard display/capability probes are read-only.
    if len(words) < 2 or words[1] not in ("[", "test", "loadfont", "keystatus", "cpuid"):
        _reject("Custom GRUB condition commands have unknown fallback effects")
    condition = " ".join(words[1:]).replace("] ;", "];")
    if condition in ("[ -s $prefix/grubenv ]; then", "[ -s ${prefix}/grubenv ]; then"):
        return "grubenv"
    for name in ("next_entry", "prev_entry", "prev_saved_entry", "env_block"):
        if condition in (f"[ ${{{name}}} ]; then", f"[ ${name} ]; then"):
            return name
    return "other"


def _fallback_effect(line):
    return re.search(r"(?:^|[;\s])(?:set\s+)?(?:default|saved_entry|next_entry|prev_entry|prev_saved_entry|prefix|env_block)\s*=|"
                     r"(?:^|[;\s])(?:load_env|eval|configfile|savedefault)(?:\s|;|$)|"
                     r"(?:^|[;\s])save_env\s+(?:default|saved_entry|next_entry|prev_entry|prev_saved_entry)(?:\s|;|$)", line)


def parse_grub(config_text, environment_text):
    if len(config_text) > 2 * 1024 * 1024:
        _reject("GRUB configuration exceeds the supported size")
    environment = {}
    for line in environment_text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or key in environment:
            _reject("Malformed or duplicate GRUB environment assignment")
        environment[key] = value
    if environment.get("env_block"):
        _reject("An alternate GRUB environment block is unsupported")
    entries = {}
    stack = []
    depth = 0
    active = None
    bodies = []
    defaults = set()
    conditions = []
    environment_loaded = False
    saved_default = False
    function_name = None
    for line in config_text.splitlines():
        stripped = line.strip()
        delta = _brace_delta(line)
        if active is not None:
            if depth + delta < active["depth"]:
                parsed = _parse_entry(active["entry"], bodies)
                if parsed["id"] in entries:
                    _reject("Duplicate full GRUB entry ID")
                entries[parsed["id"]] = parsed
                active = None
                bodies = []
            else:
                bodies.append(line)
        elif function_name is not None:
            if function_name != "savedefault" and _fallback_effect(stripped):
                _reject("A custom GRUB helper can change fallback state")
            helper_words = _words(line)
            if function_name != "savedefault" and helper_words:
                if helper_words[0] not in ("if", "elif", "else", "fi", "insmod", "set", "save_env", "}"):
                    _reject("Custom commands inside a GRUB helper are unsupported")
                if helper_words[0] in ("if", "elif"):
                    _header_condition(helper_words)
            if depth + delta == 0:
                function_name = None
        elif stripped.startswith(("menuentry ", "submenu ")):
            words = _words(line)
            if len(words) < 4 or words[-1] != "{" or delta != 1:
                _reject("Unsupported GRUB entry declaration")
            entry_id = _entry_id(words)
            full_id = ">".join([item["id"] for item in stack] + [entry_id])
            conditional = bool(conditions) or any(item["conditional"] for item in stack)
            if words[0] == "submenu":
                stack.append({"id": entry_id, "depth": depth + 1, "conditional": conditional})
            else:
                unsafe = ["entry or parent submenu is conditionally defined"] if conditional else []
                active = {"entry": {"id": full_id, "title": words[1], "unsafe": unsafe}, "depth": depth + 1}
        elif depth == (stack[-1]["depth"] if stack else 0):
            words = _words(line)
            if words and words[0] in ("if", "elif"):
                if _fallback_effect(stripped):
                    _reject("Inline custom GRUB control flow can change the fallback")
                if words[0] == "if":
                    conditions.append(_header_condition(words))
                elif conditions:
                    conditions[-1] = _header_condition(words)
                else:
                    _reject("Unmatched GRUB elif")
            elif words and words[0] == "else":
                if not conditions:
                    _reject("Unmatched GRUB else")
                conditions[-1] = "else:" + conditions[-1]
            elif words and words[0] == "fi":
                if not conditions:
                    _reject("Unmatched GRUB fi")
                conditions.pop()
            if words and words[0] == "function":
                if depth:
                    _reject("Helpers inside submenu definitions are unsupported")
                if len(words) != 3 or words[2] != "{" or delta != 1:
                    _reject("Unsupported GRUB helper declaration")
                if words[1] not in ("savedefault", "recordfail", "load_video", "gfxmode", "initrdfail"):
                    _reject("Custom GRUB helpers are unsupported; their fallback effects are unknown")
                function_name = words[1]
            if len(words) >= 2 and words[0] == "set" and words[1].startswith("default="):
                value = words[1][8:]
                if value in ("${next_entry}", "$next_entry"):
                    if conditions != ["next_entry"]:
                        _reject("Transient GRUB default is outside its standard next_entry guard")
                elif value in ("${saved_entry}", "$saved_entry"):
                    if (conditions not in ([], ["else:next_entry"])
                            or "'" in stripped.partition("=")[2]):
                        _reject("Unsupported saved-default quoting or conditional control flow")
                    saved_default = True
                    defaults.add(environment.get("saved_entry", ""))
                elif "$" in value or "`" in value:
                    _reject("Dynamic persistent GRUB default is unsupported")
                else:
                    if conditions not in ([], ["else:next_entry"]):
                        _reject("Conditional custom GRUB persistent default is unsupported")
                    defaults.add(value)
            elif words and words[0] == "load_env":
                if len(words) == 1 and conditions in ([], ["grubenv"]):
                    environment_loaded = True
                elif not (words == ["load_env", "-f", "${env_block}"]
                          and conditions == ["env_block"] and not environment.get("env_block")):
                    _reject("Saved default requires the standard grubenv load, not custom control flow")
            elif words and words[0] in ("savedefault", "configfile", "eval", "unset"):
                _reject("Top-level GRUB control flow can change the fallback")
            elif words:
                assignment = words[1] if words[0] == "set" and len(words) == 2 else words[0]
                name, separator, value = assignment.partition("=")
                if separator and name in ("default", "saved_entry", "next_entry", "prev_entry", "prev_saved_entry", "prefix", "env_block"):
                    restored = (name == "saved_entry" and value == "${prev_saved_entry}"
                                and conditions == ["prev_saved_entry"])
                    cleared = (not value and name in ("next_entry", "prev_entry", "prev_saved_entry")
                               and conditions == [name])
                    previous = (name == "next_entry" and value == "${prev_entry}"
                                and conditions == ["prev_entry"])
                    if not (restored or cleared or previous):
                        _reject(f"Custom top-level {name} mutation can change the fallback")
                elif words[0] == "save_env":
                    arguments = words[1:]
                    alternate = arguments[:2] == ["-f", "${env_block}"]
                    if alternate:
                        arguments = arguments[2:]
                        if conditions[-1:] != ["env_block"] or environment.get("env_block"):
                            _reject("Custom save_env environment file is unsupported")
                    if len(arguments) != 1 or arguments[0].startswith("-"):
                        _reject("Only a standard single-variable save_env is supported")
                    key = arguments[0]
                    if key in ("default", "saved_entry", "next_entry", "prev_entry", "prev_saved_entry", "prefix", "env_block"):
                        permitted = "prev_saved_entry" if key == "saved_entry" else key
                        if (conditions[:1] != [permitted]
                                or conditions[1:] not in ([], ["env_block"], ["else:env_block"])):
                            _reject("Custom save_env control flow can change the fallback")
                elif not separator and words[0] not in {
                        "if", "elif", "else", "fi", "function", "}", "set", "save_env", "source",
                        "insmod", "search", "search.fs_uuid", "export", "loadfont", "load_video",
                        "terminal_input", "terminal_output", "serial", "background_color", "background_image",
                        "echo", "sleep", "keystatus", "play"}:
                    _reject("Unsupported top-level GRUB command: " + words[0])
        depth += delta
        if depth < 0:
            _reject("Unbalanced GRUB configuration braces")
        while stack and depth < stack[-1]["depth"]:
            stack.pop()
    if active is not None or depth or stack:
        _reject("Unterminated GRUB entry or function")
    if conditions:
        _reject("Unterminated GRUB header condition")
    if saved_default and not environment_loaded:
        _reject("The generated saved default never loads the standard grubenv")
    if len(defaults) != 1 or not next(iter(defaults)):
        _reject("Persistent generated GRUB default is missing or ambiguous")
    default = next(iter(defaults))
    if default not in entries:
        _reject("Persistent default must be a full, installed entry ID (not an index/title)")
    pending = {key: environment[key] for key in ("next_entry", "prev_entry", "prev_saved_entry")
               if environment.get(key)}
    return {"entries": entries, "default": default, "pending": pending,
            "environment": environment}


def read_bzimage_release(image_prefix):
    if (len(image_prefix) < 0x210 or image_prefix[0x1fe:0x200] != b"\x55\xaa"
            or image_prefix[0x202:0x206] != b"HdrS"
            or struct.unpack_from("<H", image_prefix, 0x206)[0] < 0x0200):
        _reject("Image is not a supported x86 Linux bzImage")
    offset = struct.unpack_from("<H", image_prefix, 0x20e)[0]
    if not offset:
        _reject("Image has no embedded kernel version")
    start = 0x200 + offset
    end = image_prefix.find(b"\x00", start, min(start + 1024, len(image_prefix)))
    if end < start:
        _reject("Embedded kernel version is missing or unterminated")
    try:
        version = image_prefix[start:end].decode("ascii")
    except UnicodeDecodeError:
        _reject("Embedded kernel version is not ASCII")
    parts = version.split()
    if not parts or not _RELEASE.fullmatch(parts[0]):
        _reject("Embedded kernel release is invalid")
    return parts[0]


def _cmdline_limit(image_prefix):
    protocol = struct.unpack_from("<H", image_prefix, 0x206)[0]
    if protocol < 0x0206:
        return 255
    if len(image_prefix) < 0x23c:
        _reject("Image has no readable command-line size")
    limit = struct.unpack_from("<I", image_prefix, 0x238)[0]
    if not limit:
        _reject("Image reports an unknown command-line size")
    return min(limit, 2047)


def parse_initrd_releases(listing):
    releases = set()
    for line in listing.splitlines():
        path = line.strip().removeprefix("./").lstrip("/")
        if len(path) > 4096:
            _reject("Unsupported initramfs listing path length")
        parts = path.split("/")
        if parts[:1] == ["usr"]:
            parts = parts[1:]
        if len(parts) >= 3 and parts[:2] == ["lib", "modules"]:
            if not _RELEASE.fullmatch(parts[2]):
                _reject("Invalid modules release in initramfs")
            releases.add(parts[2])
    return sorted(releases)


def normalise_cmdline(args, panic_seconds):
    if isinstance(panic_seconds, bool) or not isinstance(panic_seconds, int) or panic_seconds <= 0:
        _reject("panic-seconds must be a positive integer", exit_code=2)
    result = []
    for arg in args:
        if not isinstance(arg, str) or any(char in arg for char in ("\x00", "\n", "\r", "$", "`", '"', "\\")):
            _reject("Unsupported kernel command-line quoting or substitution")
        if arg.startswith("panic="):
            continue
        if arg == "panic":
            _reject("Bare panic argument is unsupported")
        # Linux command-line parsing understands double quotes, not shell escaping.
        result.append('"' + arg + '"' if any(c.isspace() for c in arg) else arg)
    result.append(f"panic={panic_seconds}")
    command_line = " ".join(result)
    if len(command_line.encode("utf-8")) > 2047:
        _reject("Kernel command line exceeds the supported 2047-byte limit; panic could be truncated")
    return command_line


def parse_efi_boot_manager(text):
    fields = {}
    entries = {}
    for line in text.splitlines():
        for key in ("BootCurrent", "BootOrder", "BootNext"):
            if line.startswith(key + ":"):
                if key in fields:
                    _reject(f"Duplicate EFI {key}")
                fields[key] = line.partition(":")[2].strip()
        match = re.match(r"Boot([0-9a-fA-F]{4})(\*?)\s+(.+)", line)
        if match:
            entry_id = match[1].upper()
            if entry_id in entries:
                _reject("Duplicate EFI boot entry")
            entries[entry_id] = (bool(match[2]), match[3])
    current = fields.get("BootCurrent", "").upper()
    order = fields.get("BootOrder", "").upper().split(",")
    if (not re.fullmatch(r"[0-9A-F]{4}", current)
            or not order or any(not re.fullmatch(r"[0-9A-F]{4}", item) for item in order)
            or order[0] != current or len(order) != len(set(order))):
        _reject("EFI BootCurrent must be the first unambiguous BootOrder entry")
    if fields.get("BootNext"):
        _reject("EFI BootNext could bypass the known-good GRUB fallback")
    if current not in entries or not entries[current][0]:
        _reject("The current EFI boot entry is absent or inactive")
    description = entries[current][1]
    start = description.find("HD(")
    if start < 0:
        _reject("Only the Ubuntu GPT ESP shim boot path is supported")
    path = description[start:]
    pattern = (r"HD\([0-9]+,GPT,(" + _UUID
               + r"),(?:0x[0-9a-f]+|[0-9]+),(?:0x[0-9a-f]+|[0-9]+)\)"
                 r"/\\EFI\\ubuntu\\shimx64\.efi(?:[0-9a-f]*)")
    match = re.fullmatch(pattern, path, flags=re.IGNORECASE)
    if not match:
        _reject("EFI boot entry is not the supported Ubuntu shim path")
    return {"boot_current": current, "boot_order": order,
            "partition_uuid": match[1].lower(), "loader_path": "/EFI/ubuntu/shimx64.efi"}


def parse_efi_forwarder(text):
    commands = [_words(line) for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if len(commands) != 3:
        _reject("Only the literal three-command Ubuntu EFI GRUB forwarder is supported")
    search, prefix, load = commands
    if (len(search) not in (3, 4) or search[0] != "search.fs_uuid"
            or not re.fullmatch(_UUID, search[1]) or search[2] != "root"
            or (len(search) == 4 and not re.fullmatch(r"[A-Za-z0-9,._\-]+", search[3]))):
        _reject("EFI forwarder must search a literal root filesystem UUID")
    if len(prefix) != 2 or prefix[0] != "set":
        _reject("EFI forwarder has no literal prefix")
    match = re.fullmatch(r"prefix=\(\$root\)(/[A-Za-z0-9_./+\-]+)", prefix[1])
    if (not match or ".." in PurePosixPath(match[1]).parts
            or load not in (["configfile", "$prefix/grub.cfg"], ["configfile", "${prefix}/grub.cfg"])):
        _reject("EFI forwarder uses an unsupported dynamic prefix/configfile")
    return {"root_uuid": search[1].lower(), "prefix": str(PurePosixPath(match[1]))}


class Host:
    euid = property(lambda self: os.geteuid())

    def read_text(self, path):
        with open(path, encoding="utf-8") as stream:
            text = stream.read(2 * 1024 * 1024 + 1)
        if len(text) > 2 * 1024 * 1024:
            _reject(f"Text file exceeds supported size: {path}")
        return text

    def read_bytes(self, path, limit):
        with open(path, "rb") as stream:
            return stream.read(limit)

    def stat(self, path):
        value = os.stat(path)
        return {"dev": value.st_dev, "ino": value.st_ino, "size": value.st_size,
                "mtime_ns": value.st_mtime_ns, "regular": stat.S_ISREG(value.st_mode)}

    def is_dir(self, path):
        return os.path.isdir(path)

    def realpath(self, path):
        return str(Path(path).resolve(strict=True))

    def which(self, name):
        return shutil.which(name)

    def run(self, argv):
        return subprocess.run(argv, shell=False, capture_output=True, text=True,
                              timeout=120, check=False,
                              env={**os.environ, "LC_ALL": "C", "SYSTEMD_COLORS": "0", "SYSTEMD_PAGER": ""})


def _checked_run(host, argv):
    result = host.run(argv)
    if result.returncode:
        _reject(f"Read-only command failed: {argv[0]}: {result.stderr.strip()[:1024]}")
    return result.stdout


def _flag(host, path):
    value = host.read_text(path).strip()
    if value not in ("0", "1"):
        _reject(f"Unknown kernel loaded flag: {path}")
    return value == "1"


def _flatten_mounts(records):
    result = []
    for record in records:
        result.append({key: str(record.get(key) or "") for key in ("target", "uuid", "source", "fstype")})
        result.extend(_flatten_mounts(record.get("children", [])))
    return result


def _loader_evidence(host, mounts):
    if not host.is_dir("/sys/firmware/efi"):
        _reject("Only the Ubuntu EFI GRUB 2 boot chain is supported")
    tool = host.which("bootctl")
    if tool:
        status = host.run([tool, "--no-pager", "status"])
        current = False
        for line in status.stdout.splitlines():
            if line.strip() == "Current Boot Loader:":
                current = True
                continue
            if current and line and not line[0].isspace():
                break
            if current and line.strip().startswith("Product:"):
                product = line.strip().partition(":")[2].strip().lower()
                if product and product not in ("n/a", "unknown") and not product.startswith("grub"):
                    _reject("The active loader is foreign/systemd-boot; only Ubuntu EFI GRUB 2 is supported")
    tools = {name: host.which(name) for name in ("efibootmgr", "findmnt", "lsblk")}
    if not all(tools.values()):
        _reject("efibootmgr, findmnt and lsblk are required to qualify the EFI chain")
    manager = parse_efi_boot_manager(_checked_run(host, [tools["efibootmgr"], "--verbose"]))
    data = json.loads(_checked_run(host, [tools["findmnt"], "--json", "--target", "/boot/efi",
                                         "--output", "TARGET,SOURCE,FSTYPE,UUID"]))
    esp_records = _flatten_mounts(data.get("filesystems", []))
    if len(esp_records) != 1 or esp_records[0]["target"] != "/boot/efi" or esp_records[0]["fstype"] != "vfat":
        _reject("The selected Ubuntu ESP must be mounted at /boot/efi as vfat")
    esp = esp_records[0]
    if not esp["source"].startswith("/dev/"):
        _reject("ESP block device identity is unknown")
    partition_uuid = _checked_run(host, [tools["lsblk"], "--noheadings", "--nodeps", "--output",
                                        "PARTUUID", esp["source"]]).strip().lower()
    if partition_uuid != manager["partition_uuid"]:
        _reject("The mounted ESP is not the partition selected by EFI BootCurrent")
    if esp not in mounts:
        mounts.append(esp)
    directory = "/boot/efi/EFI/ubuntu/"
    files = {name: host.stat(directory + name) for name in ("shimx64.efi", "grubx64.efi", "grub.cfg")}
    if any(not value["regular"] or value["size"] <= 0 for value in files.values()):
        _reject("Ubuntu EFI shim, GRUB binary and forwarder must be nonempty regular files")
    text = host.read_text(directory + "grub.cfg")
    forwarder = parse_efi_forwarder(text)
    mapped = _mapped_path(forwarder["prefix"] + "/grub.cfg", forwarder["root_uuid"], mounts, host)
    if mapped != CONFIG:
        _reject("The EFI forwarder does not select the inspected GRUB configuration")
    return {"type": "grub2", "qualified": True,
            "evidence": "EFI BootCurrent/BootOrder -> matching ESP Ubuntu shim -> literal GRUB forwarder",
            "chain": {**manager, **forwarder, "esp": esp, "partition_uuid": partition_uuid,
                      "files": files, "forwarder": text}}


def _mapped_path(path, root_uuid, mounts, host):
    pure = PurePosixPath(path)
    if not path.startswith("/") or ".." in pure.parts or "$" in path or "(" in path:
        _reject("GRUB image path is not a literal absolute filesystem path")
    matching = {item["target"] for item in mounts if item["uuid"].lower() == root_uuid.lower()}
    if len(matching) != 1:
        _reject("GRUB root UUID has no unique root/boot mount mapping")
    mapped = os.path.normpath(os.path.join(next(iter(matching)), path.lstrip("/")))
    if hasattr(host, "realpath"):
        mapped = host.realpath(mapped)
    if os.path.commonpath(["/boot", mapped]) != "/boot":
        _reject("Only installed images under /boot are supported")
    return mapped


def collect_snapshot(host, target_entry=None, good_entry=None):
    try:
        config = host.read_text(CONFIG)
        grub_tool = host.which("grub-editenv")
        if not grub_tool:
            _reject("grub-editenv is required; systemd-boot is not supported")
        environment = _checked_run(host, [grub_tool, ENVIRONMENT, "list"])
        grub = parse_grub(config, environment)
        # Standard 41_custom is harmless only when its optional payload is absent.
        source_lines = [line.strip() for line in config.splitlines() if line.strip().startswith("source ")]
        for line in source_lines:
            words = _words(line)
            if len(words) != 2 or words[1] not in ("${config_directory}/custom.cfg", "$prefix/custom.cfg", "${prefix}/custom.cfg"):
                _reject("Custom top-level GRUB source is unsupported")
            try:
                custom = host.stat("/boot/grub/custom.cfg")
            except FileNotFoundError:
                continue
            if custom["size"]:
                _reject("A nonempty custom.cfg can change the persistent fallback")
        findmnt = host.which("findmnt")
        if not findmnt:
            _reject("findmnt is required for root/boot path mapping")
        mounts = []
        for target in ("/", "/boot"):
            data = json.loads(_checked_run(host, [findmnt, "--json", "--target", target,
                                                 "--output", "TARGET,SOURCE,FSTYPE,UUID"]))
            for item in _flatten_mounts(data.get("filesystems", [])):
                if item not in mounts:
                    mounts.append(item)
        tools = {name: host.which(name) for name in ("kexec", "systemctl")}
        uname = host.which("uname") or "/usr/bin/uname"
        snapshot = {
            "grub": grub, "current_release": host.read_text("/proc/sys/kernel/osrelease").strip(),
            "boot_id": host.read_text("/proc/sys/kernel/random/boot_id").strip(),
            "machine": _checked_run(host, [uname, "-m"]).strip(),
            "pid1": host.read_text("/proc/1/comm").strip(), "euid": host.euid,
            "normal_loaded": _flag(host, NORMAL_LOADED), "crash_loaded": _flag(host, CRASH_LOADED),
            "tools": tools, "mounts": mounts, "artifacts": {},
            "loader": _loader_evidence(host, mounts),
            "config_identity": {"config": config, "environment": environment, "mounts": mounts},
        }
        for entry_id in dict.fromkeys(item for item in (target_entry, good_entry) if item):
            if entry_id not in grub["entries"]:
                _reject(f"No installed GRUB entry with full ID: {entry_id}")
            entry = grub["entries"][entry_id]
            if entry["unsafe"]:
                _reject(f"Unsupported selected entry {entry_id}: {', '.join(entry['unsafe'])}")
            kernel = _mapped_path(entry["linux"], entry["root_uuid"], mounts, host)
            initrd = _mapped_path(entry["initrd"], entry["root_uuid"], mounts, host)
            kernel_stat, initrd_stat = host.stat(kernel), host.stat(initrd)
            if not kernel_stat["regular"] or not initrd_stat["regular"]:
                _reject("Selected kernel and initrd must be regular files")
            prefix = host.read_bytes(kernel, 131072)
            release = read_bzimage_release(prefix)
            lsinitramfs = host.which("lsinitramfs")
            if not lsinitramfs:
                _reject("lsinitramfs is required to verify installed initrd modules")
            releases = parse_initrd_releases(_checked_run(host, [lsinitramfs, initrd]))
            snapshot["artifacts"][entry_id] = {
                "kernel": kernel, "initrd": initrd, "release": release,
                "initrd_releases": releases, "modules_present": host.is_dir("/lib/modules/" + release),
                "kernel_stat": kernel_stat, "initrd_stat": initrd_stat,
                "cmdline_limit": _cmdline_limit(prefix),
            }
        return snapshot
    except SwitchError:
        raise
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        _reject(f"Cannot establish read-only boot facts: {error}")


def validate_plan(snapshot, target_entry, good_entry, panic_seconds):
    try:
        if snapshot["machine"] != "x86_64" or snapshot["pid1"] != "systemd":
            _reject("Only x86_64 hosts with systemd PID 1 are supported")
        if (snapshot["loader"].get("type") != "grub2" or not snapshot["loader"].get("evidence")
                or snapshot["loader"].get("qualified") is not True):
            _reject("The active GRUB 2 loader must be positively identified")
        if snapshot["normal_loaded"]:
            _reject("A normal kexec image is already loaded; it will not be overwritten")
        if snapshot["grub"]["pending"]:
            _reject("Pending GRUB next/previous entry state prevents a known-good fallback")
        if target_entry == good_entry or snapshot["grub"]["default"] != good_entry:
            _reject("The distinct known-good entry must already be the persistent GRUB default")
        for name in ("kexec", "systemctl"):
            path = snapshot["tools"].get(name)
            if not path or not os.path.isabs(path) or os.path.basename(path) != name:
                _reject(f"Required executable is unavailable: {name}")
        for entry_id in (target_entry, good_entry):
            entry = snapshot["grub"]["entries"][entry_id]
            if entry["unsafe"]:
                _reject(f"Selected entry is unsafe: {entry_id}: {entry['unsafe']}")
            artifact = snapshot["artifacts"][entry_id]
            release = artifact["release"]
            if not release or not _RELEASE.fullmatch(release):
                _reject("Unknown embedded kernel release")
            if (artifact["initrd_releases"] != [release] or not artifact["modules_present"]
                    or os.path.basename(artifact["kernel"]) != "vmlinuz-" + release
                    or os.path.basename(artifact["initrd"]) != "initrd.img-" + release):
                _reject(f"Installed image, initrd and modules do not match release {release}")
            for kind in ("kernel", "initrd"):
                if not artifact[kind + "_stat"]["regular"] or artifact[kind + "_stat"]["size"] <= 0:
                    _reject("Kernel and initrd must be nonempty regular installed files")
                expected = _mapped_path(entry["linux" if kind == "kernel" else "initrd"],
                                        entry["root_uuid"], snapshot["mounts"], object())
                if expected != artifact[kind]:
                    _reject("Artifact path does not match the selected GRUB root/boot mapping")
        target = snapshot["artifacts"][target_entry]
        cmdline = normalise_cmdline(snapshot["grub"]["entries"][target_entry]["args"], panic_seconds)
        if len(cmdline.encode("utf-8")) > target["cmdline_limit"]:
            _reject("Command line exceeds the image's boot-protocol limit; panic would not be reliable")
        plan = {
            "state": "planned", "target_entry": target_entry, "good_entry": good_entry,
            "panic_seconds": panic_seconds, "release": target["release"],
            "kernel": target["kernel"], "initrd": target["initrd"], "cmdline": cmdline,
            "commands": [[snapshot["tools"]["kexec"], "--load", target["kernel"],
                          "--initrd=" + target["initrd"], "--append=" + cmdline],
                         [snapshot["tools"]["systemctl"], "kexec"]],
            "crash_loaded": snapshot["crash_loaded"],
            "identity": {"boot_id": snapshot["boot_id"], "current_release": snapshot["current_release"],
                         "config": snapshot["config_identity"], "artifacts": snapshot["artifacts"],
                         "mounts": snapshot["mounts"], "tools": snapshot["tools"], "loader": snapshot["loader"]},
        }
        return json.loads(json.dumps(plan))
    except SwitchError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        _reject(f"Incomplete or unknown validation facts: {error}")


def execute_switch(plan, *, execute=False, runner=None, recheck=None, read_loaded=None, receipt=None):
    if not execute:
        return plan
    if any(callback is None for callback in (runner, recheck, read_loaded, receipt)):
        _reject("Execution requires all production boundaries", exit_code=2)
    current = recheck()
    if current != plan:
        _reject("Boot facts or installed artifacts changed; generate a new plan")
    commands = plan.get("commands", [])
    if (len(commands) != 2 or len(commands[0]) != 5
            or os.path.basename(commands[0][0]) != "kexec" or commands[0][1] != "--load"
            or commands[0][2:] != [plan["kernel"], "--initrd=" + plan["initrd"], "--append=" + plan["cmdline"]]
            or len(commands[1]) != 2 or os.path.basename(commands[1][0]) != "systemctl"
            or commands[1][1] != "kexec"):
        _reject("Only a validated normal load and orderly systemctl kexec are allowed")

    def event(state, **facts):
        return {"state": state, "time": datetime.now(timezone.utc).isoformat(),
                "target_entry": plan["target_entry"], "good_entry": plan["good_entry"],
                "release": plan["release"], "commands": commands, **facts}

    def save(state, **facts):
        try:
            receipt(event(state, **facts))
        except (OSError, ValueError, SwitchError) as error:
            raise SwitchError("receipt-failed", f"Cannot persist {state} receipt: {error}", 6) from error

    def observed():
        try:
            value = read_loaded()
            return value if isinstance(value, bool) else None
        except Exception:
            return None

    def best_effort(state, **facts):
        try:
            receipt(event(state, **facts))
        except Exception:
            pass

    stage = "prepared"
    try:
        save("prepared", normal_loaded=False)
        stage = "loading"
        try:
            result = runner(commands[0])
        except (OSError, subprocess.SubprocessError) as error:
            value = observed()
            best_effort("load-state-unknown", normal_loaded=value, detail=str(error))
            raise SwitchError("load-state-unknown", "Load command failed or timed out; loaded state may have changed", 6) from error
        loaded = observed()
        if result.returncode:
            state = "load-failed" if loaded is False else "load-state-unknown"
            best_effort(state, normal_loaded=loaded, returncode=result.returncode)
            raise SwitchError(state, f"kexec load failed; normal_loaded={loaded}; no handoff or cleanup attempted",
                              4 if loaded is False else 6)
        if loaded is not True:
            best_effort("load-state-unknown", normal_loaded=loaded)
            raise SwitchError("load-state-unknown", "Load returned success but loaded flag is not confirmed; no handoff", 6)
        stage = "loaded"
        save("loaded", normal_loaded=True)
        stage = "handoff"
        try:
            result = runner(commands[1])
        except (OSError, subprocess.SubprocessError) as error:
            best_effort("handoff-failed", normal_loaded=observed(), detail=str(error))
            raise SwitchError("handoff-failed", "Handoff command failed or timed out; no retry or cleanup attempted", 6) from error
        if result.returncode:
            best_effort("handoff-failed", normal_loaded=observed(), returncode=result.returncode)
            raise SwitchError("handoff-failed", "systemctl rejected handoff; the loaded image may remain", 5)
        save("handoff-requested", normal_loaded=True)
        return event("handoff-requested", normal_loaded=True)
    except (KeyboardInterrupt, InterruptedError) as error:
        best_effort("interrupted", stage=stage, normal_loaded=observed())
        raise SwitchError("interrupted", f"Interrupted during {stage}; inspect loaded state before any further action", 6) from error


def _private_parent(path):
    parent = Path(path).absolute().parent
    for item in (parent, *parent.parents):
        if item.is_symlink():
            _reject("Receipt directories must not be symlinks")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        _reject("Receipt parent must be owned by the caller and have mode 0700")
    return parent


def write_receipt(path, event):
    path = Path(path).absolute()
    parent = _private_parent(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            _reject("Existing receipt must be a private regular file, not a link")
    descriptor, temporary = tempfile.mkstemp(prefix=".kernel-switch-", dir=parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(event, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def _execution_lock():
    descriptor = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
            _reject("Unsafe kernel-switch lock file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _reject("Another kernel-switch invocation holds the execution lock")
        yield
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action")
    subparsers.add_parser("inspect", help="Read boot facts without loading a kernel")
    for action in ("plan", "switch"):
        command = subparsers.add_parser(action)
        command.add_argument("--target-entry", required=True)
        command.add_argument("--good-entry", required=True)
        command.add_argument("--panic-seconds", type=int, default=10)
        if action == "switch":
            command.add_argument("--execute", action="store_true")
            command.add_argument("--receipt")
    options = parser.parse_args(argv)
    options.action = options.action or "inspect"
    try:
        host = Host()
        if options.action == "inspect":
            snapshot = collect_snapshot(host)
            result = {key: snapshot[key] for key in ("current_release", "boot_id", "machine", "pid1",
                                                     "normal_loaded", "crash_loaded", "tools", "mounts")}
            result.update(state="inspected", loader=snapshot["loader"], default=snapshot["grub"]["default"],
                          pending=snapshot["grub"]["pending"], entries=snapshot["grub"]["entries"])
        else:
            execute = options.action == "switch" and options.execute
            if execute and host.euid != 0:
                _reject("--execute requires root")
            if execute and not options.receipt:
                _reject("--execute requires an explicit private --receipt path", exit_code=2)

            def recheck():
                snapshot = collect_snapshot(host, options.target_entry, options.good_entry)
                return validate_plan(snapshot, options.target_entry, options.good_entry, options.panic_seconds)

            plan = recheck()
            if not execute:
                result = plan
            else:
                # No state-changing operation, including locking or receipt creation,
                # occurs on the default inspect/plan paths.
                with _execution_lock():
                    result = execute_switch(plan, execute=True, runner=host.run, recheck=recheck,
                                            read_loaded=lambda: _flag(host, NORMAL_LOADED),
                                            receipt=lambda event: write_receipt(options.receipt, event))
        print(json.dumps(result, sort_keys=True))
        return 0
    except SwitchError as error:
        print(json.dumps({"state": error.state, "error": str(error), "exit_code": error.exit_code}), file=sys.stderr)
        return error.exit_code
    except (OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"state": "unknown", "error": str(error), "exit_code": 6}), file=sys.stderr)
        return 6


if __name__ == "__main__":
    sys.exit(main())

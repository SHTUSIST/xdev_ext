# SPDX-License-Identifier: GPL-2.0
"""Associate one serialized CREATE invocation with its kmsg diagnostic."""

import re
from check_protocol import integer

_LINE = re.compile(
    r"XDEV_EXT_XDOMAIN_ADMIT session=([0-9]+) stage=([0-9]+) requester=([0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]) errno=(-?[0-9]+) reachability=([0-9]+) distance=(-?[0-9]+) backing=0x([0-9a-fA-F]+) refused=0x([0-9a-fA-F]+) mapped=([0-9]+)"
)


def match_admission(records, window, expected):
    def incomplete(reason):
        return {"status": "incomplete", "reason": reason, "matched": None}

    try:
        if (
            not all(
                window[k] is True
                for k in ("exclusive_creator", "lock_held", "complete", "readable")
            )
            or window["kmsg_lost"] is not False
        ):
            return incomplete("unproved exclusive complete kmsg window")
        for k in ("cursor_seq", "begin_ns", "end_ns"):
            integer(window[k])
        if window["end_ns"] < window["begin_ns"]:
            return incomplete("invalid invocation interval")
        candidates = []
        for r in records:
            integer(r["seq"])
            integer(r["monotonic_ns"])
            if (
                r["seq"] <= window["cursor_seq"]
                or not window["begin_ns"] <= r["monotonic_ns"] <= window["end_ns"]
            ):
                continue
            if "XDEV_EXT_XDOMAIN_ADMIT" not in r["message"]:
                continue
            m = _LINE.fullmatch(r["message"])
            if not m:
                return incomplete("malformed admission scalar")
            v = m.groups()
            d = dict(
                zip(
                    (
                        "session",
                        "stage",
                        "requester",
                        "errno",
                        "reachability",
                        "distance",
                        "backing",
                        "refused",
                        "mapped",
                    ),
                    (
                        int(v[0]),
                        int(v[1]),
                        v[2],
                        int(v[3]),
                        int(v[4]),
                        int(v[5]),
                        int(v[6], 16),
                        int(v[7], 16),
                        int(v[8]),
                    ),
                )
            )
            integer(d["session"])
            integer(d["stage"], maximum=(1 << 32) - 1)
            integer(d["reachability"], maximum=(1 << 32) - 1)
            for k in ("backing", "refused", "mapped"):
                integer(d[k], maximum=(1 << 32) - 1)
            for k in ("errno", "distance"):
                integer(d[k], minimum=-(1 << 31), maximum=(1 << 31) - 1)
            if any(d[k] != expected[k] for k in ("requester", "stage", "errno")):
                return incomplete("unrelated concurrent admission")
            candidates.append(d)
        if len(candidates) != 1:
            return incomplete("requires exactly one admission diagnostic")
        return {"status": "matched", "reason": "", "matched": candidates[0]}
    except (KeyError, ValueError, TypeError):
        return incomplete("invalid admission evidence")

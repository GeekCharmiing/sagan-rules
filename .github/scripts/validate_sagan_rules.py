#!/usr/bin/env python3
"""
Sagan Legacy Rule Validator
Mirrors failure conditions extracted from quadrantsec/sagan src/rules.c
Each check corresponds to a Sagan_Log(ERROR, ...) abort in Load_Rules().
"""

import re
import sys
import os

# ── Constants pulled directly from src/rules.h VALID_RULE_OPTIONS ────────────
VALID_RULE_OPTIONS = {
    "parse_port", "parse_proto", "parse_proto_program",
    "flexbits_upause", "xbits_upause", "flexbits_pause", "xbits_pause",
    "default_proto", "default_src_port", "default_dst_port",
    "parse_src_ip", "parse_dst_ip", "parse_hash",
    "xbits", "flexbits", "dynamic_load", "country_code",
    "meta_content", "meta_nocase",
    "rev", "classtype", "program", "event_type", "reference",
    "sid", "syslog_tag", "syslog_facility", "syslog_level", "syslog_priority",
    "pri", "priority", "email", "normalize",
    "msg", "content", "nocase", "offset", "meta_offset",
    "depth", "meta_depth", "distance", "meta_distance", "within", "meta_within",
    "pcre", "alert_time", "threshold", "after",
    "blacklist", "bro-intel", "zeek-intel", "external", "bluedot",
    "metadata", "event_id",
    "json_content", "json_nocase", "json_pcre",
    "json_meta_content", "json_meta_nocase",
    "json_strstr", "json_meta_strstr",
    "append_program", "json_contains", "json_map",
    "json_decode_base64", "json_meta_contains",
    "json_decode_base64_pcre", "json_decode_base64_meta",
    "offload",
}

VALID_RULE_TYPES   = {"alert", "drop", "pass"}
VALID_PROTOCOLS    = {"any", "tcp", "udp", "icmp", "syslog"}
VALID_PARSE_HASH   = {"md5", "sha1", "sha256"}
VALID_XBIT_ACTIONS = {"set", "unset", "isset", "isnotset", "toggle", "noalert", "noeve"}
VALID_XBIT_TRACK   = {"ip_src", "ip_dst", "ip_pair"}
VALID_FLEXBIT_ACTIONS = {
    "noalert", "set", "unset", "isset", "isnotset",
    "set_srcport", "set_dstport", "set_ports", "count", "noeve",
}
VALID_THRESHOLD_TYPES  = {"limit", "suppress"}
VALID_THRESHOLD_TRACKS = {"by_src", "by_dst", "by_username", "by_string", "by_srcport", "by_dstport"}

REQUIRED_KEYWORDS = {"sid", "rev", "msg"}

# ── Helpers ───────────────────────────────────────────────────────────────────

def extract_body(rule: str):
    """Return the text between the outermost ( ) of the rule."""
    start = rule.find("(")
    end   = rule.rfind(")")
    if start == -1 or end == -1:
        return None
    return rule[start + 1 : end]


def tokenize_options(body: str):
    """
    Split rule body on ';', then split each token on the first ':'.
    Returns list of (keyword, rest_or_None) tuples.
    Mirrors strtok_r(rulestring, ";") + strtok_r(tokenrule, ":") in rules.c.
    """
    tokens = []
    for raw in body.split(";"):
        raw = raw.strip()
        if not raw:
            continue
        if ":" in raw:
            kw, rest = raw.split(":", 1)
        else:
            kw, rest = raw, None
        tokens.append((kw.strip(), rest.strip() if rest else None))
    return tokens


def pcre_has_closing_slash(pcre_val: str) -> bool:
    """
    Check that a pcre value has a closing / (not escaped).
    Mirrors the pcreflag logic in rules.c.
    """
    found_open = False
    for i in range(1, len(pcre_val)):
        if pcre_val[i] == "/" and pcre_val[i - 1] != "\\":
            found_open = True
    return found_open


def try_compile_pcre(pattern: str) -> str | None:
    """Return error string if pattern fails Python re compilation, else None."""
    try:
        re.compile(pattern)
        return None
    except re.error as e:
        return str(e)


def between_quotes(s: str) -> str | None:
    """Extract string between first pair of double-quotes."""
    m = re.search(r'"([^"]*)"', s)
    return m.group(1) if m else None


# ── Per-rule validation ───────────────────────────────────────────────────────

def validate_rule(rule: str, lineno: int, filename: str) -> tuple[list[str], list[str]]:
    errors = []
    warnings = []

    def err(msg):
        errors.append(f"{filename}:{lineno}: {msg}")

    def warn(msg):
        warnings.append(f"{filename}:{lineno}: {msg}")

    # ── 1. Structural sanity (rules.c basic checks) ──────────────────────────
    # Must contain ; : ( )
    for ch, name in [(";", "semicolon"), (":", "colon"),
                     ("(", "opening paren"), (")", "closing paren")]:
        if ch not in rule:
            err(f"Rule appears to be incorrect – missing '{name}'")
            return errors, warnings   # Can't continue without structure

    # ── 2. Required keywords ─────────────────────────────────────────────────
    for kw in REQUIRED_KEYWORDS:
        if not re.search(rf'\b{kw}\s*:', rule):
            err(f"Missing required option '{kw}'")

    # ── 3. Rule type (alert / drop / pass) ───────────────────────────────────
    first_word = rule.split()[0].lower() if rule.split() else ""
    if first_word not in VALID_RULE_TYPES:
        err(f"Rule type must be 'alert', 'drop' or 'pass'; got '{first_word}'")
        return errors, warnings

    # ── 4. Protocol field ────────────────────────────────────────────────────
    parts = rule.split()
    if len(parts) < 2:
        err("Rule is too short to contain a protocol")
    else:
        proto = parts[1].lower()
        if proto not in VALID_PROTOCOLS:
            err(f"Protocol must be one of {sorted(VALID_PROTOCOLS)}; got '{proto}'")

    # ── 5. Parse rule body ───────────────────────────────────────────────────
    body = extract_body(rule)
    if body is None:
        err("Cannot extract rule body between ( )")
        return errors, warnings

    tokens = tokenize_options(body)

    seen_keywords        = set()
    content_count        = 0
    meta_content_count   = 0
    json_content_count   = 0
    json_meta_content_count = 0
    json_pcre_count      = 0

    for kw, rest in tokens:
        seen_keywords.add(kw)

        # ── 5a. Valid rule options (VALID_RULE_OPTIONS check) ─────────────
        if kw and kw not in VALID_RULE_OPTIONS:
            err(f"Unknown rule option '{kw}'")
            continue

        # ── 5b. Keyword-specific checks ───────────────────────────────────

        # sid
        if kw == "sid":
            if not rest or not rest.strip().isdigit():
                err("'sid' value is missing or non-numeric")

        # rev
        elif kw == "rev":
            if not rest or not rest.strip().isdigit():
                err("'rev' value is missing or non-numeric")

        # msg
        elif kw == "msg":
            # rest may be "msg"; value is after the colon in the original split
            val = between_quotes(rest) if rest else None
            if val is None or val == "":
                err("'msg' value is empty or not quoted")

        # content
        elif kw == "content":
            content_count += 1
            if not rest:
                err("'content' appears to be incomplete (no value)")
            else:
                val = between_quotes(rest)
                if val is None or val == "":
                    err("'content' value is empty or not quoted")

        # nocase / offset / depth / distance / within
        elif kw in ("nocase", "offset", "depth", "distance", "within"):
            if content_count < 1:
                err(f"'{kw}' has no preceding 'content' to apply to")

        # meta_content
        elif kw == "meta_content":
            meta_content_count += 1
            if not rest:
                err("'meta_content' appears to be incomplete")
            elif "%sagan%" not in rest:
                err("'meta_content' is missing the required '%sagan%' helper")

        # meta_nocase / meta_offset / meta_depth / meta_distance / meta_within
        elif kw in ("meta_nocase", "meta_offset", "meta_depth", "meta_distance", "meta_within"):
            if meta_content_count < 1:
                err(f"'{kw}' has no preceding 'meta_content' to apply to")

        # pcre
        elif kw == "pcre":
            if not rest:
                err("'pcre' appears to be incomplete (no value)")
            else:
                val = between_quotes(rest)
                if val is None or val == "":
                    err("'pcre' value is empty or not quoted")
                else:
                    if not pcre_has_closing_slash(val):
                        warn(f"'pcre' is missing the closing '/' in: {val}")
                    else:
                        # Extract the actual pattern between slashes
                        m = re.match(r'^/(.*)/[imsxAEG]*$', val)
                        if m:
                            pattern = m.group(1)
                            compile_err = try_compile_pcre(pattern)
                            if compile_err:
                                warn(f"'pcre' pattern may have issues: {compile_err} — pattern: {val}")

        # json_content
        elif kw == "json_content":
            json_content_count += 1
            if not rest:
                err("'json_content' appears to be incomplete")
            else:
                # Key must be quoted and start with '.'
                first_arg = rest.split(",")[0].strip()
                key = between_quotes(first_arg)
                if key is None:
                    err("'json_content' key is not quoted")
                elif not key.startswith("."):
                    err(f"'json_content' key must start with '.'; got '{key}'")

        # json_nocase / json_contains
        elif kw in ("json_nocase", "json_contains"):
            if json_content_count < 1:
                err(f"'{kw}' has no preceding 'json_content' to apply to")

        # json_pcre
        elif kw == "json_pcre":
            json_pcre_count += 1
            if not rest:
                err("'json_pcre' appears to be incomplete")
            else:
                first_arg = rest.split(",")[0].strip()
                key = between_quotes(first_arg)
                if key is None:
                    err("'json_pcre' key is not quoted")
                elif not key.startswith("."):
                    err(f"'json_pcre' key must start with '.'; got '{key}'")

        # json_meta_content
        elif kw == "json_meta_content":
            json_meta_content_count += 1
            if not rest:
                err("'json_meta_content' appears to be incomplete")
            else:
                first_arg = rest.split(",")[0].strip()
                key = between_quotes(first_arg)
                if key is None:
                    err("'json_meta_content' key is not quoted")
                elif not key.startswith("."):
                    err(f"'json_meta_content' key must start with '.'; got '{key}'")

        # json_meta_nocase / json_meta_contains
        elif kw in ("json_meta_nocase", "json_meta_contains"):
            if json_meta_content_count < 1:
                err(f"'{kw}' has no preceding 'json_meta_content' to apply to")

        # reference
        elif kw == "reference":
            if not rest or "," not in rest:
                err("'reference' must be comma-delimited (e.g. 'url,example.com')")

        # classtype
        elif kw == "classtype":
            if not rest or not rest.strip():
                err("'classtype' appears to be incomplete")

        # parse_hash
        elif kw == "parse_hash":
            if not rest or rest.strip() not in VALID_PARSE_HASH:
                err(f"'parse_hash' must be one of {sorted(VALID_PARSE_HASH)}; got '{rest}'")

        # parse_src_ip / parse_dst_ip
        elif kw in ("parse_src_ip", "parse_dst_ip"):
            if not rest or not rest.strip().isdigit():
                err(f"'{kw}' requires a numeric position argument")

        # xbits
        elif kw == "xbits":
            if not rest:
                err("'xbits' appears to be incomplete")
            else:
                action = rest.split(",")[0].strip()
                if action not in VALID_XBIT_ACTIONS:
                    err(f"'xbits' action must be one of {sorted(VALID_XBIT_ACTIONS)}; got '{action}'")
                elif action in ("set", "unset", "isset", "isnotset", "toggle"):
                    parts_xbit = [p.strip() for p in rest.split(",")]
                    if len(parts_xbit) < 3:
                        err(f"'xbits {action}' is incomplete — requires action,name,track by ...")
                    else:
                        track_val = parts_xbit[2]
                        if not track_val.startswith("track"):
                            err(f"'xbits' expected 'track' keyword; got '{track_val}'")
                        else:
                            direction = track_val.replace("track", "").strip()
                            if direction not in VALID_XBIT_TRACK:
                                err(f"'xbits' track direction must be one of {sorted(VALID_XBIT_TRACK)}; got '{direction}'")
                    if action == "set" and len(parts_xbit) < 4:
                        err("'xbits set' requires an 'expire<N>' time argument")

        # flexbits
        elif kw == "flexbits":
            if not rest:
                err("'flexbits' appears to be incomplete")
            else:
                action = rest.split(",")[0].strip()
                if action not in VALID_FLEXBIT_ACTIONS:
                    err(f"'flexbits' action must be one of {sorted(VALID_FLEXBIT_ACTIONS)}; got '{action}'")
                elif action in ("set", "set_srcport", "set_dstport", "set_ports"):
                    parts_fb = [p.strip() for p in rest.split(",")]
                    if len(parts_fb) < 3:
                        err(f"'flexbits {action}' is incomplete — requires action,name,timeout")
                    else:
                        timeout = parts_fb[2].strip()
                        if not timeout.isdigit() or int(timeout) == 0:
                            err(f"'flexbits {action}' requires a valid non-zero expire time; got '{timeout}'")

        # threshold
        elif kw == "threshold":
            if not rest:
                err("'threshold' appears to be incomplete")
            else:
                has_type    = "type" in rest
                has_track   = "track" in rest
                has_count   = "count" in rest
                has_seconds = "seconds" in rest
                if not (has_type and has_track and has_count and has_seconds):
                    err("'threshold' is incomplete — must specify type, track, count and seconds")
                if has_type:
                    if "limit" not in rest and "suppress" not in rest:
                        err("'threshold' type must be 'limit' or 'suppress'")
                if has_count:
                    m = re.search(r'count\s+(\d+)', rest)
                    if m and int(m.group(1)) == 0:
                        err("'threshold' count cannot be 0")
                if has_seconds:
                    m = re.search(r'seconds\s+(\d+)', rest)
                    if m and int(m.group(1)) == 0:
                        err("'threshold' seconds cannot be 0")

        # after
        elif kw == "after":
            if not rest:
                err("'after' appears to be incomplete")
            else:
                has_track   = "track" in rest
                has_count   = "count" in rest
                has_seconds = "seconds" in rest
                if not (has_track and has_count and has_seconds):
                    err("'after' is incomplete — must specify track, count and seconds")
                if has_count:
                    m = re.search(r'count\s+(\d+)', rest)
                    if m and int(m.group(1)) == 0:
                        err("'after' count cannot be 0")
                if has_seconds:
                    m = re.search(r'seconds\s+(\d+)', rest)
                    if m and int(m.group(1)) == 0:
                        err("'after' seconds cannot be 0")

        # default_proto
        elif kw == "default_proto":
            if not rest or rest.strip() not in ("icmp", "tcp", "udp", "1", "6", "17"):
                err(f"'default_proto' must be icmp/tcp/udp or 1/6/17; got '{rest}'")

        # default_src_port
        elif kw == "default_src_port":
            if not rest or not rest.strip().isdigit():
                err(f"'{kw}' requires a numeric port value")

        # flexbits_upause / xbits_upause / flexbits_pause / xbits_pause
        elif kw in ("flexbits_upause", "xbits_upause", "flexbits_pause", "xbits_pause"):
            if not rest or not rest.strip().isdigit():
                err(f"'{kw}' requires a numeric time argument")

        # syslog_tag length check (MAX_SYSLOG_TAG reasonable upper bound)
        elif kw == "syslog_tag":
            if rest and len(rest.strip()) > 256:
                err("'syslog_tag' exceeds maximum allowed length")

        # alert_time
        elif kw == "alert_time":
            if not rest:
                err("'alert_time' appears to be incomplete")
            else:
                if "hours" in rest:
                    m = re.search(r'hours\s+(\d{4})-(\d{4})', rest)
                    if not m:
                        warn("'alert_time' hours format should be HHMM-HHMM")
                    else:
                        start_h = int(m.group(1)[:2])
                        start_m = int(m.group(1)[2:])
                        end_h   = int(m.group(2)[:2])
                        end_m   = int(m.group(2)[2:])
                        if start_h > 23:
                            warn("'alert_time' starting hour cannot exceed 23")
                        if start_m > 59:
                            warn("'alert_time' starting minute cannot exceed 59")
                        if end_h > 23:
                            warn("'alert_time' ending hour cannot exceed 23")
                        if end_m > 59:
                            warn("'alert_time' ending minute cannot exceed 59")
                if "days" in rest:
                    m = re.search(r'days\s+([0-6]+)', rest)
                    if not m:
                        warn("'alert_time' days should be digits 0-6")
                    else:
                        for ch in m.group(1):
                            if ch not in "0123456":
                                warn(f"'alert_time' day '{ch}' is invalid (0=Sun … 6=Sat)")

    return errors, warnings


# ── File-level validation ─────────────────────────────────────────────────────

def validate_file(filepath: str) -> tuple[list[str], list[str]]:
    errors = []
    warnings = []
    sid_seen: set[str] = set()

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        return [f"{filepath}: Cannot open file — {e}"], []

    for lineno, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")

        # Skip blank lines and comments (rules.c: '#', '\n'=10, ';', ' ')
        if not line or line[0] in ("#", ";") or line[0] == " ":
            continue

        rule_errors, rule_warnings = validate_rule(line, lineno, filepath)
        errors.extend(rule_errors)
        warnings.extend(rule_warnings)

        # Duplicate SID check (not in rules.c but causes silent conflicts)
        m = re.search(r'\bsid\s*:\s*(\d+)', line)
        if m:
            sid = m.group(1)
            if sid in sid_seen:
                errors.append(f"{filepath}:{lineno}: Duplicate sid:{sid}")
            sid_seen.add(sid)

    return errors, warnings


# ── Entry point ───────────────────────────────────────────────────────────────

def main(argv: list[str]) -> int:
    if not argv:
        print("Usage: validate_sagan_rules.py <file.rules> [...]", file=sys.stderr)
        return 1

    all_errors: list[str] = []
    all_warnings: list[str] = []

    for path in argv:
        if not os.path.isfile(path):
            all_errors.append(f"{path}: File not found")
            continue
        file_errors, file_warnings = validate_file(path)
        all_errors.extend(file_errors)
        all_warnings.extend(file_warnings)

    if all_warnings:
        print("\n[WARN] Sagan rule validation found advisories:\n")
        for w in all_warnings:
            print(f"  ⚠  {w}")
        print()

    if all_errors:
        print("\n[FAIL] Sagan rule validation found errors:\n")
        for e in all_errors:
            print(f"  ✗  {e}")
        print(f"\n{len(all_errors)} error(s), {len(all_warnings)} warning(s) found across {len(argv)} file(s).")
        return 1

    print(f"[PASS] All rules validated successfully ({len(argv)} file(s), {len(all_warnings)} warning(s)).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

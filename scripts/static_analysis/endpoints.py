import base64
import binascii
import html
import ipaddress
import re
from urllib.parse import unquote, urlsplit, urlunsplit

from .common import stable_id

URL_PATTERN = re.compile(r"(?i)\b(?:https?|wss?|mqtts?|tcp|tls|udp)://[^\s<>\"'`\\]+")
RELATIVE_PATTERN = re.compile(
    r"(?<![:\w/])//(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?::[0-9]{1,5})?(?:/[^\s<>\"'`\\]*)?"
)
DOMAIN_PATTERN = re.compile(
    r"(?<![\w@./-])(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)\.)+(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]+)(?![\w.-])"
)
TELEMETRY_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(report|upload|collect|track|tracking|analytics|telemetry|beacon|metrics|events?|logs?|crash)(?:$|[/_.-])"
)
COMMAND_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(command|cmd|dispatch|execute|script)(?:$|[/_.-])"
)
ESCAPE_PATTERN = re.compile(r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|(/))")
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/_-]{16,8192}={0,2}\Z")
SOURCE_SUFFIXES = {
    "java",
    "kt",
    "class",
    "dex",
    "xml",
    "json",
    "html",
    "js",
    "png",
    "jpg",
    "so",
    "zip",
    "apk",
    "txt",
    "properties",
    "proto",
}
MATCH_BUDGET_INTERVAL = 256
NETWORK_SCHEMES = {"http", "https", "ws", "wss", "mqtt", "mqtts", "tcp", "tls", "udp"}


def host_normalize(value):
    value = value.rstrip(".").lower()
    if not value or any(char.isspace() for char in value):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(value) > 253:
        return None
    if all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split(".")
    ):
        return value
    return None


def host_matches(host, suffix):
    return host == suffix or host.endswith("." + suffix)


def trim_url(value):
    value = value.rstrip(".,;!?")
    for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
        while value.endswith(closing) and value.count(closing) > value.count(opening):
            value = value[:-1]
    return value


def normalize_endpoint(value, kind="url"):
    raw = trim_url(value)
    if any(character in raw for character in ("{", "}", "${", "%s", "%d")):
        return {
            "kind": "unresolved_template",
            "value": raw,
            "host": None,
            "tags": [],
            "reason": "Endpoint contains an unresolved placeholder",
        }
    if kind == "domain":
        host = host_normalize(raw)
        if not host or "." not in host or host.rsplit(".", 1)[-1] in SOURCE_SUFFIXES:
            return None
        return {
            "kind": kind,
            "value": host,
            "host": host,
            "tags": [],
            "reason": "Bare domain candidate; network use is unproven",
        }
    try:
        parsed = urlsplit("https:" + raw if kind == "scheme_relative" else raw)
        host = host_normalize(parsed.hostname or "")
        port = parsed.port
        if not host or parsed.scheme.lower() not in NETWORK_SCHEMES or port == 0:
            return None
        authority = f"[{host}]" if ":" in host else host
        if port is not None and (parsed.scheme.lower(), port) not in {
            ("http", 80),
            ("https", 443),
            ("ws", 80),
            ("wss", 443),
        }:
            authority += f":{port}"
        normalized = urlunsplit(
            (
                "" if kind == "scheme_relative" else parsed.scheme.lower(),
                authority,
                parsed.path,
                parsed.query,
                "",
            )
        )
        tags = []
        path = unquote(parsed.path)
        if TELEMETRY_PATH.search(path):
            tags.append("telemetry_path_candidate")
        if COMMAND_PATH.search(path):
            tags.append("command_path_candidate")
        return {
            "kind": kind,
            "value": normalized,
            "host": host,
            "tags": tags,
            "has_userinfo": parsed.username is not None,
        }
    except (ValueError, UnicodeError):
        return None


def decoded_variants(value, max_length=16384):
    yield value, []
    if len(value) > max_length:
        return
    queue = [(value, [])]
    seen = {value}
    while queue:
        current, chain = queue.pop(0)
        if len(chain) >= 2:
            continue
        variants = []
        escaped = ESCAPE_PATTERN.sub(
            lambda match: (
                chr(int(match[1] or match[2], 16)) if match[1] or match[2] else "/"
            ),
            current,
        )
        variants.append((escaped, "escaped_literal"))
        variants.append((html.unescape(current), "html_entities"))
        if re.search(r"(?i)(?:https?|wss?|mqtts?)%3a|%2f%2f", current):
            variants.append((unquote(current), "percent_encoding"))
        if BASE64_PATTERN.fullmatch(current):
            try:
                decoded = base64.b64decode(
                    current + "=" * (-len(current) % 4), altchars=b"-_", validate=True
                ).decode("utf-8")
                if URL_PATTERN.search(decoded) or RELATIVE_PATTERN.search(decoded):
                    variants.append((decoded, "base64"))
            except (ValueError, UnicodeError, binascii.Error):
                pass
        for variant, transform in variants:
            if variant in seen or len(variant) > max_length:
                continue
            seen.add(variant)
            updated = chain + [transform]
            yield variant, updated
            queue.append((variant, updated))


class EndpointCollector:
    def __init__(self, limits, budget=None):
        self.limits = limits
        self.budget = budget
        self.items = {}
        self.truncated = False
        self.evidence_truncated = False

    def add_text(self, value, source, references=None):
        if not any(
            marker in value for marker in (".", ":", "\\", "%", "&")
        ) and not BASE64_PATTERN.fullmatch(value):
            return
        for decoded, transforms in decoded_variants(value):
            occupied = []
            for kind, pattern in (
                ("url", URL_PATTERN),
                ("scheme_relative", RELATIVE_PATTERN),
                ("domain", DOMAIN_PATTERN),
            ):
                if kind == "domain":
                    occupied.sort()
                    occupied_index = 0
                    occupied_end = 0
                for index, match in enumerate(pattern.finditer(decoded)):
                    if self.budget is not None and index % MATCH_BUDGET_INTERVAL == 0:
                        self.budget.check()
                    if kind == "domain":
                        while (
                            occupied_index < len(occupied)
                            and occupied[occupied_index][0] <= match.start()
                        ):
                            occupied_end = max(
                                occupied_end, occupied[occupied_index][1]
                            )
                            occupied_index += 1
                        if match.start() < occupied_end:
                            continue
                    endpoint = normalize_endpoint(match.group(), kind)
                    if endpoint is None:
                        continue
                    if kind != "domain":
                        occupied.append(match.span())
                    key = (endpoint["kind"], endpoint["value"])
                    if key not in self.items:
                        if len(self.items) >= self.limits.max_results:
                            self.truncated = True
                            continue
                        self.items[key] = {
                            **endpoint,
                            "id": stable_id("endpoint", *key),
                            "evidence_level": "E1",
                            "evidence": [],
                        }
                    record = self.items[key]
                    evidence = {
                        **source,
                        "character_offset": match.start(),
                        "transforms": transforms,
                        "excerpt": match.group()[:2048],
                    }
                    evidence["id"] = stable_id(
                        "evidence", source, match.start(), transforms, match.group()
                    )
                    if len(record["evidence"]) < self.limits.max_evidence:
                        if evidence["id"] not in {
                            item["id"] for item in record["evidence"]
                        }:
                            record["evidence"].append(evidence)
                    else:
                        self.evidence_truncated = True
                    if references:
                        record["evidence_level"] = "E2"
                        for reference in references:
                            linked = {
                                **evidence,
                                **reference,
                                "kind": "dex_string_reference",
                            }
                            linked["id"] = stable_id(
                                "reference", evidence["id"], reference
                            )
                            if len(record["evidence"]) < self.limits.max_evidence:
                                if linked["id"] not in {
                                    item["id"] for item in record["evidence"]
                                }:
                                    record["evidence"].append(linked)
                            else:
                                self.evidence_truncated = True

    def results(self):
        return sorted(
            self.items.values(), key=lambda item: (item["kind"], item["value"])
        )


def redact_text(value):
    def replace(match):
        candidate = match.group()
        suffix = ""
        if "?" in candidate:
            candidate = candidate.split("?", 1)[0]
            suffix = "?<redacted>"
        if "#" in candidate:
            candidate = candidate.split("#", 1)[0]
            suffix += "#<redacted>"
        candidate = re.sub(r"(://)[^/@\s]+@", r"\1<redacted>@", candidate)
        return candidate + suffix

    return URL_PATTERN.sub(replace, value)


def sanitized(value):
    if isinstance(value, dict):
        return {key: sanitized(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitized(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value

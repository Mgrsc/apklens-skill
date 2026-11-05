import base64
import binascii
import html
import ipaddress
import re
from collections import Counter
from urllib.parse import unquote, urlsplit, urlunsplit

from .common import stable_id

URL_PATTERN = re.compile(r"(?i)\b(?:https?|wss?|mqtts?|tcp|tls|udp)://[^\s<>\"'`\\]+")
RELATIVE_PATTERN = re.compile(
    r"(?<![:\w/])//(?:\[[0-9A-Fa-f:.%A-Za-z_-]+\]|(?:[^\W_][\w-]*\.)+[^\W_][\w-]*)(?::[0-9]{1,5})?(?:/[^\s<>\"'`\\]*)?"
)
DOMAIN_PATTERN = re.compile(
    r"(?<![\w@./-])(?:[^\W_](?:[^\W_]|-){0,62}\.)+(?:[^\W\d_]{1,63}|xn--[A-Za-z0-9-]+)(?![\w.-])"
)
IPV4_PATTERN = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
IPV6_PATTERN = re.compile(
    r"(?<![\w:])[0-9A-Fa-f]*:[0-9A-Fa-f:]+(?:%[A-Za-z0-9_.-]+)?(?![\w:])"
)
HOST_CONTEXT_PATTERN = re.compile(
    r"(?i)(?:^|[^\w])(?:host(?:name)?|server|endpoint|base[_-]?url|domain|dns|proxy|url|uri|origin|address)[\"']?\s*[:=]\s*[\"']?\s*$"
)
HOST_ATTRIBUTES = {
    "host",
    "hostname",
    "server",
    "endpoint",
    "domain",
    "url",
    "uri",
    "address",
}
LOW_CONFIDENCE_SAMPLE_LIMIT = 32
LOW_CONFIDENCE_EXCERPT_CHARACTERS = 256
SOURCE_KINDS = {
    "manifest",
    "xml",
    "binary_xml",
    "resources",
    "dex_string",
    "dex_raw_fallback",
    "native_strings",
    "asset_strings",
    "decompiled_source",
}
TELEMETRY_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(report|upload|collect|track|tracking|analytics|telemetry|beacon|metrics|events?|logs?|crash)(?:$|[/_.-])"
)
COMMAND_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(command|cmd|dispatch|execute|script)(?:$|[/_.-])"
)
ESCAPE_PATTERN = re.compile(r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|(/))")
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/_-]{16,8192}={0,2}\Z")
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
        if not host or "." not in host:
            return None
        return {
            "kind": kind,
            "value": host,
            "host": host,
            "tags": [],
            "reason": "Bare domain candidate; network use is unproven",
        }
    if kind == "ip":
        try:
            host = str(ipaddress.ip_address(raw))
        except ValueError:
            return None
        return {
            "kind": "ip",
            "value": host,
            "host": host,
            "tags": [],
            "reason": "IP literal candidate; network use is unproven",
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
        self.observed = Counter()
        self.by_source = {}
        self.dropped = Counter()
        self.contextual = {}
        self.samples = []
        self.evicted_contextual = 0

    def _source_kind(self, source):
        kind = source.get("kind", "unknown")
        return kind if kind in SOURCE_KINDS else "other"

    def _observe(self, classification, source):
        self.observed[classification] += 1
        self.by_source.setdefault(self._source_kind(source), Counter())[
            classification
        ] += 1

    def _evidence(self, source, match, transforms, excerpt_limit=2048):
        raw = match.group()
        return {
            **source,
            "character_offset": match.start(),
            "transforms": transforms,
            "excerpt": raw[:excerpt_limit],
            "id": stable_id("evidence", source, match.start(), transforms, raw),
        }

    def _low_confidence(self, source, match, transforms):
        self._observe("low_confidence", source)
        if (
            len(self.samples)
            >= min(LOW_CONFIDENCE_SAMPLE_LIMIT, self.limits.max_results)
            or len(self.samples) + len(self.items) >= self.limits.max_results
        ):
            return
        self.samples.append(
            {
                "value": match.group()[:LOW_CONFIDENCE_EXCERPT_CHARACTERS],
                "classification": "low_confidence",
                "reason": "Dotted token without explicit network context; intent is unknown",
                "evidence": self._evidence(
                    source, match, transforms, LOW_CONFIDENCE_EXCERPT_CHARACTERS
                ),
            }
        )

    def _admit(self, endpoint, classification):
        key = (endpoint["kind"], endpoint["value"])
        if key in self.items:
            return self.items[key]
        if len(self.items) + len(self.samples) >= self.limits.max_results:
            if self.samples:
                self.samples.pop()
            elif classification != "contextual_host" and self.contextual:
                removed, _ = self.contextual.popitem()
                del self.items[removed]
                self.truncated = True
                self.evicted_contextual += 1
            else:
                self.truncated = True
                self.dropped[classification] += 1
                return None
        record = {
            **endpoint,
            "id": stable_id("endpoint", *key),
            "candidate_class": classification,
            "evidence_level": "E1",
            "evidence": [],
        }
        self.items[key] = record
        if classification == "contextual_host":
            self.contextual[key] = None
        return record

    def add_text(self, value, source, references=None, network_context=False):
        if not any(
            marker in value for marker in (".", ":", "\\", "%", "&")
        ) and not BASE64_PATTERN.fullmatch(value):
            return
        for decoded, transforms in decoded_variants(value):
            occupied = []
            for kind, pattern in (
                ("url", URL_PATTERN),
                ("scheme_relative", RELATIVE_PATTERN),
                ("ip", IPV4_PATTERN),
                ("ip", IPV6_PATTERN),
                ("domain", DOMAIN_PATTERN),
            ):
                occupied.sort()
                occupied_index = 0
                occupied_end = 0
                spans = []
                for index, match in enumerate(pattern.finditer(decoded)):
                    if self.budget is not None and index % MATCH_BUDGET_INTERVAL == 0:
                        self.budget.check()
                    while (
                        occupied_index < len(occupied)
                        and occupied[occupied_index][0] <= match.start()
                    ):
                        occupied_end = max(occupied_end, occupied[occupied_index][1])
                        occupied_index += 1
                    if match.start() < occupied_end:
                        continue
                    if kind == "domain":
                        attribute = (
                            source.get("attribute", "").rsplit("}", 1)[-1].lower()
                        )
                        if (
                            not network_context
                            and attribute not in HOST_ATTRIBUTES
                            and not HOST_CONTEXT_PATTERN.search(
                                decoded[max(0, match.start() - 96) : match.start()]
                            )
                        ):
                            self._low_confidence(source, match, transforms)
                            continue
                        classification = "contextual_host"
                    else:
                        classification = (
                            "ip_literal" if kind == "ip" else "explicit_url"
                        )
                    if kind in {"url", "scheme_relative"}:
                        spans.append(match.span())
                    endpoint = normalize_endpoint(match.group(), kind)
                    if endpoint is None:
                        continue
                    if classification == "contextual_host":
                        endpoint["reason"] = (
                            "Host with explicit network context; network use is unproven"
                        )
                    if kind == "ip":
                        spans.append(match.span())
                    self._observe(classification, source)
                    record = self._admit(endpoint, classification)
                    if record is None:
                        continue
                    evidence = self._evidence(source, match, transforms)
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
                occupied.extend(spans)

    @property
    def partial(self):
        return (
            self.truncated
            or self.evidence_truncated
            or self.observed["low_confidence"] > len(self.samples)
        )

    def candidate_summary(self):
        return {
            "policy_version": 1,
            "unit": "match_occurrence",
            "observed_occurrences": dict(self.observed),
            "by_source": {
                key: dict(value) for key, value in sorted(self.by_source.items())
            },
            "retained_records": dict(
                Counter(value["candidate_class"] for value in self.items.values())
            ),
            "dropped_network_occurrences": dict(self.dropped),
            "evicted_contextual_records": self.evicted_contextual,
            "low_confidence_sample_count": len(self.samples),
            "low_confidence_samples_truncated": self.observed["low_confidence"]
            > len(self.samples),
            "low_confidence_samples": self.samples,
            "meaning": "Endpoints contain explicit locators or contextual hosts; bare dotted tokens remain unknown and are summarized with bounded samples, not reported as absent risks",
        }

    def coverage_reason(self):
        reasons = []
        if self.truncated or self.evidence_truncated:
            reasons.append("Network candidate or evidence count exceeds the budget")
        if self.observed["low_confidence"] > len(self.samples):
            reasons.append(
                "Low-confidence dotted tokens exceed bounded provenance samples; network intent remains unknown"
            )
        return "; ".join(reasons) or None

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

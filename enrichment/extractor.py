"""Bounded, deterministic IOC normalization and extraction."""
from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

CONFIDENCE = {"raw": 0.4, "context": 0.7, "structured": 0.95}
MAX_TEXT = 262144
FILE_TLDS = {"pdf", "sys", "exe", "dll", "bat", "cmd", "ps1", "sh", "log", "txt", "json", "xml", "csv", "zip", "doc", "docx", "png", "jpg", "jpeg", "gif", "so", "local"}
URL_RE = re.compile(r"(?:https?|ftp)://[^\s<>\"']{1,2048}", re.IGNORECASE)
EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,63}(?![\w-])")
DOMAIN_RE = re.compile(r"(?<![\w@-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w-])")
HASH_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])")
IPV4_RE = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
IP_TOKEN_RE = re.compile(r"(?<![A-Fa-f0-9])[0-9A-Fa-f:.%]{3,64}(?![A-Fa-f0-9])")
PATH_RE = re.compile(r"(?:[A-Za-z]:[\\/]|/|\\\\)[^\s\"'<>]{1,1024}")
ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


@dataclass(frozen=True)
class Indicator:
    type: str
    value: str
    confidence: float
    source_field: str
    classification: str | None = None


def sanitize(value, limit=2048):
    text = ANSI_RE.sub("", str(value))
    return "".join(ch for ch in text if ch >= " " and ch not in "\x7f\x9b").strip()[:limit]


def normalize_domain(value):
    text = sanitize(value, 255).rstrip(".").lower()
    if len(text) > 253 or "." not in text or ".." in text:
        return None
    try:
        ascii_domain = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = ascii_domain.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") or not re.fullmatch(r"[a-z0-9-]+", label) for label in labels):
        return None
    tld = labels[-1]
    if len(tld) < 2 or not tld.isalpha() or tld in FILE_TLDS:
        return None
    return ascii_domain


def normalize_ip(value):
    text = sanitize(value, 128)
    # Zone IDs are interface-local metadata; canonical IOC identity excludes the zone.
    if "%" in text:
        text = text.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    classification = next((label for flag, label in (
        (address.is_loopback, "loopback"), (address.is_link_local, "link_local"),
        (address.is_multicast, "multicast"), (address.is_private, "private"),
        (address.is_global, "global")) if flag), "private")
    kind = "ipv4" if address.version == 4 else "ipv6"
    return kind, address.compressed, classification


def normalize_url(value):
    text = sanitize(value, 2048).rstrip(".,;:!?) ]}")
    try:
        parts = urlsplit(text)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https", "ftp"} or not parts.hostname or parts.username or parts.password:
            return None
        host_raw = parts.hostname
        try:
            host = ipaddress.ip_address(host_raw.split("%", 1)[0]).compressed.lower()
            if ":" in host:
                host = f"[{host}]"
        except ValueError:
            host = normalize_domain(host_raw)
            if not host:
                return None
        port = parts.port
        netloc = host
        defaults = {"http": 80, "https": 443, "ftp": 21}
        if port is not None and port != defaults[scheme]:
            netloc += f":{port}"
        return urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))[:2048]
    except (ValueError, UnicodeError):
        return None


class IOCExtractor:
    def __init__(self, *, extract_raw_paths=False, include_non_global_ips=True):
        self.extract_raw_paths = extract_raw_paths
        self.include_non_global_ips = include_non_global_ips

    def extract(self, event):
        found = {}
        user_values = {sanitize(event.get(k), 320).casefold() for k in ("username", "target_user") if event.get(k)}
        attrs = event.get("attributes") or {}
        if attrs.get("actor_user"):
            user_values.add(sanitize(attrs["actor_user"], 320).casefold())
        def add(kind, value, source, level, classification=None):
            keyval = normalize_ip(value) if kind in {"ipv4", "ipv6", "ip"} else None
            if keyval:
                kind, value, classification = keyval
                if not self.include_non_global_ips and classification != "global": return
            elif kind == "domain":
                value = normalize_domain(value)
                if not value: return
            elif kind == "url":
                value = normalize_url(value)
                if not value: return
            elif kind == "email":
                text = sanitize(value, 320)
                if "@" not in text: return
                local, domain = text.rsplit("@", 1)
                domain = normalize_domain(domain)
                if not domain: return
                value = f"{local}@{domain}"
            elif kind in {"md5", "sha1", "sha256"}:
                value = sanitize(value, 64).lower()
            elif kind == "file_path":
                value = sanitize(value, 1024)
            if level == "raw" and str(value).casefold() in user_values: return
            confidence = CONFIDENCE[level]
            indicator = Indicator(kind, value, confidence, sanitize(source, 128), classification)
            key = (kind, value)
            old = found.get(key)
            if old is None or (confidence, source) > (old.confidence, old.source_field):
                found[key] = indicator

        structured = [(k, event.get(k)) for k in ("source_ip", "destination_ip", "url", "domain", "email", "file_hash", "command_line", "process_name", "image", "target_filename") if event.get(k)]
        attributes = event.get("attributes") or {}
        for key in ("image", "target_filename", "file_path", "executable_path", "command_line"):
            if attributes.get(key): structured.append((key, attributes[key]))
        raw = event.get("raw_event")
        if isinstance(raw, dict):
            for key in ("source_ip", "src_ip", "destination_ip", "dst_ip", "url", "domain", "email", "file_hash", "md5", "sha1", "sha256", "image", "target_filename", "command_line"):
                if raw.get(key) is not None:
                    structured.append((key, raw[key]))
        for field, value in structured:
            if not isinstance(value, (str, int, float)): continue
            text = sanitize(value, MAX_TEXT)
            if field in {"source_ip", "src_ip", "destination_ip", "dst_ip"}:
                add("ip", text, field, "structured")
            elif field in {"url"}:
                add("url", text, field, "structured")
            elif field == "domain": add("domain", text, field, "structured")
            elif field == "email": add("email", text, field, "structured")
            elif field in {"file_hash", "md5", "sha1", "sha256"}:
                kind = "sha256" if len(text) == 64 else "sha1" if len(text) == 40 else "md5" if len(text) == 32 else ""
                if kind and re.fullmatch(r"[A-Fa-f0-9]+", text): add(kind, text, field, "structured")
            if field in {"image", "target_filename", "file_path", "executable_path", "command_line"}:
                tokens = PATH_RE.findall(text)
                for path in tokens:
                    add("file_path", path, field, "structured")
        # Raw string scan is capped; explicit URLs are excluded from a second domain extraction.
        blob = sanitize(str(raw if isinstance(raw, str) else __import__("json").dumps(raw, ensure_ascii=True, default=str) if raw is not None else ""), MAX_TEXT)
        if event.get("raw_record"):
            blob += " " + sanitize(event["raw_record"], max(0, MAX_TEXT - len(blob)))
        spans = []
        for match in URL_RE.finditer(blob):
            url = match.group(0)
            add("url", url, "raw_url", "raw")
            spans.append(match.span())
        for match in EMAIL_RE.finditer(blob): add("email", match.group(0), "raw_email", "raw")
        for match in IPV4_RE.finditer(blob): add("ip", match.group(0), "raw_ip", "raw")
        for match in IP_TOKEN_RE.finditer(blob):
            token = match.group(0).strip(".,;:()[]{}<>")
            if ":" in token: add("ip", token, "raw_ip", "raw")
        for match in HASH_RE.finditer(blob):
            value = match.group(0)
            start, end = max(0, match.start() - 12), min(len(blob), match.end() + 4)
            context = blob[start:end].lower()
            kind = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
            level = "context" if re.search(r"(?:hash\s*=|md5\s*:|sha1\s*:|sha256\s*:)", context) else "raw"
            add(kind, value, "raw_hash", level)
        for match in DOMAIN_RE.finditer(blob):
            if any(match.start() < end and start < match.end() for start, end in spans): continue
            add("domain", match.group(0), "raw_domain", "raw")
        if self.extract_raw_paths:
            for path in PATH_RE.findall(blob): add("file_path", path, "raw_path", "raw")
        return sorted(found.values(), key=lambda item: (item.type, item.value, item.source_field))

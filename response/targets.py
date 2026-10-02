"""Strict validation and canonicalization for evidence-derived response targets."""
import ipaddress
import re
import unicodedata

from enrichment.extractor import normalize_domain

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_BIDI = {"RLO", "LRO", "RLE", "LRE", "PDF", "RLI", "LRI", "FSI", "PDI"}
_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def canonical_target(target: str, target_type: str) -> str:
    if target_type not in {"ip", "host", "account", "domain"}:
        raise ValueError("target_type is required and must be supported")
    if not isinstance(target, str) or not target or len(target) > 255:
        raise ValueError("target is empty or exceeds the 255 character limit")
    if _CONTROL.search(target) or any(unicodedata.category(ch)=="Cc" or unicodedata.bidirectional(ch) in _BIDI for ch in target):
        raise ValueError("target contains disallowed control or bidirectional characters")
    value = target.strip()
    if not value:
        raise ValueError("target is empty")
    if target_type == "ip":
        if "%" in value:
            raise ValueError("IPv6 zone identifiers are not allowed")
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("target is not a valid IP address") from exc
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved or address.is_unspecified:
            raise ValueError("loopback, link-local, multicast, reserved, and unspecified IPs are not valid targets")
        rfc1918 = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"))
        private_allowed = any(address.version == network.version and address in network for network in rfc1918)
        if isinstance(address, ipaddress.IPv6Address) and address in ipaddress.ip_network("fc00::/7"):
            private_allowed = True
        if not address.is_global and not private_allowed:
            raise ValueError("reserved or non-global IP targets are not allowed")
        return str(address)
    if target_type == "host":
        value = value.rstrip(".")
        if len(value) > 253 or not value:
            raise ValueError("hostname exceeds its length limit")
        labels = value.split(".")
        if any(not _LABEL.fullmatch(label) for label in labels) or any(len(label) > 63 for label in labels):
            raise ValueError("hostname must be an RFC 1123 or NetBIOS name")
        return value.lower()
    if target_type == "account":
        if len(value) > 256 or value.startswith("-") or value.endswith(("\\", "@")):
            raise ValueError("account name is invalid")
        if value.count("\\") > 1 or value.count("@") > 1 or ("\\" in value and "@" in value):
            raise ValueError("account must be DOMAIN\\user, UPN, or a machine account")
        if not re.fullmatch(r"[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_$.-]+|@[A-Za-z0-9.-]+)?", value):
            raise ValueError("account name contains invalid characters")
        return value.lower()
    domain = normalize_domain(value)
    if not domain:
        raise ValueError("domain is invalid")
    return domain

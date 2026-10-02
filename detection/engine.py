import ipaddress
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from database.repositories import AlertRepository, EvidenceLinkRepository, EventRepository, RuleExecutionRepository
from models.alert import Alert
from models.ids import stable_id
from models.timestamps import to_utc_iso

RULE_IDS = ("R001", "R002", "R003", "R010", "R011", "R020", "R021", "R030", "R040")
SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
DEFAULT_PATH = Path(__file__).with_name("rules.json")
MITRE = {"R001": (["T1110"], ["Credential Access"]), "R002": (["T1110"], ["Credential Access"]),
         "R003": (["T1110"], ["Credential Access"]), "R011": (["T1098"], ["Persistence", "Privilege Escalation"]),
         "R020": (["T1136"], ["Persistence"]), "R030": (["T1070.001"], ["Defense Evasion"]),
         "R040": (["T1543.003"], ["Persistence", "Privilege Escalation"])}
EVENT_RULES = {"privilege_assigned": "R010", "account_disabled": "R011", "account_enabled": "R011",
              "account_deleted": "R011", "group_membership_change": "R011",
              "account_created": "R020", "account_lockout": "R021", "audit_log_cleared": "R030",
              "service_created": "R040"}


def load_config(path=None):
    path = Path(path or os.getenv("RULES_CONFIG", DEFAULT_PATH))
    config = json.loads(path.read_text(encoding="utf-8"))
    rules = config.get("rules")
    if not isinstance(rules, dict) or set(rules) - set(RULE_IDS):
        raise ValueError("rules config must contain only known rule IDs")
    if set(rules) != set(RULE_IDS):
        raise ValueError("rules config must define every supported rule")
    for rule_id, rule in rules.items():
        if not isinstance(rule.get("enabled"), bool): raise ValueError(f"{rule_id}.enabled must be boolean")
        if type(rule.get("threshold")) is not int or not 1 <= rule["threshold"] <= 100000: raise ValueError(f"{rule_id}.threshold is invalid")
        if type(rule.get("window_seconds")) is not int or not 1 <= rule["window_seconds"] <= 86400: raise ValueError(f"{rule_id}.window_seconds is invalid")
        if rule.get("severity") not in SEVERITIES: raise ValueError(f"{rule_id}.severity is invalid")
        confidence = rule.get("confidence")
        if type(confidence) not in (int, float) or not 0 <= confidence <= 1: raise ValueError(f"{rule_id}.confidence is invalid")
    suppression = config.setdefault("suppression", {})
    suppression.setdefault("trusted_users", [])
    suppression.setdefault("trusted_hosts", [])
    suppression.setdefault("trusted_source_ips", [])
    for address in suppression["trusted_source_ips"]:
        ipaddress.ip_network(address, strict=False)
    for key in ("trusted_users", "trusted_hosts"):
        if not isinstance(suppression[key], list): raise ValueError(f"suppression.{key} must be a list")
    return config


def _safe(value, limit=200):
    return re.sub(r"[\x00-\x1f\x7f-\x9f\x1b]", "?", str(value or ""))[:limit]


class DetectionContext:
    """Read-only bounded temporal event queries."""
    def __init__(self, events):
        self.events = sorted(events, key=lambda e: (to_utc_iso(e["timestamp"]), e["event_id"]))

    def get_events(self, event_type, key, since, until):
        start, end = to_utc_iso(since), to_utc_iso(until)
        field, value = key
        return [e for e in self.events if (event_type is None or e.get("event_type") == event_type)
                and e.get(field) == value and start <= to_utc_iso(e["timestamp"]) <= end]

    def count_events(self, event_type, key, since, until):
        return len(self.get_events(event_type, key, since, until))

    def find_matching_events(self, event_type, fields, since, until):
        start, end = to_utc_iso(since), to_utc_iso(until)
        return [e for e in self.events if (event_type is None or e.get("event_type") == event_type)
                and all(e.get(k) == v for k, v in fields.items())
                and start <= to_utc_iso(e["timestamp"]) <= end]


class DetectionEngine:
    def __init__(self, database, config_path=None):
        self.db = database
        self.config = load_config(config_path)
        self.events = EventRepository(database)
        self.alerts = AlertRepository(database)
        self.links = EvidenceLinkRepository(database)
        self.audit = RuleExecutionRepository(database)

    def run(self, since=None, batch_id=None):
        events = self.events.query(since=since, batch_id=batch_id)
        context = DetectionContext(events)
        now = datetime.now(timezone.utc).isoformat()
        candidates = self._candidates(context)
        # Same-rule candidates with identical evidence are merged across IP and username grouping.
        merged = {}
        for candidate in candidates:
            if candidate["rule_id"] in {"R001", "R002"}:
                key = (candidate["rule_id"], tuple(candidate["event_ids"]))
                if key in merged:
                    merged[key]["grouping_key"] += "; " + candidate["grouping_key"]
                    continue
                merged[key] = candidate
            else:
                merged[(candidate["rule_id"], candidate["id"])] = candidate
        candidates = list(merged.values())
        # Stronger R001 supersedes any overlapping R002 burst.
        r1_sets = [set(c["event_ids"]) for c in candidates if c["rule_id"] == "R001"]
        active, suppressed = [], []
        for c in candidates:
            config = self.config["rules"][c["rule_id"]]
            if not config["enabled"]: continue
            if c["rule_id"] == "R002" and any(set(c["event_ids"]) <= s for s in r1_sets):
                suppressed.append((c, "superseded_by_R001")); continue
            reason = self._suppression(c)
            if reason: suppressed.append((c, reason))
            else: active.append(c)
        counts = {rid: {"created": 0, "suppressed": 0} for rid in RULE_IDS}
        for c in active:
            rid, cfg = c["rule_id"], self.config["rules"][c["rule_id"]]
            techniques, tactics = MITRE.get(rid, ([], []))
            first = context.events_by_id[c["event_ids"][0]] if hasattr(context, "events_by_id") else next(e for e in events if e["event_id"] == c["event_ids"][0])
            title = c.get("title", rid + " detection")
            explanation = _safe(c.get("explanation", f"{title}; grouping {c['grouping_key']}; {len(c['event_ids'])} event(s)."), 1000)
            alert = Alert("detection", c["grouping_key"], cfg["severity"], title, 50, c["event_ids"],
                          "Review the linked evidence.", confidence=cfg["confidence"], rule_id=rid,
                          status="NEW", alert_id=c["id"], timestamp=to_utc_iso(first["timestamp"]),
                          title=title, explanation=explanation, mitre_techniques=techniques,
                          mitre_tactics=tactics, evidence_refs=c["event_ids"], grouping_key=c["grouping_key"])
            payload = alert.to_dict()
            created = self.alerts.save(payload)
            for event_id in c["event_ids"]:
                self.links.link_reference("ALERT", c["id"], "EVENT", event_id)
            counts[rid]["created"] += int(created)
        for c, reason in suppressed:
            self.audit.save_suppressed(stable_id("sup", c["rule_id"], c["grouping_key"], c["id"], reason),
                c["rule_id"], c["grouping_key"], reason, now, c["event_ids"])
            counts[c["rule_id"]]["suppressed"] += 1
        for rid in RULE_IDS:
            self.audit.record(rid, now, batch_id, since, len(events), counts[rid]["created"], counts[rid]["suppressed"], "completed", [])
        return sorted(active, key=lambda c: (c["timestamp"], c["id"]))

    def _candidates(self, context):
        out = []
        failures = [e for e in context.events if e.get("event_type") == "auth_failure"]
        for rid in ("R001", "R002"):
            cfg = self.config["rules"][rid]
            if not cfg["enabled"]: continue
            for field in ("source_ip", "username"):
                groups = {}
                for e in failures:
                    val = e.get(field)
                    if val: groups.setdefault(str(val), []).append(e)
                for value, rows in groups.items():
                    pos = 0
                    while pos < len(rows):
                        anchor = rows[pos]
                        end_time = datetime.fromisoformat(to_utc_iso(anchor["timestamp"])) + timedelta(seconds=cfg["window_seconds"])
                        group = []
                        j = pos
                        while j < len(rows) and datetime.fromisoformat(to_utc_iso(rows[j]["timestamp"])) <= end_time:
                            group.append(rows[j]); j += 1
                        if len(group) >= cfg["threshold"]:
                            ids = [e["event_id"] for e in group]
                            gkey = f"{field}={_safe(value)}"
                            out.append({"rule_id": rid, "id": stable_id("det", rid, gkey, anchor["event_id"]),
                                "timestamp": anchor["timestamp"], "event_ids": ids, "grouping_key": gkey,
                                "title": "Brute-force burst" if rid == "R001" else "Repeated authentication failures"})
                            pos = j if j > pos else pos + 1
                        else: pos += 1
        # R003 is grouped strictly by source IP + username, uses failures in the preceding window.
        cfg = self.config["rules"]["R003"]
        if cfg["enabled"]:
            for success in context.events:
                if success.get("event_type") != "auth_success" or not success.get("source_ip") or not success.get("username"): continue
                t = datetime.fromisoformat(to_utc_iso(success["timestamp"]))
                start = (t - timedelta(seconds=cfg["window_seconds"])).isoformat()
                matches = [e for e in context.find_matching_events("auth_failure", {"source_ip": success["source_ip"], "username": success["username"]}, start, success["timestamp"])
                           if e["event_id"] != success["event_id"]]
                # Do not repeatedly alert on the same fixed failure burst.
                if matches:
                    anchor = matches[0]
                    ids = [e["event_id"] for e in matches] + [success["event_id"]]
                    gkey = f"source_ip={_safe(success['source_ip'])};username={_safe(success['username'])}"
                    out.append({"rule_id": "R003", "id": stable_id("det", "R003", gkey, anchor["event_id"]),
                        "timestamp": anchor["timestamp"], "event_ids": sorted(set(ids)), "grouping_key": gkey,
                        "title": "Authentication failure followed by success"})
        # Fixed event rules; lockout pattern requires configured repeated threshold.
        for rid in ("R010", "R011", "R020", "R021", "R030", "R040"):
            cfg = self.config["rules"][rid]
            if not cfg["enabled"]: continue
            matching = [e for e in context.events if EVENT_RULES.get(e.get("event_type")) == rid]
            if rid == "R021":
                groups = {}
                for e in matching:
                    key = (e.get("hostname") or "", e.get("username") or e.get("target_user") or "")
                    groups.setdefault(key, []).append(e)
                for (host, user), rows in groups.items():
                    for anchor in rows:
                        t = datetime.fromisoformat(to_utc_iso(anchor["timestamp"]))
                        group = [e for e in rows if t <= datetime.fromisoformat(to_utc_iso(e["timestamp"])) <= t + timedelta(seconds=cfg["window_seconds"])]
                        if len(group) >= cfg["threshold"]:
                            ids = [e["event_id"] for e in group]; g = f"host={_safe(host)};user={_safe(user)}"
                            out.append({"rule_id": rid, "id": stable_id("det", rid, g, ids[0]), "timestamp": anchor["timestamp"], "event_ids": ids, "grouping_key": g, "title": "Repeated account lockouts"}); break
            else:
                for e in matching:
                    g = f"host={_safe(e.get('hostname') or '')};user={_safe(e.get('target_user') or e.get('username') or '')}"
                    out.append({"rule_id": rid, "id": stable_id("det", rid, g, e["event_id"]), "timestamp": e["timestamp"], "event_ids": [e["event_id"]], "grouping_key": g, "title": rid + " security event"})
        # Repeated successes/lockout anchors extend one fixed burst detection.
        by_id = {}
        for candidate in out:
            existing = by_id.get(candidate["id"])
            if existing:
                existing["event_ids"] = sorted(set(existing["event_ids"]) | set(candidate["event_ids"]))
            else:
                by_id[candidate["id"]] = candidate
        return list(by_id.values())

    def _suppression(self, candidate):
        events = [self.events.get(eid) for eid in candidate["event_ids"]]
        suppression = self.config["suppression"]
        users = set(suppression["trusted_users"])
        hosts = set(suppression["trusted_hosts"])
        # Specificity precedence: trusted user, then trusted source IP/CIDR, then host.
        if any(e and (e.get("target_user") or e.get("username")) in users for e in events): return "trusted_user"
        networks = [ipaddress.ip_network(x, strict=False) for x in suppression["trusted_source_ips"]]
        if any(e and e.get("source_ip") and any(ipaddress.ip_address(e["source_ip"]) in n for n in networks) for e in events): return "trusted_source_ip"
        if any(e and e.get("hostname") in hosts for e in events): return "trusted_host"
        return None

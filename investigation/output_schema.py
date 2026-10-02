"""Strict structured output validation and safe rendering helpers."""
import html
import json
import re
from html.parser import HTMLParser


OUTPUT_SCHEMA_VERSION = "phase6.output.v1"
CONFIDENCE = {"high", "medium", "low"}
BASIS = {"observed", "inferred", "unknown"}
ACTION_TYPES = {"validate_login", "review_auth_logs", "reset_credentials", "isolate_host", "escalate"}
ROOT_KEYS = ("summary", "attack_narrative", "timeline_assessment", "key_findings", "supported_claims",
             "attack_progression", "ioc_assessment", "mitre_assessment", "uncertainties",
             "recommended_actions", "confidence", "limitations")
MAX_STRING = 2000
MAX_ARRAY = 100
MAX_EVIDENCE = 50

OUTPUT_JSON_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": list(ROOT_KEYS),
    "$defs": {
        "finding": {"type":"object","additionalProperties":False,"required":["text","basis","confidence","evidence"],"properties":{
            "text":{"type":"string","maxLength":MAX_STRING},"basis":{"type":"string","enum":sorted(BASIS)},
            "confidence":{"type":"string","enum":sorted(CONFIDENCE)},"evidence":{"type":"array","maxItems":MAX_EVIDENCE,
                "uniqueItems":True,"items":{"type":"string","pattern":"^[DEIM][1-9][0-9]*$"}}}},
        "ioc": {"type":"object","additionalProperties":False,"required":["ioc","assessment","basis","evidence"],"properties":{
            "ioc":{"type":"string","pattern":"^I[1-9][0-9]*$"},"assessment":{"type":"string","enum":["relevant","benign","uncertain"]},
            "basis":{"type":"string","enum":sorted(BASIS)},"evidence":{"type":"array","maxItems":MAX_EVIDENCE,"uniqueItems":True,"items":{"type":"string","pattern":"^[DEIM][1-9][0-9]*$"}}}},
        "mitre": {"type":"object","additionalProperties":False,"required":["mapping","assessment","evidence"],"properties":{
            "mapping":{"type":"string","pattern":"^M[1-9][0-9]*$"},"assessment":{"type":"string","enum":["supported","weak","unsupported"]},
            "evidence":{"type":"array","minItems":1,"maxItems":MAX_EVIDENCE,"uniqueItems":True,"items":{"type":"string","pattern":"^[DEIM][1-9][0-9]*$"}}}},
        "recommendation": {"type":"object","additionalProperties":False,"required":["action_type","action","priority","reason","evidence"],"properties":{
            "action_type":{"type":"string","enum":sorted(ACTION_TYPES)},"action":{"type":"string","maxLength":MAX_STRING},
            "priority":{"type":"string","enum":["high","medium","low"]},"reason":{"type":"string","maxLength":MAX_STRING},
            "evidence":{"type":"array","maxItems":MAX_EVIDENCE,"uniqueItems":True,"items":{"type":"string","pattern":"^[DEIM][1-9][0-9]*$"}}}},
    },
    "properties": {
        "summary": {"type": "string","maxLength":MAX_STRING}, "attack_narrative": {"type": "string","maxLength":MAX_STRING},
        "timeline_assessment": {"type": "string","maxLength":MAX_STRING}, "confidence": {"type": "string", "enum": sorted(CONFIDENCE)},
        "key_findings": {"type": "array","maxItems":MAX_ARRAY,"items":{"$ref":"#/$defs/finding"}}, "supported_claims": {"type": "array","maxItems":MAX_ARRAY,"items":{"$ref":"#/$defs/finding"}},
        "attack_progression": {"type": "array","maxItems":MAX_ARRAY,"items":{"$ref":"#/$defs/finding"}}, "ioc_assessment": {"type": "array","maxItems":MAX_ARRAY,"items":{"$ref":"#/$defs/ioc"}},
        "mitre_assessment": {"type": "array","maxItems":MAX_ARRAY,"items":{"$ref":"#/$defs/mitre"}}, "uncertainties": {"type": "array","maxItems":MAX_ARRAY,"items":{"$ref":"#/$defs/finding"}},
        "recommended_actions": {"type": "array","maxItems":MAX_ARRAY,"items":{"$ref":"#/$defs/recommendation"}}, "limitations": {"type": "array","maxItems":MAX_ARRAY,"items":{"$ref":"#/$defs/finding"}},
    },
}

_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_URL = re.compile(r"\bhttps?://[A-Za-z0-9.-]+(?:\:[0-9]+)?(?:/[^\s]*)?", re.IGNORECASE)
_COMMAND = re.compile(r"(?:\b(?:sudo|bash|sh|zsh|powershell|cmd(?:\.exe)?|curl|wget|python(?:\d+(?:\.\d+)*)?|rm|del|format|ssh|chmod|nc|netcat|echo|cat|ls|touch|mkdir|copy|move|reg|net|systemctl|service|apt|pip|docker|kubectl)\b|[|;&`])", re.I)

HIGH_RISK = {
    "privilege_escalation": re.compile(r"privilege escalation|elevat(?:ed|ion)|became administrator", re.I),
    "persistence": re.compile(r"persistence|persistent access|backdoor", re.I),
    "exfiltration": re.compile(r"exfiltrat|data theft|stolen data", re.I),
    "successful_exploitation": re.compile(r"successful(?:ly)? exploit|exploitation succeeded|compromised host", re.I),
    "credential_compromise": re.compile(r"credential compromise|credentials? (?:were )?compromised|stolen credentials", re.I),
}
DEFAULT_CLAIM_GUARD = {
    "privilege_escalation": {"event_types": ["privilege_assigned", "group_membership_change"], "rule_ids": ["R010", "R011"]},
    "persistence": {"event_types": ["service_created", "account_created", "group_membership_change"], "rule_ids": ["R011", "R020", "R040"]},
    "exfiltration": {"event_types": ["data_exfiltration", "large_outbound_transfer"], "rule_ids": ["R050"]},
    "successful_exploitation": {"event_types": ["exploit_success", "successful_exploitation"], "rule_ids": ["R060"]},
    "credential_compromise": {"event_types": ["credential_compromise"], "rule_ids": ["R003"]},
}


class OutputValidationError(ValueError):
    def __init__(self, errors):
        self.errors = [str(e)[:300] for e in errors[:10]]
        super().__init__("; ".join(self.errors))


class _TextOnly(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.parts=[]
    def handle_data(self, data): self.parts.append(data)


def sanitize_text(value):
    if not isinstance(value, str): raise ValueError("expected string")
    value = _ANSI.sub("", value)
    value = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", value)
    parser = _TextOnly()
    try: parser.feed(value); parser.close(); value = " ".join(parser.parts)
    except Exception: value = re.sub(r"<[^>]*>", " ", value)
    value = html.unescape(value)
    value = re.sub(r"<[^>]*>", " ", value)
    value = value.replace("<", "").replace(">", "")
    value = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", value)
    value = re.sub(r"(?i)\b(?:javascript|data):", "[blocked]:", value)
    value = value.replace("`", "")
    value = re.sub(r"\s+", " ", value).strip()
    return _URL.sub(lambda m: re.sub(r"\.", "[.]", re.sub(r"^https?://", lambda x: "hxxp://" if x.group(0).lower().startswith("http://") else "hxxps://", m.group(0), flags=re.I)), value)[:MAX_STRING]


def _string(obj, key, errors, *, required=True, limit=MAX_STRING):
    value=obj.get(key)
    if not isinstance(value,str):
        if required: errors.append(f"{key} must be a string")
        return ""
    if len(value)>limit: errors.append(f"{key} exceeds {limit} characters")
    return value


def validate_output(value, alias_map, detections, events, claim_guard=None):
    """Validate complete Phase 6 JSON, enforce typed aliases and high-risk claim evidence."""
    errors=[]
    if isinstance(value,str):
        try: value=json.loads(value)
        except (TypeError,ValueError) as exc: raise OutputValidationError([f"invalid JSON: {exc}"])
    if not isinstance(value,dict): raise OutputValidationError(["root must be an object"])
    if set(value)!=set(ROOT_KEYS): errors.append("root keys do not match the required output schema")
    for key in ROOT_KEYS:
        if key not in value: errors.append(f"missing {key}")
    output={}
    for key in ("summary","attack_narrative","timeline_assessment"):
        output[key]=_string(value,key,errors,limit=MAX_STRING)
    confidence=value.get("confidence")
    if confidence not in CONFIDENCE: errors.append("confidence must be high, medium, or low")
    output["confidence"]=confidence if confidence in CONFIDENCE else "low"

    def array(key):
        rows=value.get(key)
        if not isinstance(rows,list): errors.append(f"{key} must be an array"); return []
        if len(rows)>MAX_ARRAY: errors.append(f"{key} exceeds {MAX_ARRAY} items")
        return rows

    def aliases(row, key, allowed=None, minimum=0):
        refs=row.get(key)
        if not isinstance(refs,list): errors.append(f"{key} must be an array"); return []
        if len(refs)>MAX_EVIDENCE: errors.append(f"{key} exceeds {MAX_EVIDENCE} references")
        if len(refs)!=len(set(map(str,refs))): errors.append(f"{key} contains duplicate evidence references")
        if len(refs)<minimum: errors.append(f"{key} requires at least {minimum} evidence item(s)")
        for alias in refs:
            record=alias_map.get(alias)
            if record is None: errors.append(f"unknown evidence alias: {alias}")
            elif allowed and record["type"] not in allowed: errors.append(f"wrong evidence type for alias {alias}")
        return refs

    def finding_array(key):
        rows=array(key); clean=[]
        for i,row in enumerate(rows[:MAX_ARRAY]):
            if not isinstance(row,dict): errors.append(f"{key}[{i}] must be an object"); continue
            if set(row)!={"text","basis","confidence","evidence"}: errors.append(f"{key}[{i}] has unexpected or missing fields")
            text=_string(row,"text",errors); basis=row.get("basis"); conf=row.get("confidence")
            if basis not in BASIS: errors.append(f"{key}[{i}].basis is invalid")
            if conf not in CONFIDENCE: errors.append(f"{key}[{i}].confidence is invalid")
            minimum=1 if basis=="observed" else 2 if basis=="inferred" else 0
            refs=aliases(row,"evidence",minimum=minimum)
            clean.append({"text":text,"basis":basis if basis in BASIS else "unknown","confidence":conf if conf in CONFIDENCE else "low","evidence":refs})
        return clean

    for key in ("key_findings","supported_claims","uncertainties","limitations"):
        output[key]=finding_array(key)
    output["attack_progression"]=[]
    for i,row in enumerate(array("attack_progression")[:MAX_ARRAY]):
        if not isinstance(row,dict): errors.append(f"attack_progression[{i}] must be an object"); continue
        if set(row)!={"text","basis","confidence","evidence"}: errors.append(f"attack_progression[{i}] fields are invalid")
        text=_string(row,"text",errors); basis=row.get("basis"); conf=row.get("confidence")
        if basis not in BASIS: errors.append(f"attack_progression[{i}].basis is invalid")
        if conf not in CONFIDENCE: errors.append(f"attack_progression[{i}].confidence is invalid")
        min_refs=1 if basis=="observed" else 2 if basis=="inferred" else 0
        refs=aliases(row,"evidence",allowed={"detection","event"},minimum=min_refs)
        output["attack_progression"].append({"text":text,"basis":basis if basis in BASIS else "unknown","confidence":conf if conf in CONFIDENCE else "low","evidence":refs})
    output["ioc_assessment"]=[]
    for i,row in enumerate(array("ioc_assessment")[:MAX_ARRAY]):
        if not isinstance(row,dict): errors.append(f"ioc_assessment[{i}] must be an object"); continue
        if set(row)!={"ioc","assessment","basis","evidence"}: errors.append(f"ioc_assessment[{i}] fields are invalid")
        record=alias_map.get(row.get("ioc"))
        if record is None: errors.append(f"unknown IOC alias: {row.get('ioc')}")
        elif record["type"]!="ioc": errors.append(f"wrong evidence type for IOC alias {row.get('ioc')}")
        assessment=row.get("assessment"); basis=row.get("basis")
        if assessment not in {"relevant","benign","uncertain"}: errors.append(f"ioc_assessment[{i}].assessment is invalid")
        if basis not in BASIS: errors.append(f"ioc_assessment[{i}].basis is invalid")
        minimum=1 if basis=="observed" else 2 if basis=="inferred" else 0
        refs=aliases(row,"evidence",minimum=minimum)
        output["ioc_assessment"].append({"ioc":row.get("ioc"),"assessment":assessment,"basis":basis,"evidence":refs})
    output["mitre_assessment"]=[]
    for i,row in enumerate(array("mitre_assessment")[:MAX_ARRAY]):
        if not isinstance(row,dict): errors.append(f"mitre_assessment[{i}] must be an object"); continue
        if set(row)!={"mapping","assessment","evidence"}: errors.append(f"mitre_assessment[{i}] fields are invalid")
        record=alias_map.get(row.get("mapping"))
        if record is None: errors.append(f"unknown mapping alias: {row.get('mapping')}")
        elif record["type"]!="mapping": errors.append(f"wrong evidence type for mapping alias {row.get('mapping')}")
        if row.get("assessment") not in {"supported","weak","unsupported"}: errors.append(f"mitre_assessment[{i}].assessment is invalid")
        refs=aliases(row,"evidence",minimum=1)
        output["mitre_assessment"].append({"mapping":row.get("mapping"),"assessment":row.get("assessment"),"evidence":refs})
    output["recommended_actions"]=[]
    for i,row in enumerate(array("recommended_actions")[:MAX_ARRAY]):
        if not isinstance(row,dict): errors.append(f"recommended_actions[{i}] must be an object"); continue
        if set(row)!={"action_type","action","priority","reason","evidence"}: errors.append(f"recommended_actions[{i}] fields are invalid")
        action_type=row.get("action_type"); priority=row.get("priority")
        if action_type not in ACTION_TYPES: errors.append(f"recommended_actions[{i}].action_type is invalid")
        if priority not in {"high","medium","low"}: errors.append(f"recommended_actions[{i}].priority is invalid")
        action=_string(row,"action",errors); reason=_string(row,"reason",errors)
        if _COMMAND.search(action) or _COMMAND.search(reason): errors.append(f"recommended_actions[{i}] contains command-like content")
        refs=aliases(row,"evidence")
        output["recommended_actions"].append({"action_type":action_type,"action":action,"priority":priority,"reason":reason,"evidence":refs})

    guard=claim_guard or DEFAULT_CLAIM_GUARD
    aliases_to_rows={}
    for alias,meta in alias_map.items():
        if meta["type"]=="detection": aliases_to_rows[alias]=detections.get(meta["id"],{})
        elif meta["type"]=="event": aliases_to_rows[alias]=events.get(meta["id"],{})
    for key in ("key_findings","supported_claims","attack_progression"):
        for row in output[key]:
            text=row["text"]
            for category,pattern in HIGH_RISK.items():
                if not pattern.search(text): continue
                config=guard.get(category,DEFAULT_CLAIM_GUARD[category]); compatible=False
                for alias in row["evidence"]:
                    evidence=aliases_to_rows.get(alias,{})
                    if evidence.get("event_type") in config.get("event_types",[]) or evidence.get("rule_id") in config.get("rule_ids",[]): compatible=True; break
                if not compatible: errors.append(f"high-risk claim lacks compatible evidence: {category}")
    if errors: raise OutputValidationError(errors)
    # Sanitize every user-visible string after validation; action_type remains authoritative.
    for key in ("summary","attack_narrative","timeline_assessment"):
        output[key]=sanitize_text(output[key])
    for key in ("key_findings","supported_claims","uncertainties","limitations","attack_progression"):
        for row in output[key]: row["text"]=sanitize_text(row["text"])
    for row in output["recommended_actions"]:
        row["action"]=sanitize_text(row["action"]); row["reason"]=sanitize_text(row["reason"])
    return output


def translate_aliases(result, alias_map):
    """Replace validated packet aliases by their underlying persisted IDs."""
    result=json.loads(json.dumps(result))
    def replace(rows, field="evidence"):
        for row in rows:
            row[field]=[alias_map[a]["id"] for a in row.get(field,[])]
    for key in ("key_findings","supported_claims","uncertainties","limitations","attack_progression","recommended_actions"):
        replace(result[key])
    for row in result["ioc_assessment"]:
        row["ioc"]=alias_map[row["ioc"]]["id"]; row["evidence"]=[alias_map[a]["id"] for a in row["evidence"]]
    for row in result["mitre_assessment"]:
        row["mapping"]=alias_map[row["mapping"]]["id"]; row["evidence"]=[alias_map[a]["id"] for a in row["evidence"]]
    return result

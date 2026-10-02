"""Canonical, deterministic and bounded incident evidence packet builder."""
import hashlib
import json
import re
from collections import defaultdict

from investigation.output_schema import sanitize_text

PACKET_SCHEMA_VERSION = "phase6.packet.v1"
_SECRET = re.compile(r"(?i)([\"']?(?:password|passwd|secret|token|api[_-]?key|authorization|private[_-]?key)[\"']?\s*[:=]\s*[\"']?)([^\s,;\"']+)")


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _json_or_empty(value):
    try: return json.loads(value or "{}") if isinstance(value,str) else (value or {})
    except (TypeError,ValueError): return {}


def _safe_raw(raw, max_chars):
    value=raw
    if not isinstance(value,str): value=canonical_json(value)
    original_length=len(value)
    value=_SECRET.sub(lambda m: f"{m.group(1)}=[REDACTED]", value)
    value=sanitize_text(value)
    excerpt=value[:max_chars]
    return excerpt, max(0,original_length-len(excerpt))


class EvidencePacketBuilder:
    def __init__(self, *, max_events=100, max_iocs=100, max_mappings=100,
                 max_packet_bytes=256000, raw_excerpt_chars=1000):
        self.max_events=max(0,int(max_events)); self.max_iocs=max(0,int(max_iocs))
        self.max_mappings=max(0,int(max_mappings)); self.max_packet_bytes=max(1024,int(max_packet_bytes))
        self.raw_excerpt_chars=max(0,int(raw_excerpt_chars))

    def build(self, connection, incident_id):
        incident_row=connection.execute("SELECT payload FROM incidents WHERE incident_id=?",(incident_id,)).fetchone()
        if not incident_row: raise LookupError(f"Incident not found: {incident_id}")
        incident=_json_or_empty(incident_row["payload"])
        if incident.get("merged_into"):
            raise ValueError(f"Incident has been merged into {incident['merged_into']}. Investigate the surviving incident instead.")
        tables={r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        detection_ids=self._ids(connection,tables,incident_id,"incident_detections","detection_id",incident.get("detection_ids") or incident.get("alert_ids") or [])
        detection_rows={}
        for did in detection_ids:
            row=connection.execute("SELECT timestamp,severity,payload FROM alerts WHERE alert_id=?",(did,)).fetchone()
            if not row: continue
            p=_json_or_empty(row["payload"])
            detection_rows[did]={"id":did,"timestamp":row["timestamp"],"severity":row["severity"],
                "rule_id":p.get("rule_id"),"title":p.get("title") or p.get("attack_type") or p.get("rule_id") or "Security detection",
                "event_ids":set()}
        detection_ids=sorted(detection_rows)
        refs={did:set() for did in detection_ids}
        for did in detection_ids:
            payload=_json_or_empty(connection.execute("SELECT payload FROM alerts WHERE alert_id=?",(did,)).fetchone()[0])
            linked=payload.get("evidence_refs") or payload.get("evidence") or []
            if isinstance(linked,str): linked=[linked]
            refs[did].update(x for x in linked if isinstance(x,str))
            if "evidence_refs" in tables:
                refs[did].update(r[0] for r in connection.execute("SELECT evidence_id FROM evidence_refs WHERE owner_type='ALERT' AND owner_id=? AND evidence_type='EVENT'",(did,)))
        event_ids=set()
        if "incident_events" in tables:
            event_ids.update(r[0] for r in connection.execute("SELECT event_id FROM incident_events WHERE incident_id=?",(incident_id,)))
        elif "evidence_links" in tables:
            event_ids.update(r[0] for r in connection.execute("SELECT event_id FROM evidence_links WHERE incident_id=?",(incident_id,)))
        for did,linked in refs.items(): event_ids.update(linked)
        event_rows={}
        for eid in (sorted(event_ids) if "events" in tables else []):
            row=connection.execute("SELECT id,timestamp,host,user,src_ip,dst_ip,event_type,raw FROM events WHERE id=?",(eid,)).fetchone()
            if not row: continue
            try: rawrecord=_json_or_empty(row["raw"])
            except Exception: rawrecord={}
            raw=rawrecord.get("raw_event",rawrecord.get("event",row["raw"]))
            excerpt,omitted=_safe_raw(raw,self.raw_excerpt_chars)
            event_rows[eid]={"id":eid,"timestamp":row["timestamp"],"host":sanitize_text(row["host"] or ""),
                "user":sanitize_text(row["user"] or ""),"src_ip":sanitize_text(row["src_ip"] or ""),
                "dst_ip":sanitize_text(row["dst_ip"] or ""),"event_type":sanitize_text(row["event_type"] or "unknown"),
                "raw_excerpt":excerpt,"raw_omitted":omitted}
        for did,linked in refs.items(): detection_rows[did]["event_ids"].update(linked.intersection(event_rows))
        ioc_ids=set()
        if "incident_iocs" in tables:
            ioc_ids.update(r[0] for r in connection.execute("SELECT ioc_id FROM incident_iocs WHERE incident_id=?",(incident_id,)))
        if not ioc_ids and "ioc_detection_links" in tables and detection_ids:
            marks=",".join("?" for _ in detection_ids)
            ioc_ids.update(r[0] for r in connection.execute(f"SELECT DISTINCT ioc_id FROM ioc_detection_links WHERE detection_id IN ({marks})",detection_ids))
        ioc_rows={}
        for iid in sorted(ioc_ids):
            row=connection.execute("SELECT value,type,classification,payload FROM iocs WHERE ioc_id=?",(iid,)).fetchone()
            if row:
                p=_json_or_empty(row["payload"])
                ioc_rows[iid]={"id":iid,"value":sanitize_text(row["value"]),"type":sanitize_text(row["type"]),
                    "classification":sanitize_text(row["classification"] or p.get("classification") or "unknown")}
        mapping_ids=set()
        if "incident_attack_mappings" in tables:
            mapping_ids.update(r[0] for r in connection.execute("SELECT mapping_id FROM incident_attack_mappings WHERE incident_id=?",(incident_id,)))
        if not mapping_ids and "attack_mappings" in tables and detection_ids:
            marks=",".join("?" for _ in detection_ids)
            mapping_ids.update(r[0] for r in connection.execute(f"SELECT id FROM attack_mappings WHERE detection_id IN ({marks})",detection_ids))
        mappings={}
        for mid in sorted(mapping_ids):
            row=connection.execute("SELECT technique_id,technique_name,tactic_ids,attack_version FROM attack_mappings WHERE id=?",(mid,)).fetchone()
            if row: mappings[mid]={"id":mid,"technique_id":row["technique_id"],"technique_name":sanitize_text(row["technique_name"]),
                "tactic_ids":_json_or_empty(row["tactic_ids"]) if isinstance(row["tactic_ids"],str) else row["tactic_ids"],"attack_version":row["attack_version"]}

        alias_map={}
        aliases={}
        for kind,ids,prefix in (("detection",detection_ids,"D"),("event",sorted(event_rows),"E"),
                                ("ioc",sorted(ioc_rows),"I"),("mapping",sorted(mappings),"M")):
            aliases[kind]={}
            for n,real_id in enumerate(sorted(ids),1):
                alias=f"{prefix}{n}"; aliases[kind][real_id]=alias
                alias_map[alias]={"type":kind,"id":real_id}
        all_events=sorted(event_rows.values(),key=lambda e:(e["timestamp"],e["id"]))
        selected={}
        # 1. At least the earliest persisted event for each detection.
        for did in detection_ids:
            candidates=sorted((event_rows[eid] for eid in detection_rows[did]["event_ids"] if eid in event_rows),key=lambda e:(e["timestamp"],e["id"]))
            if candidates: selected[candidates[0]["id"]]=candidates[0]
        # 2. Always include incident-wide earliest and latest linked events.
        if all_events:
            selected[all_events[0]["id"]]=all_events[0]; selected[all_events[-1]["id"]]=all_events[-1]
        # 3. Fill remaining event capacity in timestamp / event ID order.
        limit=max(self.max_events,len(selected))
        for row in all_events:
            if len(selected)>=limit: break
            selected[row["id"]]=row
        chosen_events=sorted(selected.values(),key=lambda e:(e["timestamp"],e["id"]))
        omitted_ids=set(event_rows)-set(selected)
        unavailable_events=len(event_ids-set(event_rows))
        chosen_iocs=sorted(ioc_rows)[:self.max_iocs]; chosen_mappings=sorted(mappings)[:self.max_mappings]
        ioc_omitted=len(ioc_rows)-len(chosen_iocs); mapping_omitted=len(mappings)-len(chosen_mappings)
        raw_omitted=sum(e["raw_omitted"] for e in event_rows.values())
        packet_detections=[]; detection_chars_omitted=0
        for did in detection_ids:
            original_title=str(detection_rows[did]["title"] or "Security detection")
            safe_title=sanitize_text(original_title)
            bounded_title=safe_title[:160]
            detection_chars_omitted+=max(0,len(original_title)-len(bounded_title))
            packet_detections.append({"alias":aliases["detection"][did],"timestamp":detection_rows[did]["timestamp"],
                "severity":detection_rows[did]["severity"],"rule_id":sanitize_text(detection_rows[did]["rule_id"] or "unknown"),
                "title":bounded_title,"events":[aliases["event"][eid] for eid in sorted(detection_rows[did]["event_ids"] & set(selected),key=lambda e:(event_rows[e]["timestamp"],e))]})
        truncated=bool(omitted_ids or unavailable_events or ioc_omitted or mapping_omitted or raw_omitted or detection_chars_omitted)
        packet={"schema_version":PACKET_SCHEMA_VERSION,
            "limits":{"max_events":self.max_events,"max_iocs":self.max_iocs,"max_mappings":self.max_mappings,
                      "max_packet_bytes":self.max_packet_bytes,"raw_excerpt_chars":self.raw_excerpt_chars},
            "incident":{"severity":sanitize_text(incident.get("severity","unknown")),
                "risk_level":sanitize_text(incident.get("risk_level","unknown")),"risk_score":incident.get("risk_score",0),
                "deterministic_confidence":sanitize_text(incident.get("confidence","low")),
                "primary_host":sanitize_text(incident.get("primary_host") or ""),"primary_user":sanitize_text(incident.get("primary_user") or ""),
                "primary_src_ip":sanitize_text(incident.get("primary_src_ip") or ""),
                "detection_count":len(detection_ids)},
            "detections":packet_detections,
            "events":[{"alias":aliases["event"][e["id"]],"timestamp":e["timestamp"],"host":e["host"],"user":e["user"],
                "src_ip":e["src_ip"],"dst_ip":e["dst_ip"],"event_type":e["event_type"],
                "timeline_description":self._timeline(e),"raw_excerpt":e["raw_excerpt"]} for e in chosen_events],
            "iocs":[{"alias":aliases["ioc"][iid],"value":ioc_rows[iid]["value"],"type":ioc_rows[iid]["type"],"classification":ioc_rows[iid]["classification"]} for iid in chosen_iocs],
            "attack_mappings":[{"alias":aliases["mapping"][mid],"technique_id":mappings[mid]["technique_id"],
                "technique_name":mappings[mid]["technique_name"],"tactic_ids":mappings[mid]["tactic_ids"],
                "attack_version":mappings[mid]["attack_version"]} for mid in chosen_mappings],
            "truncation":{"truncated":truncated,"events_omitted":len(omitted_ids)+unavailable_events,"detections_omitted":0,
                "iocs_omitted":ioc_omitted,"attack_mappings_omitted":mapping_omitted,"raw_characters_omitted":raw_omitted,
                "detection_characters_omitted":detection_chars_omitted,
                "category_omissions":{"events":len(omitted_ids)+unavailable_events,"iocs":ioc_omitted,"attack_mappings":mapping_omitted,"detection_characters":detection_chars_omitted}}}
        # Drop only non-mandatory event details and raw text deterministically until bounded.
        packet,chosen_events=self._bound_packet(packet,chosen_events,selected,alias_map)
        present={item["alias"] for key in ("detections","events","iocs","attack_mappings") for item in packet[key]}
        present.update(alias for det in packet["detections"] for alias in det["events"])
        alias_map={alias:row for alias,row in alias_map.items() if alias in present}
        evidence_hash=hashlib.sha256(canonical_json(packet).encode("utf-8")).hexdigest()
        internal={"model_packet":packet,"alias_map":alias_map}
        type_rows={alias_map[item["alias"]]["id"]:{"event_type":item["event_type"]} for item in packet["events"]}
        detection_types={did:{"rule_id":detection_rows[did]["rule_id"]} for did in detection_ids}
        return {"packet":packet,"packet_json":canonical_json(internal),"alias_map":alias_map,
            "evidence_hash":evidence_hash,"packet_bytes":len(canonical_json(packet).encode("utf-8")),
            "events_count":len(packet["events"]),"detections_count":len(detection_ids),
            "iocs_count":len(chosen_iocs),"attack_count":len(chosen_mappings),
            "truncation":packet["truncation"],"incident_title":sanitize_text(incident.get("title") or incident_id),
            "detection_rows":detection_types,"event_rows":type_rows}

    @staticmethod
    def _ids(c,tables,incident_id,table,column,fallback):
        if table in tables: return sorted({r[0] for r in c.execute(f"SELECT {column} FROM {table} WHERE incident_id=?",(incident_id,))})
        return sorted(set(fallback))

    @staticmethod
    def _timeline(event):
        kind=event["event_type"].replace("_"," ")
        user=f" for user {event['user']}" if event["user"] else ""
        ip=f" from {event['src_ip']}" if event["src_ip"] else ""
        return sanitize_text(f"{kind.title()}{user}{ip}.")

    def _bound_packet(self,packet,chosen,all_selected,alias_map):
        def size(): return len(canonical_json(packet).encode("utf-8"))
        while size()>self.max_packet_bytes:
            raw_events=[e for e in reversed(packet["events"]) if e["raw_excerpt"]]
            if raw_events:
                e=raw_events[0]; packet["truncation"]["raw_characters_omitted"]+=len(e["raw_excerpt"])
                packet["truncation"]["truncated"]=True; e["raw_excerpt"]=""
                continue
            event_aliases={row["alias"] for row in packet["events"]}
            mandatory={}
            for det in packet["detections"]:
                for a in det["events"][:1]: mandatory[a]=True
            if packet["events"]:
                mandatory[packet["events"][0]["alias"]]=True
                mandatory[packet["events"][-1]["alias"]]=True
            removable=next((e for e in reversed(packet["events"]) if e["alias"] not in mandatory),None)
            if removable:
                packet["events"].remove(removable)
                for det in packet["detections"]:
                    det["events"]=[a for a in det["events"] if a!=removable["alias"]]
                packet["truncation"]["events_omitted"]+=1
                packet["truncation"]["category_omissions"]["events"]+=1
                packet["truncation"]["truncated"]=True
                continue
            # Last resort trims bounded display strings while retaining every detection identity.
            trimmed=False
            for det in reversed(packet["detections"]):
                if len(det["title"])>24:
                    old_length=len(det["title"]); det["title"]=det["title"][:max(24,len(det["title"])-128)]
                    removed=old_length-len(det["title"]); packet["truncation"]["detection_characters_omitted"]+=removed
                    packet["truncation"]["category_omissions"]["detection_characters"]+=removed
                    trimmed=True; packet["truncation"]["truncated"]=True; break
            if trimmed: continue
            raise ValueError("minimum evidence packet exceeds configured size limit")
        return packet,chosen

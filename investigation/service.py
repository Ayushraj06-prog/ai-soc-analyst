"""Persisted evidence-bounded Phase 6 investigation orchestration."""
import hashlib
import json
import re
import sqlite3
import time
from datetime import datetime, timezone

from app.config import settings
from database.database import Database
from investigation.output_schema import OutputValidationError, translate_aliases, validate_output
from investigation.packet import EvidencePacketBuilder, canonical_json
from investigation.prompt import PROMPT_VERSION, build_prompt, template_hash
from investigation.provider import OllamaProvider, ProviderError, validate_endpoint
from models.ids import stable_id

PROMPT_SCHEMA_VERSION="phase6.request.v1"
_CONF_RANK={"LOW":0,"low":0,"MEDIUM":1,"medium":1,"HIGH":2,"high":2}
_SENSITIVE=re.compile(r"(?i)([\"']?(?:password|passwd|secret|token|api[_-]?key|authorization)[\"']?\s*[:=]\s*[\"']?)([^\s,;\"']+)")


class InvestigationError(RuntimeError): pass


class InvestigationService:
    def __init__(self, database, *, provider=None, config=None, claim_guard=None):
        self.db=database if isinstance(database,Database) else Database(database)
        self.provider=provider
        self.config={
            "provider":settings.llm_provider,"model":settings.llm_model,"host":settings.ollama_host,
            "allow_remote":settings.allow_remote_llm,"num_ctx":settings.llm_num_ctx,
            "timeout_seconds":settings.llm_timeout_seconds,"max_output_tokens":settings.llm_max_output_tokens,
            "temperature":settings.llm_temperature,"seed":settings.llm_seed,
            "stale_timeout_seconds":settings.llm_stale_timeout_seconds,"max_attempts":settings.llm_max_attempts,
            "max_packet_bytes":settings.llm_packet_max_bytes,"max_events":settings.llm_packet_max_events,
            "max_iocs":settings.llm_packet_max_iocs,"max_mappings":settings.llm_packet_max_mappings,
            "raw_excerpt_chars":settings.llm_raw_excerpt_chars,"max_validation_errors":settings.llm_max_validation_errors,
            "created_by":settings.llm_created_by,"prompt_version":PROMPT_VERSION,"prompt_schema_version":PROMPT_SCHEMA_VERSION,
        }
        if config: self.config.update(config)
        self.claim_guard=claim_guard
        self.config["max_attempts"]=max(1,min(3,int(self.config["max_attempts"])))
        if int(self.config["num_ctx"]) <= int(self.config["max_output_tokens"]): raise ValueError("LLM_NUM_CTX must exceed LLM_MAX_OUTPUT_TOKENS")

    def investigate(self, incident_id, *, force=False, dry_run=False, show_prompt=False, created_by=None):
        """Build a stable packet, optionally preview it, then reserve and execute a run."""
        if not dry_run and not show_prompt:
            self.db.migrate()
        read_db=Database(self.db.path)
        with read_db.read_session() as connection:
            packet_info=self._build_packet(connection,incident_id)
            prompt,marker=self._make_prompt(packet_info["packet"])
            # Enforce an explicit total context budget before any provider request.
            available=int(self.config["num_ctx"])-int(self.config["max_output_tokens"])
            while self._estimate_tokens(prompt)>available and packet_info["packet_bytes"]>1024:
                cap=max(1024,packet_info["packet_bytes"]-max(256,(self._estimate_tokens(prompt)-available)*4))
                packet_info=self._build_packet(connection,incident_id,max_packet_bytes=cap)
                prompt,marker=self._make_prompt(packet_info["packet"])
                if cap==1024 and self._estimate_tokens(prompt)>available: break
            packet_info["estimated_tokens"]=self._estimate_tokens(prompt)
            packet_info["prompt"]=prompt
            packet_info["marker"]=marker
            incident_row=connection.execute("SELECT payload FROM incidents WHERE incident_id=?",(incident_id,)).fetchone()
            incident=json.loads(incident_row["payload"]) if incident_row else {}
        if dry_run or show_prompt:
            return {"status":"dry_run","incident_id":incident_id,"incident":packet_info["incident_title"],"detections":packet_info["detections_count"],
                "events":packet_info["events_count"],"iocs":packet_info["iocs_count"],"attack_mappings":packet_info["attack_count"],
                "evidence_hash":packet_info["evidence_hash"],"packet_size":packet_info["packet_bytes"],
                "estimated_tokens":packet_info["estimated_tokens"],"truncation":packet_info["truncation"],
                "prompt":packet_info["prompt"] if show_prompt else None}
        if self._estimate_tokens(prompt)>int(self.config["num_ctx"])-int(self.config["max_output_tokens"]):
            raise InvestigationError("minimum evidence packet exceeds configured context budget; provider was not called")
        provider_name,model=self._provider_identity(packet_info)
        deterministic=incident.get("confidence","low")
        generation_config=self._generation_config()
        generation_hash=hashlib.sha256(canonical_json(generation_config).encode()).hexdigest()
        investigation_key=stable_id("invkey",incident_id,packet_info["evidence_hash"],template_hash(),provider_name,model,generation_hash,self.config["prompt_schema_version"])
        reserve=self._reserve(investigation_key,incident_id,packet_info,provider_name,model,generation_hash,generation_config,
            force=force,created_by=created_by or self.config["created_by"])
        if reserve["status"]!="reserved": return reserve
        investigation_id=reserve["investigation_id"]
        if not self._has_usable_evidence(packet_info["packet"]):
            result=self._empty_result()
            self._complete(investigation_id,result,packet_info,deterministic,provider="none",ai_unavailable=False)
            return {"status":"completed","investigation_id":investigation_id,"run_number":reserve["run_number"],
                "result":result,"evidence_hash":packet_info["evidence_hash"],"ai_unavailable":False}
        try:
            provider=self.provider or self._default_provider(provider_name,model)
            validation_errors=[]; raw_last=""; max_attempts=self._attempt_budget(investigation_key,force=force)
            for attempt_number in range(1,max_attempts+1):
                p,_=self._make_prompt(packet_info["packet"],validation_errors=validation_errors)
                started=self._start_attempt(investigation_id,attempt_number)
                try:
                    raw=provider.generate(p) if hasattr(provider,"generate") else provider(p)
                    raw_last=str(raw)
                    validated=validate_output(raw,packet_info["alias_map"],packet_info["detection_rows"],packet_info["event_rows"],self.claim_guard)
                    translated=translate_aliases(validated,packet_info["alias_map"])
                    attempt_hash=hashlib.sha256(raw_last.encode("utf-8",errors="replace")).hexdigest()
                    self._finish_attempt(investigation_id,attempt_number,"completed",started,[],"",attempt_hash,None)
                    self._complete(investigation_id,translated,packet_info,deterministic,provider=provider_name,
                        ai_unavailable=False,raw_hash=attempt_hash,validation_errors=validation_errors)
                    return self._result_summary(investigation_id,reserve,translated,packet_info,deterministic)
                except OutputValidationError as exc:
                    validation_errors=(validation_errors+exc.errors)[:int(self.config["max_validation_errors"])]
                    raw_hash=hashlib.sha256(raw_last.encode("utf-8",errors="replace")).hexdigest() if raw_last else None
                    excerpt=self._safe_excerpt(raw_last) if raw_last else None
                    self._finish_attempt(investigation_id,attempt_number,"invalid",started,exc.errors,str(exc),raw_hash,excerpt)
                    if attempt_number>=max_attempts or attempt_number>=2: break
                except Exception as exc:
                    error=self._safe_excerpt(str(exc))
                    self._finish_attempt(investigation_id,attempt_number,"failed",started,[],error,
                        hashlib.sha256(raw_last.encode("utf-8",errors="replace")).hexdigest() if raw_last else None,
                        self._safe_excerpt(raw_last) if raw_last else None)
                    if attempt_number>=max_attempts: break
            status="invalid" if validation_errors else "failed"
            last_error="; ".join(validation_errors[-3:]) if validation_errors else "provider unavailable after automatic attempts"
            self._fail(investigation_id,status,last_error,validation_errors,raw_last,provider_name,ai_unavailable=not bool(validation_errors))
            return {"status":status,"investigation_id":investigation_id,"run_number":reserve["run_number"],
                "validation_errors":validation_errors,"last_error":last_error}
        except Exception as exc:
            error=self._safe_excerpt(str(exc))
            self._fail(investigation_id,"failed",error,[],"",provider_name,ai_unavailable=True)
            return {"status":"failed","investigation_id":investigation_id,"run_number":reserve["run_number"],"last_error":error}

    def _build_packet(self,connection,incident_id,max_packet_bytes=None):
        builder=EvidencePacketBuilder(max_events=self.config["max_events"],max_iocs=self.config["max_iocs"],
            max_mappings=self.config["max_mappings"],max_packet_bytes=max_packet_bytes or self.config["max_packet_bytes"],
            raw_excerpt_chars=self.config["raw_excerpt_chars"])
        result=builder.build(connection,incident_id)
        # Keep only packet evidence for deterministic claim compatibility checks.
        detections={}; events={}
        for row in connection.execute("SELECT alert_id,payload FROM alerts"):
            try: p=json.loads(row["payload"])
            except Exception: continue
            detections[row["alert_id"]]={"rule_id":p.get("rule_id")}
        for event in result["packet"]["events"]:
            real_id=result["alias_map"][event["alias"]]["id"]
            # Event types are structured and present in the exact packet.
            events[real_id]={"event_type":event["event_type"]}
        # Map every detection and event alias back to the corresponding types.
        for alias,meta in result["alias_map"].items():
            if meta["type"]=="detection": result["detection_rows"]=detections
            elif meta["type"]=="event": result["event_rows"]=events
        result.setdefault("detection_rows",detections); result.setdefault("event_rows",events)
        return result

    def _generation_config(self):
        return {"temperature":self.config["temperature"],"seed":self.config["seed"],
            "num_ctx":self.config["num_ctx"],"max_output_tokens":self.config["max_output_tokens"],
            "output_schema_version":self.config["prompt_schema_version"],
            "endpoint_hash":hashlib.sha256(str(self.config["host"]).encode()).hexdigest()}

    def _provider_identity(self,packet_info):
        if not self._has_usable_evidence(packet_info["packet"]): return "none",""
        return str(self.config["provider"]),str(self.config["model"])

    def _default_provider(self,provider,model):
        if provider.lower()!="ollama": raise ProviderError(f"unsupported provider: {provider}")
        validate_endpoint(self.config["host"],self.config["allow_remote"])
        return OllamaProvider(model=model,host=self.config["host"],timeout=self.config["timeout_seconds"],
            num_ctx=self.config["num_ctx"],temperature=self.config["temperature"],seed=self.config["seed"],
            max_output_tokens=self.config["max_output_tokens"],allow_remote=self.config["allow_remote"])

    def _reserve(self,key,incident_id,packet,provider,model,generation_hash,generation_config,*,force,created_by):
        now=datetime.now(timezone.utc); now_iso=now.isoformat()
        self.db.migrate()
        with self.db.session() as c:
            c.execute("BEGIN IMMEDIATE")
            rows=c.execute("SELECT * FROM investigations WHERE investigation_key=? ORDER BY run_number DESC",(key,)).fetchall()
            rows=[dict(r) for r in rows]
            for row in rows:
                if row["status"]=="running":
                    age=(now-datetime.fromisoformat(row["started_at"])).total_seconds()
                    if age>int(self.config["stale_timeout_seconds"]):
                        c.execute("UPDATE investigations SET status='stale',last_error='stale running investigation timed out',completed_at=? WHERE investigation_id=?",(now_iso,row["investigation_id"]))
                        c.execute("UPDATE investigation_attempts SET status='failed',completed_at=?,error='parent investigation became stale' WHERE investigation_id=? AND status='running'",(now_iso,row["investigation_id"]))
                    else:
                        return {"status":"already_running","investigation_id":row["investigation_id"],"run_number":row["run_number"]}
            rows=c.execute("SELECT * FROM investigations WHERE investigation_key=? ORDER BY run_number DESC",(key,)).fetchall()
            rows=[dict(r) for r in rows]
            if not force:
                completed=next((r for r in rows if r["status"]=="completed"),None)
                if completed:
                    return {"status":"reused","investigation_id":completed["investigation_id"],"run_number":completed["run_number"],"result":json.loads(completed["result_json"]),"evidence_hash":completed["evidence_hash"]}
                used=sum(int(r["attempt_count"]) for r in rows)
                if used>=int(self.config["max_attempts"]):
                    return {"status":"retry_limit","investigation_id":rows[0]["investigation_id"] if rows else None,"message":"automatic investigation retry limit reached; use --force for an explicit new run"}
            run_number=max((r["run_number"] for r in rows),default=0)+1
            investigation_id=stable_id("invest",key,run_number)
            # Unique key and run number plus BEGIN IMMEDIATE serialize concurrent reserves.
            c.execute("""INSERT INTO investigations(investigation_id,investigation_key,run_number,incident_id,status,provider,model,
                prompt_version,prompt_template_hash,generation_config_hash,generation_config_json,prompt_schema_version,evidence_hash,
                packet_json,alias_map_json,deterministic_confidence,attempt_count,created_by,started_at)
                VALUES(?,?,?,?,'running',?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (investigation_id,key,run_number,incident_id,provider,model,self.config["prompt_version"],template_hash(),generation_hash,
                 canonical_json(generation_config),self.config["prompt_schema_version"],packet["evidence_hash"],packet["packet_json"],
                 canonical_json(packet["alias_map"]),"low",0,created_by,now_iso))
        return {"status":"reserved","investigation_id":investigation_id,"run_number":run_number}

    def _attempt_budget(self,key,force=False):
        if force: return int(self.config["max_attempts"])
        with self.db.read_session() as c:
            row=c.execute("SELECT COALESCE(SUM(attempt_count),0) FROM investigations WHERE investigation_key=?",(key,)).fetchone()
        return max(0,int(self.config["max_attempts"])-int(row[0]))

    def _start_attempt(self,investigation_id,number):
        now=datetime.now(timezone.utc).isoformat(); attempt_id=stable_id("invatt",investigation_id,number)
        with self.db.session() as c:
            c.execute("INSERT INTO investigation_attempts(attempt_id,investigation_id,attempt_number,status,started_at) VALUES(?,?,?,'running',?)",
                      (attempt_id,investigation_id,number,now))
            c.execute("UPDATE investigations SET attempt_count=attempt_count+1 WHERE investigation_id=?",(investigation_id,))
        return now

    def _finish_attempt(self,investigation_id,number,status,started,errors,error,raw_hash,excerpt):
        now=datetime.now(timezone.utc).isoformat()
        with self.db.session() as c:
            c.execute("UPDATE investigation_attempts SET status=?,completed_at=?,validation_errors=?,error=?,raw_output_hash=?,raw_output_excerpt=? WHERE investigation_id=? AND attempt_number=?",
                (status,now,canonical_json(errors[:int(self.config["max_validation_errors"])]),error[:1000],raw_hash,excerpt,investigation_id,number))
            c.execute("UPDATE investigations SET last_error=?,validation_errors=? WHERE investigation_id=?",
                (error[:1000],canonical_json(errors[:int(self.config["max_validation_errors"])]),investigation_id))

    def _complete(self,investigation_id,result,packet,deterministic,*,provider,ai_unavailable,raw_hash=None,validation_errors=None):
        ai_conf=result.get("confidence","low"); warning=_CONF_RANK.get(ai_conf,0)>_CONF_RANK.get(deterministic,0)
        now=datetime.now(timezone.utc).isoformat()
        with self.db.session() as c:
            row=c.execute("SELECT alias_map_json FROM investigations WHERE investigation_id=?",(investigation_id,)).fetchone()
            alias_map=json.loads(row[0]) if row else {}
            self._store_evidence(c,investigation_id,result,alias_map)
            c.execute("UPDATE investigations SET status='completed',provider=?,result_json=?,deterministic_confidence=?,ai_confidence=?,confidence_warning=?,ai_unavailable=?,raw_output_hash=?,raw_output_excerpt=NULL,validation_errors=?,last_error='',completed_at=? WHERE investigation_id=?",
                (provider,canonical_json(result),str(deterministic).lower(),ai_conf,int(warning),int(ai_unavailable),raw_hash,
                 canonical_json((validation_errors or [])[:int(self.config["max_validation_errors"])]),now,investigation_id))

    def _store_evidence(self,c,investigation_id,result,alias_map):
        c.execute("DELETE FROM investigation_evidence WHERE investigation_id=?",(investigation_id,))
        groups=(("key_findings","finding"),("supported_claims","finding"),("attack_progression","finding"),
                ("ioc_assessment","finding"),("mitre_assessment","finding"),("recommended_actions","recommendation"),
                ("uncertainties","uncertainty"),("limitations","limitation"))
        for key,category in groups:
            for n,item in enumerate(result.get(key,[])):
                finding_id=stable_id("ifind",investigation_id,key,n)
                refs=item.get("evidence",[])
                special=item.get("ioc") or item.get("mapping")
                if special: refs=[special]+refs
                for real_id in refs:
                    evidence_type=next((meta["type"].upper() for meta in alias_map.values() if meta["id"]==real_id),"UNKNOWN")
                    link_id=stable_id("invrel",investigation_id,finding_id,evidence_type,real_id,category)
                    c.execute("""INSERT OR IGNORE INTO investigation_evidence
                        (id,investigation_id,finding_id,finding_category,evidence_type,evidence_id,relationship,basis,confidence,priority,action_type)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?)""",(link_id,investigation_id,finding_id,category,evidence_type,real_id,
                            "supports" if category!="recommendation" else "justifies",item.get("basis",""),item.get("confidence",""),
                            item.get("priority",""),item.get("action_type","")))

    def _fail(self,investigation_id,status,error,validation_errors,raw_output,provider,*,ai_unavailable):
        now=datetime.now(timezone.utc).isoformat(); raw=raw_output or ""
        raw_hash=hashlib.sha256(raw.encode("utf-8",errors="replace")).hexdigest() if raw else None
        excerpt=self._safe_excerpt(raw) if raw else None
        with self.db.session() as c:
            c.execute("UPDATE investigations SET status=?,last_error=?,validation_errors=?,raw_output_hash=?,raw_output_excerpt=?,ai_unavailable=?,completed_at=? WHERE investigation_id=?",
                (status,error[:1000],canonical_json(validation_errors[:int(self.config["max_validation_errors"])]),raw_hash,excerpt,int(ai_unavailable),now,investigation_id))

    @staticmethod
    def _safe_excerpt(raw):
        from investigation.output_schema import sanitize_text
        raw=re.sub(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@",r"\1[REDACTED]@",str(raw))
        raw=_SENSITIVE.sub(lambda m:f"{m.group(1)}=[REDACTED]",raw)
        return sanitize_text(raw)[:4000]

    @staticmethod
    def _empty_result():
        return {"summary":"Insufficient evidence for AI investigation.","attack_narrative":"","timeline_assessment":"",
            "key_findings":[],"supported_claims":[],"attack_progression":[],"ioc_assessment":[],"mitre_assessment":[],
            "uncertainties":[],"recommended_actions":[],"confidence":"low",
            "limitations":[{"text":"No usable linked detection, event, IOC, or ATT&CK evidence was available.","basis":"unknown","confidence":"low","evidence":[]}]}

    @staticmethod
    def _has_usable_evidence(packet):
        return bool(packet["detections"] or packet["events"] or packet["iocs"] or packet["attack_mappings"])

    @staticmethod
    def _estimate_tokens(prompt): return (len(prompt.encode("utf-8"))+3)//4

    @staticmethod
    def _make_prompt(packet,validation_errors=None):
        return build_prompt(packet,validation_errors=validation_errors)

    @staticmethod
    def _result_summary(investigation_id,reserve,result,packet,deterministic):
        warning=_CONF_RANK.get(result.get("confidence"),0)>_CONF_RANK.get(deterministic,0)
        return {"status":"completed","investigation_id":investigation_id,"run_number":reserve["run_number"],
            "result":result,"evidence_hash":packet["evidence_hash"],"confidence_warning":warning}

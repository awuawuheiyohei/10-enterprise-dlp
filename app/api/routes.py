"""
DLP API Routes
- Dashboard / Rules / Detect / Incidents / ServiceNow / CEF / Audit
"""
import json
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Body, Query
from pydantic import BaseModel, Field

from ..models.db import get_conn, init_db, row_to_dict, rows_to_dicts, write_audit, db_connection
from ..models.engine import (
    DLPEngine, build_servicenow_ticket, build_cef_event,
    DEFAULT_RULES as DEFAULT_RULES_DATA,
)
from ..models.rules_data import (
    DEFAULT_RULES, CLASSIFICATION_LEVELS, CHANNELS, DEFAULT_CHANNEL_ACTIONS,
    stats as rules_stats,
)
from ..models.seed import seed_all

router = APIRouter()
_engine: Optional[DLPEngine] = None


def get_engine() -> DLPEngine:
    global _engine
    if _engine is None:
        _engine = _load_engine_from_db()
    return _engine


def _load_engine_from_db() -> DLPEngine:
    conn = get_conn()
    try:
        rows = rows_to_dicts(conn.execute("SELECT * FROM dlp_rules").fetchall())
    finally:
        conn.close()
    rules = []
    for r in rows:
        try:
            ca = json.loads(r["channel_actions"]) if r["channel_actions"] else {}
        except Exception:
            ca = {}
        rules.append({
            "rule_id": r["rule_id"],
            "rule_name": r["rule_name"],
            "classification": r["classification"],
            "category": r["category"],
            "detector_type": r["detector_type"],
            "detector_payload": r["detector_payload"],
            "match_threshold": r["match_threshold"],
            "enabled": r["enabled"],
            "channel_actions": ca,
            "description": r["description"],
        })
    return DLPEngine(rules)


def rebuild_engine():
    global _engine
    _engine = _load_engine_from_db()


# ============================================
# Pydantic Schemas
# ============================================
class DetectRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000)
    channel: str = "WEB_UPLOAD"
    actor: str = "employee"
    source_label: Optional[str] = None
    record: bool = True


class RuleCreate(BaseModel):
    rule_id: str
    rule_name: str
    classification: str
    category: str
    detector_type: str
    detector_payload: str = ""
    match_threshold: int = 1
    enabled: bool = True
    channel_actions: dict
    description: Optional[str] = None


# ============================================
# Dashboard
# ============================================
@router.get("/dashboard/summary")
async def dashboard_summary():
    init_db()
    conn = get_conn()
    n_rules = conn.execute("SELECT COUNT(*) FROM dlp_rules WHERE enabled=1").fetchone()[0]
    n_incidents = conn.execute("SELECT COUNT(*) FROM dlp_incidents").fetchone()[0]
    by_severity = rows_to_dicts(conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM dlp_incidents GROUP BY severity ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END"
    ).fetchall())
    by_channel = rows_to_dicts(conn.execute(
        "SELECT channel, COUNT(*) as cnt FROM dlp_incidents GROUP BY channel ORDER BY cnt DESC"
    ).fetchall())
    by_action = rows_to_dicts(conn.execute(
        "SELECT action_taken, COUNT(*) as cnt FROM dlp_incidents GROUP BY action_taken"
    ).fetchall())
    by_class = rows_to_dicts(conn.execute(
        "SELECT classification, COUNT(*) as cnt FROM dlp_incidents GROUP BY classification"
    ).fetchall())
    n_blocked = conn.execute("SELECT COUNT(*) FROM dlp_incidents WHERE action_taken='BLOCK'").fetchone()[0]
    n_sn = conn.execute("SELECT COUNT(*) FROM servicenow_tickets").fetchone()[0]
    n_sn_new = conn.execute("SELECT COUNT(*) FROM servicenow_tickets WHERE state='NEW'").fetchone()[0]
    return {
        "rules_enabled": n_rules,
        "incidents_total": n_incidents,
        "by_severity": by_severity,
        "by_channel": by_channel,
        "by_action": by_action,
        "by_classification": by_class,
        "blocked_count": n_blocked,
        "servicenow": {"total": n_sn, "new": n_sn_new},
    }


# ============================================
# Rules
# ============================================
@router.get("/rules")
async def list_rules(classification: Optional[str] = None, enabled: Optional[bool] = None):
    init_db()
    conn = get_conn()
    sql = "SELECT * FROM dlp_rules WHERE 1=1"
    params = []
    if classification:
        sql += " AND classification=?"
        params.append(classification)
    if enabled is not None:
        sql += " AND enabled=?"
        params.append(1 if enabled else 0)
    sql += " ORDER BY rule_id"
    rows = rows_to_dicts(conn.execute(sql, params).fetchall())
    for r in rows:
        try:
            r["channel_actions"] = json.loads(r["channel_actions"]) if r["channel_actions"] else {}
        except Exception:
            r["channel_actions"] = {}
    return {"count": len(rows), "items": rows, "classification_levels": CLASSIFICATION_LEVELS}


@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM dlp_rules WHERE rule_id=?", (rule_id,)).fetchone()
    if not row:
        raise HTTPException(404, f"Rule not found: {rule_id}")
    d = row_to_dict(row)
    try:
        d["channel_actions"] = json.loads(d["channel_actions"]) if d["channel_actions"] else {}
    except Exception:
        d["channel_actions"] = {}
    return d


@router.post("/rules")
async def create_rule(rule: RuleCreate, actor: str = "grc-team"):
    init_db()
    conn = get_conn()
    if rule.classification not in CLASSIFICATION_LEVELS:
        raise HTTPException(400, f"Invalid classification. Allowed: {list(CLASSIFICATION_LEVELS.keys())}")
    if conn.execute("SELECT 1 FROM dlp_rules WHERE rule_id=?", (rule.rule_id,)).fetchone():
        raise HTTPException(409, f"Rule ID exists: {rule.rule_id}")
    conn.execute(
        """INSERT INTO dlp_rules (rule_id, rule_name, classification, category,
           detector_type, detector_payload, match_threshold, enabled, channel_actions, description)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (rule.rule_id, rule.rule_name, rule.classification, rule.category,
         rule.detector_type, rule.detector_payload, rule.match_threshold,
         1 if rule.enabled else 0, json.dumps(rule.channel_actions, ensure_ascii=False),
         rule.description)
    )
    write_audit(conn, actor=actor, action="create_rule",
                entity_type="dlp_rules", entity_id=rule.rule_id,
                details={"classification": rule.classification})
    conn.commit(); conn.close()
    rebuild_engine()
    return {"rule_id": rule.rule_id, "status": "created"}


@router.patch("/rules/{rule_id}")
async def toggle_rule(rule_id: str, enabled: bool, actor: str = "grc-team"):
    conn = get_conn()
    if not conn.execute("SELECT 1 FROM dlp_rules WHERE rule_id=?", (rule_id,)).fetchone():
        raise HTTPException(404, f"Rule not found: {rule_id}")
    conn.execute("UPDATE dlp_rules SET enabled=? WHERE rule_id=?", (1 if enabled else 0, rule_id))
    write_audit(conn, actor=actor, action="toggle_rule",
                entity_type="dlp_rules", entity_id=rule_id, details={"enabled": enabled})
    conn.commit(); conn.close()
    rebuild_engine()
    return {"rule_id": rule_id, "enabled": enabled}


# ============================================
# Detect
# ============================================
@router.post("/detect")
async def detect(req: DetectRequest):
    if req.channel not in CHANNELS:
        raise HTTPException(400, f"Invalid channel. Allowed: {CHANNELS}")
    init_db()
    eng = get_engine()
    result = eng.detect(req.text, channel=req.channel, actor=req.actor, source_label=req.source_label)

    # ServiceNow + CEF
    sn_ticket = None
    cef_event = None
    if result["needs_servicenow"]:
        sn_ticket = build_servicenow_ticket(result)
    cef_event = build_cef_event(result)

    if req.record:
        conn = get_conn()
        # 先 INSERT incident（FK 依赖）
        conn.execute(
            """INSERT INTO dlp_incidents
               (incident_id, channel, source_label, actor, matched_rules, total_matches,
                severity, classification, action_taken, matched_snippets, raw_text_hash,
                servicenow_ticket_id, cef_event_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (result["incident_id"], req.channel, req.source_label, req.actor,
             json.dumps(result["matched_rules"]), result["total_matches"],
             result["severity"], result["classification"], result["action_taken"],
             json.dumps(result["snippets"], ensure_ascii=False),
             result["text_hash"], None, f"CEF-{result['incident_id']}")
        )
        # 再 INSERT ServiceNow ticket（FK 引用 incident）
        sn_ticket_id = None
        if sn_ticket:
            # 从现有最大 ticket_id 解析下一个号，避免 UNIQUE 冲突
            row = conn.execute(
                "SELECT MAX(CAST(SUBSTR(ticket_id, 5) AS INTEGER)) FROM servicenow_tickets"
            ).fetchone()
            n_next = (row[0] or 0) + 1
            sn_ticket_id = f"SIR-{n_next:04d}"
            sn_ticket["ticket_id"] = sn_ticket_id
            conn.execute(
                """INSERT INTO servicenow_tickets
                   (ticket_id, incident_id, priority, category, short_description,
                    assignment_group, sla_target, state)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'NEW')""",
                (sn_ticket_id, result["incident_id"], sn_ticket["priority"], sn_ticket["category"],
                 sn_ticket["short_description"], sn_ticket["assignment_group"], sn_ticket["sla_target"])
            )
            # UPDATE incident 关联 SN ticket
            conn.execute(
                "UPDATE dlp_incidents SET servicenow_ticket_id=? WHERE incident_id=?",
                (sn_ticket_id, result["incident_id"])
            )
        write_audit(conn, actor=req.actor, action="detect",
                    entity_type="dlp_incidents", entity_id=result["incident_id"],
                    details={"classification": result["classification"], "action": result["action_taken"]})
        conn.commit(); conn.close()

    return {
        "result": result,
        "servicenow_ticket": sn_ticket,
        "cef_event": cef_event,
    }


# ============================================
# Incidents
# ============================================
@router.get("/incidents")
async def list_incidents(severity: Optional[str] = None, channel: Optional[str] = None,
                         classification: Optional[str] = None, limit: int = Query(50, ge=1, le=500)):
    init_db()
    conn = get_conn()
    sql = "SELECT * FROM dlp_incidents WHERE 1=1"
    params = []
    if severity:
        sql += " AND severity=?"
        params.append(severity)
    if channel:
        sql += " AND channel=?"
        params.append(channel)
    if classification:
        sql += " AND classification=?"
        params.append(classification)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = rows_to_dicts(conn.execute(sql, params).fetchall())
    for r in rows:
        try:
            r["matched_rules"] = json.loads(r["matched_rules"]) if r["matched_rules"] else {}
            r["matched_snippets"] = json.loads(r["matched_snippets"]) if r["matched_snippets"] else []
        except Exception:
            pass
    return {"count": len(rows), "items": rows}


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM dlp_incidents WHERE incident_id=?", (incident_id,)).fetchone()
    if not row:
        raise HTTPException(404, f"Incident not found: {incident_id}")
    d = row_to_dict(row)
    try:
        d["matched_rules"] = json.loads(d["matched_rules"]) if d["matched_rules"] else {}
        d["matched_snippets"] = json.loads(d["matched_snippets"]) if d["matched_snippets"] else []
    except Exception:
        pass
    # Join ServiceNow ticket
    if d.get("servicenow_ticket_id"):
        sn = conn.execute("SELECT * FROM servicenow_tickets WHERE ticket_id=?",
                          (d["servicenow_ticket_id"],)).fetchone()
        d["servicenow"] = row_to_dict(sn) if sn else None
    return d


# ============================================
# ServiceNow
# ============================================
@router.get("/servicenow/tickets")
async def list_tickets(state: Optional[str] = None, priority: Optional[str] = None):
    init_db()
    conn = get_conn()
    sql = "SELECT * FROM servicenow_tickets WHERE 1=1"
    params = []
    if state:
        sql += " AND state=?"
        params.append(state)
    if priority:
        sql += " AND priority=?"
        params.append(priority)
    sql += " ORDER BY created_at DESC"
    rows = rows_to_dicts(conn.execute(sql, params).fetchall())
    return {"count": len(rows), "items": rows}


@router.post("/servicenow/tickets/{ticket_id}/resolve")
async def resolve_ticket(ticket_id: str, actor: str = "grc-team"):
    conn = get_conn()
    if not conn.execute("SELECT 1 FROM servicenow_tickets WHERE ticket_id=?", (ticket_id,)).fetchone():
        raise HTTPException(404, f"Ticket not found: {ticket_id}")
    conn.execute("UPDATE servicenow_tickets SET state='RESOLVED' WHERE ticket_id=?", (ticket_id,))
    write_audit(conn, actor=actor, action="resolve_ticket",
                entity_type="servicenow_tickets", entity_id=ticket_id, details={})
    conn.commit(); conn.close()
    return {"ticket_id": ticket_id, "state": "RESOLVED"}


# ============================================
# Audit + Admin
# ============================================
@router.get("/audit")
async def list_audit(limit: int = Query(50, ge=1, le=500)):
    init_db()
    conn = get_conn()
    rows = rows_to_dicts(conn.execute(
        "SELECT * FROM audit_trail ORDER BY occurred_at DESC LIMIT ?", (limit,)).fetchall())
    return {"count": len(rows), "items": rows}


@router.post("/admin/seed")
async def admin_seed(actor: str = "grc-team"):
    init_db()
    stats = seed_all(verbose=False)
    rebuild_engine()
    conn = get_conn()
    write_audit(conn, actor=actor, action="reseed",
                entity_type="system", entity_id="all", details=stats)
    conn.commit(); conn.close()
    return {"status": "ok", "stats": stats}

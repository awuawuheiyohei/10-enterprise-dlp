"""Seed DLP rules + sample incidents"""
import json
from .db import get_conn, init_db
from .rules_data import DEFAULT_RULES, stats as rules_stats
from .engine import DLPEngine, build_servicenow_ticket, build_cef_event


def seed_rules(verbose=False):
    init_db()
    conn = get_conn()
    # FK 依赖：先删引用方
    conn.execute("DELETE FROM servicenow_tickets")
    conn.execute("DELETE FROM dlp_incidents")
    conn.execute("DELETE FROM dlp_rules")
    conn.execute("DELETE FROM audit_trail")

    inserted = 0
    for r in DEFAULT_RULES:
        conn.execute(
            """INSERT INTO dlp_rules (rule_id, rule_name, classification, category,
               detector_type, detector_payload, match_threshold, enabled, channel_actions, description)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (r["rule_id"], r["rule_name"], r["classification"], r["category"],
             r["detector_type"], r["detector_payload"], r["match_threshold"],
             1, json.dumps(r["channel_actions"], ensure_ascii=False), r["description"])
        )
        inserted += 1
    conn.commit()
    if verbose:
        print(f"[+] Seeded {inserted} DLP rules")
        print(f"[+] Stats: {rules_stats()}")
    return inserted


def seed_demo_incidents(verbose=False):
    """Seed 几个示例 incident 用于 Dashboard 演示"""
    conn = get_conn()
    eng = DLPEngine(DEFAULT_RULES)

    samples = [
        ("INC-DEMO-01", "Clean public text", "WEB_UPLOAD", "alice@tripbiz.com", "marketing_blog.md",
         "Hello world, this is a public blog post about our product."),
        ("INC-DEMO-02", "Customer PII leak via email", "OUTBOUND_EMAIL", "bob@tripbiz.com",
         "Subject: Re: Customer data",
         "Customer ID 11010519491231002X, phone 13800138000, please process."),
        ("INC-DEMO-03", "Credit card in Slack message", "WEB_UPLOAD", "carol@tripbiz.com",
         "slack_msg.txt",
         "Just charged the customer card 4532-0151-1283-0366"),
        ("INC-DEMO-04", "AWS keys to GitHub", "WEB_UPLOAD", "dave@tripbiz.com",
         "github_commit.txt",
         "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
        ("INC-DEMO-05", "GitHub PAT leak", "OUTBOUND_EMAIL", "eve@tripbiz.com",
         "msg.txt",
         "Here's my token: ghp_abc123def456ghi789jkl012mno345pqr678"),
    ]
    # 6-tuple unpacking: (iid, label, channel, actor, source, payload)
    inserted_incidents = 0
    for iid, label, channel, actor, source, payload in samples:
        det = eng.detect(payload, channel=channel, actor=actor, source_label=source)
        # 用固定 incident_id（demo）
        det["incident_id"] = iid

        snippets_json = json.dumps(det["snippets"], ensure_ascii=False)
        # 先 INSERT incident + commit（让 SN ticket FK 找得到）
        conn.execute(
            """INSERT INTO dlp_incidents
               (incident_id, channel, source_label, actor, matched_rules, total_matches,
                severity, classification, action_taken, matched_snippets, raw_text_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (iid, channel, source, actor, json.dumps(det["matched_rules"]),
             det["total_matches"], det["severity"], det["classification"],
             det["action_taken"], snippets_json, det["text_hash"])
        )
        conn.commit()
        inserted_incidents += 1

        # Create ServiceNow ticket if needed
        if det["needs_servicenow"]:
            ticket = build_servicenow_ticket(det)
            ticket_id = f"SIR-{inserted_incidents:04d}"
            ticket["ticket_id"] = ticket_id
            conn.execute(
                """INSERT INTO servicenow_tickets
                   (ticket_id, incident_id, priority, category, short_description,
                    assignment_group, sla_target, state)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'NEW')""",
                (ticket_id, iid, ticket["priority"], ticket["category"],
                 ticket["short_description"], ticket["assignment_group"],
                 ticket["sla_target"])
            )
            conn.commit()
            # Update incident with SN ticket id
            conn.execute(
                "UPDATE dlp_incidents SET servicenow_ticket_id=? WHERE incident_id=?",
                (ticket_id, iid)
            )
            conn.commit()

    conn.commit()
    if verbose:
        print(f"[+] Seeded {inserted_incidents} demo incidents + ServiceNow tickets")
    return inserted_incidents


def seed_all(verbose=False):
    n_rules = seed_rules(verbose=verbose)
    n_incidents = seed_demo_incidents(verbose=verbose)
    return {"rules": n_rules, "incidents": n_incidents}


if __name__ == "__main__":
    print(seed_all(verbose=True))

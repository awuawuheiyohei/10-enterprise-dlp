"""
DLP 核心引擎
- detect(text, channel) -> {matched_rules, severity, classification, action, snippets, ...}
- 策略评估：detector 命中 → rule match_threshold → channel action
- 严重度映射：RESTRICTED → CRITICAL, CONFIDENTIAL → HIGH, INTERNAL → MEDIUM, PUBLIC → LOW
"""
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple

from .validators import ContentValidators, PatternExtractors, mask_value
from .rules_data import (
    DEFAULT_RULES,
    CLASSIFICATION_LEVELS,
    DEFAULT_CHANNEL_ACTIONS,
    CHANNELS,
)


# detector_type -> extractor function
DETECTOR_MAP = {
    "CHINESE_ID": PatternExtractors.extract_chinese_ids,
    "LUHN_CARD": PatternExtractors.extract_credit_cards,
    "AWS_KEY": PatternExtractors.extract_aws_keys,
    "GITHUB_TOKEN": PatternExtractors.extract_github_tokens,
    "OPENAI_KEY": PatternExtractors.extract_openai_keys,
    "PRIVATE_KEY": PatternExtractors.extract_private_keys,
    "DB_CONN_STRING": PatternExtractors.extract_db_connection_strings,
    "EMAIL": PatternExtractors.extract_emails,
    "PHONE": PatternExtractors.extract_phones,
}

CLASSIFICATION_TO_SEVERITY = {
    "PUBLIC": "LOW",
    "INTERNAL": "MEDIUM",
    "CONFIDENTIAL": "HIGH",
    "RESTRICTED": "CRITICAL",
}


# ============================================
# Detection Engine
# ============================================
class DLPEngine:
    def __init__(self, rules: Optional[List[Dict[str, Any]]] = None):
        self.rules = rules if rules is not None else DEFAULT_RULES

    def _run_detector(self, rule: Dict[str, Any], text: str) -> List[Tuple[int, int, str]]:
        fn = DETECTOR_MAP.get(rule["detector_type"])
        if not fn:
            return []
        return fn(text)

    def detect(self, text: str, channel: str, actor: str = "employee",
               source_label: Optional[str] = None) -> Dict[str, Any]:
        """对单段文本执行全部 enabled 规则，输出 incident 评估"""
        if channel not in CHANNELS:
            raise ValueError(f"Invalid channel: {channel}. Allowed: {CHANNELS}")

        matched_rules: Dict[str, int] = {}  # rule_id -> count
        all_snippets: List[Dict[str, Any]] = []
        classifications_hit = set()

        for rule in self.rules:
            if not rule.get("enabled", 1):
                continue
            hits = self._run_detector(rule, text)
            count = len(hits)
            if count >= rule["match_threshold"]:
                matched_rules[rule["rule_id"]] = count
                classifications_hit.add(rule["classification"])
                for start, end, value in hits[:5]:  # 最多 5 条 snippet / 规则
                    all_snippets.append({
                        "rule_id": rule["rule_id"],
                        "category": rule["category"],
                        "classification": rule["classification"],
                        "value_masked": mask_value(value),
                        "value_length": len(value),
                        "position": start,
                    })

        # 评估最终 classification (取最高)
        highest_class = _highest_classification(classifications_hit)

        # 评估最终 action (按 channel 取对应 action)
        action_taken = self._evaluate_action(channel, classifications_hit)

        # 评估 severity
        severity = CLASSIFICATION_TO_SEVERITY.get(highest_class, "LOW")

        # SHA-256 of raw text (no payload stored)
        text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

        # 是否需要创建 ServiceNow ticket (RESTRICTED 或 CONFIDENTIAL with >= threshold)
        needs_sn = (highest_class == "RESTRICTED") or (
            highest_class == "CONFIDENTIAL" and any(c >= 5 for c in matched_rules.values())
        )

        return {
            "incident_id": f"INC-{uuid.uuid4().hex[:12]}",
            "channel": channel,
            "source_label": source_label,
            "actor": actor,
            "matched_rules": matched_rules,
            "total_matches": sum(matched_rules.values()),
            "classification": highest_class,
            "severity": severity,
            "action_taken": action_taken,
            "snippets": all_snippets,
            "text_hash": text_hash,
            "needs_servicenow": needs_sn,
            "classification_levels_hit": sorted(classifications_hit),
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

    def _evaluate_action(self, channel: str, classifications_hit: set) -> str:
        """按 channel + 命中规则的 channel_actions 决定 action（rule-level 优先）"""
        if not classifications_hit:
            return "ALLOW"
        highest = _highest_classification(classifications_hit)
        # 优先使用匹配规则的 channel_actions（最严格的 rule 决定 action）
        for rule in self.rules:
            if not rule.get("enabled", 1):
                continue
            if rule["classification"] == highest:
                ca = rule.get("channel_actions", {})
                act = ca.get(channel)
                if act:
                    return act
        # Fallback 到默认表
        return DEFAULT_CHANNEL_ACTIONS.get(highest, {}).get(channel, "ALLOW")


def _highest_classification(classifications: set) -> str:
    """PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED"""
    if "RESTRICTED" in classifications:
        return "RESTRICTED"
    if "CONFIDENTIAL" in classifications:
        return "CONFIDENTIAL"
    if "INTERNAL" in classifications:
        return "INTERNAL"
    return "PUBLIC"


# ============================================
# ServiceNow ticket builder (mock)
# ============================================
def build_servicenow_ticket(incident: Dict[str, Any], sla_minutes: int = 60) -> Dict[str, Any]:
    """生成 ServiceNow Security Incident (SIR) payload"""
    classification = incident["classification"]
    severity = incident["severity"]

    # 优先级映射
    priority_map = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P3"}
    priority = priority_map.get(severity, "P3")

    # SLA
    sla_target = (datetime.now(timezone.utc) + timedelta(minutes=sla_minutes)).isoformat()

    # 描述
    snippet_summary = ", ".join(set(s["category"] for s in incident["snippets"][:5]))
    short_desc = f"DLP {priority} — {classification} detected on {incident['channel']}"

    worknotes = [
        f"Incident ID: {incident['incident_id']}",
        f"Channel: {incident['channel']}",
        f"Source: {incident.get('source_label', 'N/A')}",
        f"Actor: {incident['actor']}",
        f"Classification: {classification}",
        f"Severity: {severity}",
        f"Total matches: {incident['total_matches']}",
        f"Matched rules: {', '.join(incident['matched_rules'].keys())}",
        f"Categories: {snippet_summary}",
        f"Action taken: {incident['action_taken']}",
        f"Text hash (SHA-256): {incident['text_hash']}",
    ]

    return {
        "ticket_id": None,  # 由调用方分配
        "priority": priority,
        "category": "Data Loss Prevention",
        "assignment_group": "GRC-SecOps",
        "short_description": short_desc,
        "worknotes": worknotes,
        "sla_target": sla_target,
        "state": "NEW",
        "payload_json": {
            "incident_id": incident["incident_id"],
            "priority": priority,
            "category": "Data Loss Prevention",
            "assignment_group": "GRC-SecOps",
            "short_description": short_desc,
            "work_notes": worknotes,
            "sla_target": sla_target,
            "cmdb_ci": incident.get("source_label", "unknown"),
        },
    }


# ============================================
# CEF (Common Event Format) builder (mock)
# ============================================
def build_cef_event(incident: Dict[str, Any]) -> str:
    """生成 SIEM CEF 格式日志 (Splunk / CrowdStrike 可解析)"""
    # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    extension = (
        f"act={incident['action_taken']} "
        f"cs1={incident['channel']} cs1Label=Channel "
        f"cs2={incident['classification']} cs2Label=Classification "
        f"cs3={incident['incident_id']} cs3Label=IncidentID "
        f"cn1={incident['total_matches']} cn1Label=TotalMatches "
        f"suser={incident['actor']} "
        f"shash={incident['text_hash']} "
        f"dvchost=dlp-engine"
    )
    severity = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2}.get(incident["severity"], 1)
    return (
        f"CEF:0|EnterpriseDLP|DLP-Simulation|0.1.0|{incident['classification']}|"
        f"{incident['action_taken']}|{severity}|{extension}"
    )


if __name__ == "__main__":
    eng = DLPEngine()

    samples = [
        ("干净文本", "Hello world, this is a public blog post.", "WEB_UPLOAD"),
        ("1 个手机号", "客户张三电话 13800138000，请回电。", "OUTBOUND_EMAIL"),
        ("3 个手机号", "联系人: 13800138000 / 13911112222 / 13633334444", "OUTBOUND_EMAIL"),
        ("信用卡", "Card: 4532-0151-1283-0366 exp 12/27", "OUTBOUND_EMAIL"),
        ("AWS Key", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "ENDPOINT_USB"),
        ("GitHub PAT", "我的 token: ghp_abc123def456ghi789jkl012mno345pqr678", "WEB_UPLOAD"),
        ("OpenAI Key", "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL", "OUTBOUND_EMAIL"),
        ("Private Key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAA...", "ENDPOINT_USB"),
        ("身份证", "客户身份证 11010519491231002X", "OUTBOUND_EMAIL"),
    ]
    for label, text, channel in samples:
        r = eng.detect(text, channel=channel, source_label=label)
        print(f"\n[{label}] channel={channel}")
        print(f"  matched={r['matched_rules']} total={r['total_matches']}")
        print(f"  classification={r['classification']} severity={r['severity']} action={r['action_taken']}")
        print(f"  needs_servicenow={r['needs_servicenow']}")
        for s in r["snippets"][:3]:
            print(f"    snippet: {s['value_masked']} (rule={s['rule_id']}, len={s['value_length']})")

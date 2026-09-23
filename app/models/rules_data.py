"""
DLP 规则种子数据（PRD 4 级分类分级 + 9 大检测规则）
- 4 级：PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED
- 检测器：detector_type (CHINESE_ID / LUHN_CARD / AWS_KEY / GITHUB_TOKEN / OPENAI_KEY / PRIVATE_KEY / DB_CONN_STRING / EMAIL / PHONE / HIGH_ENTROPY)
"""
from typing import List, Dict, Any


# ============================================
# 4 级分类分级
# ============================================
CLASSIFICATION_LEVELS = {
    "PUBLIC": {
        "level": 1,
        "description": "公开信息，允许无限制外发",
        "default_action": "ALLOW",
    },
    "INTERNAL": {
        "level": 2,
        "description": "企业内部信息，仅限员工与合规承包商在授权系统内使用",
        "default_action": "LOG_ONLY",
    },
    "CONFIDENTIAL": {
        "level": 3,
        "description": "机密信息，涉及客户 PII、员工人事档案、商旅订单",
        "default_action": "WARN_AND_LOG",
    },
    "RESTRICTED": {
        "level": 4,
        "description": "绝密核心资产，包含支付持卡人数据(PCI)、系统高权凭据与核心源码",
        "default_action": "BLOCK_AND_ALERT",
    },
}


# ============================================
# 通道
# ============================================
CHANNELS = ["ENDPOINT_USB", "OUTBOUND_EMAIL", "WEB_UPLOAD", "API_EGRESS"]

# 通道 -> 默认动作
DEFAULT_CHANNEL_ACTIONS = {
    "PUBLIC":      {"ENDPOINT_USB": "ALLOW",     "OUTBOUND_EMAIL": "ALLOW",     "WEB_UPLOAD": "ALLOW",     "API_EGRESS": "ALLOW"},
    "INTERNAL":    {"ENDPOINT_USB": "LOG_ONLY",  "OUTBOUND_EMAIL": "LOG_ONLY",  "WEB_UPLOAD": "LOG_ONLY",  "API_EGRESS": "LOG_ONLY"},
    "CONFIDENTIAL":{"ENDPOINT_USB": "WARN",      "OUTBOUND_EMAIL": "WARN",      "WEB_UPLOAD": "WARN",      "API_EGRESS": "WARN"},
    "RESTRICTED":  {"ENDPOINT_USB": "BLOCK",     "OUTBOUND_EMAIL": "BLOCK",     "WEB_UPLOAD": "BLOCK",     "API_EGRESS": "BLOCK"},
}


# ============================================
# 规则种子
# ============================================
DEFAULT_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "RULE-PII-CN-ID",
        "rule_name": "中国大陆居民身份证 (含 ISO 7064 校验码)",
        "classification": "CONFIDENTIAL",
        "category": "PII",
        "detector_type": "CHINESE_ID",
        "detector_payload": "",
        "match_threshold": 1,
        "channel_actions": {
            "ENDPOINT_USB": "BLOCK",
            "OUTBOUND_EMAIL": "BLOCK",
            "WEB_UPLOAD": "WARN",
            "API_EGRESS": "BLOCK",
        },
        "description": "中国 18 位二代身份证，含 MOD 11-2 加权校验",
    },
    {
        "rule_id": "RULE-PII-CN-PHONE",
        "rule_name": "中国大陆手机号",
        "classification": "CONFIDENTIAL",
        "category": "PII",
        "detector_type": "PHONE",
        "detector_payload": "",
        "match_threshold": 3,
        "channel_actions": {
            "ENDPOINT_USB": "WARN",
            "OUTBOUND_EMAIL": "WARN",
            "WEB_UPLOAD": "LOG_ONLY",
            "API_EGRESS": "WARN",
        },
        "description": "11 位 1[3-9] 开头的手机号",
    },
    {
        "rule_id": "RULE-FIN-CREDIT-CARD",
        "rule_name": "国际信用卡/借记卡号 (Luhn 校验)",
        "classification": "RESTRICTED",
        "category": "FINANCIAL",
        "detector_type": "LUHN_CARD",
        "detector_payload": "",
        "match_threshold": 1,
        "channel_actions": {
            "ENDPOINT_USB": "BLOCK",
            "OUTBOUND_EMAIL": "BLOCK",
            "WEB_UPLOAD": "BLOCK",
            "API_EGRESS": "BLOCK",
        },
        "description": "PCI DSS Req 3.4 — 持卡人数据禁止明文外发",
    },
    {
        "rule_id": "RULE-SEC-AWS-KEY",
        "rule_name": "AWS 访问凭据 (Access Key ID + Secret Key)",
        "classification": "RESTRICTED",
        "category": "CREDENTIAL",
        "detector_type": "AWS_KEY",
        "detector_payload": "",
        "match_threshold": 1,
        "channel_actions": {
            "ENDPOINT_USB": "BLOCK",
            "OUTBOUND_EMAIL": "BLOCK",
            "WEB_UPLOAD": "BLOCK",
            "API_EGRESS": "BLOCK",
        },
        "description": "AKIA[0-9A-Z]{16} + AWS Secret 40 字符",
    },
    {
        "rule_id": "RULE-SEC-GITHUB-TOKEN",
        "rule_name": "GitHub Personal Access Token",
        "classification": "RESTRICTED",
        "category": "CREDENTIAL",
        "detector_type": "GITHUB_TOKEN",
        "detector_payload": "",
        "match_threshold": 1,
        "channel_actions": {
            "ENDPOINT_USB": "BLOCK",
            "OUTBOUND_EMAIL": "BLOCK",
            "WEB_UPLOAD": "BLOCK",
            "API_EGRESS": "BLOCK",
        },
        "description": "ghp_* / github_pat_* 36+ 字符 token",
    },
    {
        "rule_id": "RULE-SEC-OPENAI-KEY",
        "rule_name": "OpenAI API Key",
        "classification": "RESTRICTED",
        "category": "CREDENTIAL",
        "detector_type": "OPENAI_KEY",
        "detector_payload": "",
        "match_threshold": 1,
        "channel_actions": {
            "ENDPOINT_USB": "BLOCK",
            "OUTBOUND_EMAIL": "BLOCK",
            "WEB_UPLOAD": "BLOCK",
            "API_EGRESS": "BLOCK",
        },
        "description": "sk-*, sk-proj-*, sk-svcacct-* 32+ 字符高熵串",
    },
    {
        "rule_id": "RULE-SEC-PRIVATE-KEY",
        "rule_name": "RSA / SSH / EC / DSA Private Key Header",
        "classification": "RESTRICTED",
        "category": "CREDENTIAL",
        "detector_type": "PRIVATE_KEY",
        "detector_payload": "",
        "match_threshold": 1,
        "channel_actions": {
            "ENDPOINT_USB": "BLOCK",
            "OUTBOUND_EMAIL": "BLOCK",
            "WEB_UPLOAD": "BLOCK",
            "API_EGRESS": "BLOCK",
        },
        "description": "-----BEGIN ... PRIVATE KEY-----",
    },
    {
        "rule_id": "RULE-CODE-DB-CONN",
        "rule_name": "数据库连接串（含明文密码）",
        "classification": "RESTRICTED",
        "category": "CODE",
        "detector_type": "DB_CONN_STRING",
        "detector_payload": "",
        "match_threshold": 1,
        "channel_actions": {
            "ENDPOINT_USB": "BLOCK",
            "OUTBOUND_EMAIL": "BLOCK",
            "WEB_UPLOAD": "BLOCK",
            "API_EGRESS": "BLOCK",
        },
        "description": "jdbc/mysql/pgsql/mongodb/redis + 密码",
    },
    {
        "rule_id": "RULE-PII-EMAIL",
        "rule_name": "员工/客户邮箱",
        "classification": "INTERNAL",
        "category": "PII",
        "detector_type": "EMAIL",
        "detector_payload": "",
        "match_threshold": 10,
        "channel_actions": {
            "ENDPOINT_USB": "LOG_ONLY",
            "OUTBOUND_EMAIL": "LOG_ONLY",
            "WEB_UPLOAD": "LOG_ONLY",
            "API_EGRESS": "LOG_ONLY",
        },
        "description": "email regex (>= 10 个触发)",
    },
]


def stats() -> dict:
    return {
        "total_rules": len(DEFAULT_RULES),
        "by_classification": _count_by("classification"),
        "by_category": _count_by("category"),
        "by_detector": _count_by("detector_type"),
    }


def _count_by(field: str) -> dict:
    counts = {}
    for r in DEFAULT_RULES:
        v = r.get(field, "?")
        counts[v] = counts.get(v, 0) + 1
    return counts

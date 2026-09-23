"""DLP Engine - 端到端测试"""
import os
import sys
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from app.main import app
from app.models.db import init_db, DB_PATH
from app.models.validators import ContentValidators, PatternExtractors, mask_value
from app.models.engine import DLPEngine, build_servicenow_ticket, build_cef_event
from app.models.rules_data import (
    DEFAULT_RULES, CLASSIFICATION_LEVELS, CHANNELS, stats as rules_stats,
)
from app.models.seed import seed_all


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    if DB_PATH.exists():
        DB_PATH.unlink()
    init_db()
    seed_all(verbose=False)
    yield


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def engine():
    return DLPEngine(DEFAULT_RULES)


# ============================================
# Validator unit tests
# ============================================
class TestLuhnValidator:
    def test_valid_visa(self):
        assert ContentValidators.validate_luhn("4532-0151-1283-0366") is True
        assert ContentValidators.validate_luhn("4532015112830366") is True

    def test_valid_mastercard(self):
        assert ContentValidators.validate_luhn("5425233430109903") is True

    def test_valid_amex(self):
        assert ContentValidators.validate_luhn("378282246310005") is True

    def test_invalid(self):
        assert ContentValidators.validate_luhn("4532015112830367") is False
        assert ContentValidators.validate_luhn("1234567890123456") is False

    def test_too_short(self):
        assert ContentValidators.validate_luhn("123") is False

    def test_too_long(self):
        assert ContentValidators.validate_luhn("1" * 25) is False


class TestChineseID:
    def test_valid(self):
        # 11010519491231002X 是真实样本（保留校验）
        assert ContentValidators.validate_chinese_id("11010519491231002X") is True

    def test_invalid_check_digit(self):
        # 改最后一位
        assert ContentValidators.validate_chinese_id("110105194912310020") is False

    def test_invalid_format(self):
        assert ContentValidators.validate_chinese_id("12345") is False
        assert ContentValidators.validate_chinese_id("abcdefghijklmnopqr") is False

    def test_invalid_prefix(self):
        assert ContentValidators.validate_chinese_id("01010519491231002X") is False


class TestShannonEntropy:
    def test_low_entropy(self):
        assert ContentValidators.shannon_entropy("aaaa") < 0.1
        assert ContentValidators.shannon_entropy("abcabc") < 2.0

    def test_high_entropy(self):
        assert ContentValidators.shannon_entropy("kJ8mN2pQ9rT4wX7zA1B2C3D4E5") > 4.0

    def test_is_high_entropy(self):
        assert ContentValidators.is_high_entropy("kJ8mN2pQ9rT4wX7zA1B2", min_len=20) is True
        assert ContentValidators.is_high_entropy("short", min_len=20) is False


class TestPatternExtractors:
    def test_credit_card(self):
        hits = PatternExtractors.extract_credit_cards("Card: 4532-0151-1283-0366")
        assert len(hits) == 1
        # masked 不在 extract 输出

    def test_aws_key(self):
        hits = PatternExtractors.extract_aws_keys("AKIAIOSFODNN7EXAMPLE")
        assert len(hits) == 1

    def test_github_token(self):
        hits = PatternExtractors.extract_github_tokens("ghp_abc123def456ghi789jkl012mno345pqr678")
        assert len(hits) == 1

    def test_openai_key(self):
        hits = PatternExtractors.extract_openai_keys("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL")
        assert len(hits) == 1

    def test_private_key(self):
        hits = PatternExtractors.extract_private_keys("-----BEGIN RSA PRIVATE KEY-----")
        assert len(hits) == 1

    def test_db_conn_string(self):
        hits = PatternExtractors.extract_db_connection_strings(
            "jdbc:mysql://db.example.com:3306/mydb?user=admin&password=secret123"
        )
        assert len(hits) >= 1

    def test_phones(self):
        hits = PatternExtractors.extract_phones("13800138000 / 13911112222")
        assert len(hits) == 2

    def test_chinese_id(self):
        hits = PatternExtractors.extract_chinese_ids("客户 ID 11010519491231002X")
        assert len(hits) == 1


class TestMask:
    def test_basic(self):
        # 16 chars: 4 prefix + 4 suffix + 8 middle *
        assert mask_value("4532015112830366") == "4532********0366"

    def test_short(self):
        assert mask_value("abc") == "***"


# ============================================
# Rules data tests
# ============================================
class TestRulesData:
    def test_total(self):
        assert len(DEFAULT_RULES) >= 9

    def test_classification_levels(self):
        assert set(CLASSIFICATION_LEVELS.keys()) == {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}

    def test_channels(self):
        assert "ENDPOINT_USB" in CHANNELS
        assert "OUTBOUND_EMAIL" in CHANNELS
        assert "WEB_UPLOAD" in CHANNELS
        assert "API_EGRESS" in CHANNELS

    def test_stats(self):
        s = rules_stats()
        assert s["total_rules"] == len(DEFAULT_RULES)
        # 至少 2 个 RESTRICTED rules
        assert s["by_classification"].get("RESTRICTED", 0) >= 4


# ============================================
# Engine tests
# ============================================
class TestEngine:
    def test_clean_text(self, engine):
        r = engine.detect("Hello world, public blog post.", channel="WEB_UPLOAD")
        assert r["classification"] == "PUBLIC"
        assert r["severity"] == "LOW"
        assert r["action_taken"] == "ALLOW"
        assert r["needs_servicenow"] is False

    def test_credit_card_blocks(self, engine):
        r = engine.detect("Card: 4532-0151-1283-0366", channel="OUTBOUND_EMAIL")
        assert r["classification"] == "RESTRICTED"
        assert r["severity"] == "CRITICAL"
        assert r["action_taken"] == "BLOCK"
        assert r["needs_servicenow"] is True
        assert "RULE-FIN-CREDIT-CARD" in r["matched_rules"]

    def test_aws_key_blocks(self, engine):
        r = engine.detect("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", channel="ENDPOINT_USB")
        assert r["classification"] == "RESTRICTED"
        assert "RULE-SEC-AWS-KEY" in r["matched_rules"]
        assert r["action_taken"] == "BLOCK"

    def test_github_token(self, engine):
        r = engine.detect("ghp_abc123def456ghi789jkl012mno345pqr678", channel="OUTBOUND_EMAIL")
        assert "RULE-SEC-GITHUB-TOKEN" in r["matched_rules"]

    def test_openai_key(self, engine):
        r = engine.detect("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL", channel="WEB_UPLOAD")
        assert "RULE-SEC-OPENAI-KEY" in r["matched_rules"]

    def test_private_key(self, engine):
        r = engine.detect("-----BEGIN RSA PRIVATE KEY-----\nMIIE...", channel="ENDPOINT_USB")
        assert "RULE-SEC-PRIVATE-KEY" in r["matched_rules"]

    def test_chinese_id_confidential(self, engine):
        r = engine.detect("客户 ID 11010519491231002X", channel="OUTBOUND_EMAIL")
        assert r["classification"] == "CONFIDENTIAL"
        assert r["severity"] == "HIGH"
        assert "RULE-PII-CN-ID" in r["matched_rules"]
        # OUTBOUND_EMAIL 上 CONFIDENTIAL 是 BLOCK
        assert r["action_taken"] == "BLOCK"

    def test_phones_under_threshold(self, engine):
        """1 个手机号 → 阈值 3，未命中"""
        r = engine.detect("联系: 13800138000", channel="WEB_UPLOAD")
        assert "RULE-PII-CN-PHONE" not in r["matched_rules"]

    def test_phones_over_threshold(self, engine):
        """3 个手机号 → 命中阈值"""
        r = engine.detect("13800138000 / 13911112222 / 13633334444", channel="WEB_UPLOAD")
        assert "RULE-PII-CN-PHONE" in r["matched_rules"]

    def test_text_hash_recorded(self, engine):
        r = engine.detect("test text", channel="WEB_UPLOAD")
        assert len(r["text_hash"]) == 64  # SHA-256 hex

    def test_snippet_masking(self, engine):
        r = engine.detect("Card 4532015112830366", channel="WEB_UPLOAD")
        for s in r["snippets"]:
            assert "*" in s["value_masked"]  # 脱敏
            assert "4532015112830366" not in s["value_masked"]  # 不含原文

    def test_invalid_channel(self, engine):
        with pytest.raises(ValueError):
            engine.detect("test", channel="INVALID")


class TestServiceNowTicket:
    def test_p1_for_critical(self):
        incident = {
            "incident_id": "INC-TEST",
            "channel": "OUTBOUND_EMAIL",
            "source_label": "test",
            "actor": "alice",
            "classification": "RESTRICTED",
            "severity": "CRITICAL",
            "total_matches": 1,
            "matched_rules": {"RULE-FIN-CREDIT-CARD": 1},
            "action_taken": "BLOCK",
            "text_hash": "x" * 64,
            "snippets": [{"category": "FINANCIAL"}],
        }
        ticket = build_servicenow_ticket(incident)
        assert ticket["priority"] == "P1"
        assert "RESTRICTED" in ticket["short_description"]
        assert any("INC-TEST" in w for w in ticket["worknotes"])


class TestCEFEvent:
    def test_format(self):
        incident = {
            "incident_id": "INC-TEST",
            "channel": "WEB_UPLOAD",
            "classification": "RESTRICTED",
            "severity": "CRITICAL",
            "action_taken": "BLOCK",
            "total_matches": 1,
            "actor": "alice",
            "text_hash": "abc123",
        }
        cef = build_cef_event(incident)
        assert cef.startswith("CEF:0|")
        assert "EnterpriseDLP" in cef
        assert "RESTRICTED" in cef
        assert "BLOCK" in cef
        assert "act=BLOCK" in cef
        assert "cs3=INC-TEST" in cef
        assert "shash=abc123" in cef


# ============================================
# FastAPI smoke tests
# ============================================
class TestHealth:
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


class TestDashboard:
    def test_summary(self, client):
        r = client.get("/api/dashboard/summary")
        assert r.status_code == 200
        d = r.json()
        assert d["rules_enabled"] >= 9
        assert d["incidents_total"] >= 5  # demo seed
        assert d["servicenow"]["total"] >= 3


class TestRulesAPI:
    def test_list(self, client):
        r = client.get("/api/rules")
        assert r.status_code == 200
        d = r.json()
        assert d["count"] >= 9
        assert "PUBLIC" in d["classification_levels"]

    def test_filter(self, client):
        r = client.get("/api/rules?classification=RESTRICTED")
        assert r.status_code == 200
        d = r.json()
        assert all(r["classification"] == "RESTRICTED" for r in d["items"])

    def test_get_one(self, client):
        r = client.get("/api/rules/RULE-FIN-CREDIT-CARD")
        assert r.status_code == 200
        d = r.json()
        assert d["detector_type"] == "LUHN_CARD"

    def test_create_rule(self, client):
        body = {
            "rule_id": "RULE-TEST-01",
            "rule_name": "Test rule",
            "classification": "INTERNAL",
            "category": "PII",
            "detector_type": "EMAIL",
            "match_threshold": 100,
            "channel_actions": {"WEB_UPLOAD": "LOG_ONLY"},
        }
        r = client.post("/api/rules", json=body)
        assert r.status_code == 200

    def test_create_invalid_class(self, client):
        body = {
            "rule_id": "RULE-BAD",
            "rule_name": "Bad",
            "classification": "INVALID",
            "category": "X",
            "detector_type": "EMAIL",
            "channel_actions": {},
        }
        r = client.post("/api/rules", json=body)
        assert r.status_code == 400

    def test_toggle_rule(self, client):
        r = client.patch("/api/rules/RULE-TEST-01?enabled=false")
        assert r.status_code == 200
        assert r.json()["enabled"] is False
        r = client.patch("/api/rules/RULE-TEST-01?enabled=true")
        assert r.json()["enabled"] is True


class TestDetect:
    def test_clean_text(self, client):
        r = client.post("/api/detect", json={"text": "hello world", "channel": "WEB_UPLOAD", "record": False})
        assert r.status_code == 200
        d = r.json()
        assert d["result"]["classification"] == "PUBLIC"

    def test_credit_card(self, client):
        r = client.post("/api/detect", json={"text": "Card 4532-0151-1283-0366", "channel": "OUTBOUND_EMAIL", "record": True})
        assert r.status_code == 200
        d = r.json()
        assert d["result"]["classification"] == "RESTRICTED"
        assert d["servicenow_ticket"] is not None
        assert d["servicenow_ticket"]["priority"] == "P1"

    def test_invalid_channel(self, client):
        r = client.post("/api/detect", json={"text": "test", "channel": "INVALID", "record": False})
        assert r.status_code == 400

    def test_short_text_rejected(self, client):
        r = client.post("/api/detect", json={"text": "", "channel": "WEB_UPLOAD"})
        assert r.status_code == 422


class TestIncidents:
    def test_list(self, client):
        r = client.get("/api/incidents")
        assert r.status_code == 200
        d = r.json()
        assert d["count"] >= 5

    def test_filter_critical(self, client):
        r = client.get("/api/incidents?severity=CRITICAL")
        assert r.status_code == 200
        d = r.json()
        assert all(i["severity"] == "CRITICAL" for i in d["items"])
        assert d["count"] >= 3

    def test_get_incident_with_sn(self, client):
        r = client.get("/api/incidents/INC-DEMO-03")
        assert r.status_code == 200
        d = r.json()
        assert d["servicenow_ticket_id"] is not None

    def test_get_404(self, client):
        r = client.get("/api/incidents/INC-XYZ")
        assert r.status_code == 404


class TestServiceNow:
    def test_list(self, client):
        r = client.get("/api/servicenow/tickets")
        assert r.status_code == 200
        d = r.json()
        assert d["count"] >= 3

    def test_filter_p1(self, client):
        r = client.get("/api/servicenow/tickets?priority=P1")
        assert r.status_code == 200
        d = r.json()
        assert all(t["priority"] == "P1" for t in d["items"])

    def test_resolve(self, client):
        r = client.get("/api/servicenow/tickets?state=NEW")
        assert r.status_code == 200
        first = r.json()["items"][0]
        tid = first["ticket_id"]
        r = client.post(f"/api/servicenow/tickets/{tid}/resolve")
        assert r.status_code == 200
        assert r.json()["state"] == "RESOLVED"


class TestAdmin:
    def test_seed(self, client):
        r = client.post("/api/admin/seed")
        assert r.status_code == 200
        d = r.json()
        assert d["stats"]["rules"] >= 9
        assert d["stats"]["incidents"] >= 5


class TestStaticUI:
    def test_index(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "DLP" in r.text

-- Enterprise DLP Policy Simulation & Data Classification Engine - SQLite schema (v1.0)
-- 依据 Security_and_GRC_14_Projects_Plan #10 PRD
-- 4 级分类分级 (Public / Internal / Confidential / Restricted)
-- 检测: 中国身份证 + Luhn 信用卡 + Shannon 熵 + AWS/GH/OAI/RSA

-- ============================================
-- 检测规则 (Rule)
-- ============================================
CREATE TABLE IF NOT EXISTS dlp_rules (
    rule_id           TEXT PRIMARY KEY,                  -- RULE-PII-CN-ID
    rule_name         TEXT NOT NULL,
    classification    TEXT NOT NULL,                     -- PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED
    category          TEXT NOT NULL,                     -- PII/FINANCIAL/CREDENTIAL/CODE/CONTRACT
    detector_type     TEXT NOT NULL,                     -- REGEX / LUHN / ID_CHECKSUM / ENTROPY / COMPOSITE
    detector_payload  TEXT NOT NULL,                     -- regex pattern / entropy config
    match_threshold   INTEGER NOT NULL DEFAULT 1,
    enabled           INTEGER NOT NULL DEFAULT 1,
    channel_actions   TEXT NOT NULL,                     -- JSON: {ENDPOINT_USB: BLOCK, OUTBOUND_EMAIL: BLOCK, ...}
    description       TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_rule_class ON dlp_rules(classification);
CREATE INDEX IF NOT EXISTS idx_rule_enabled ON dlp_rules(enabled);

-- ============================================
-- 检测事件 (Incident)
-- ============================================
CREATE TABLE IF NOT EXISTS dlp_incidents (
    incident_id    TEXT PRIMARY KEY,                     -- INC-{uuid12}
    channel        TEXT NOT NULL,                       -- ENDPOINT_USB / OUTBOUND_EMAIL / WEB_UPLOAD / API_EGRESS
    source_label   TEXT,                                -- 文件名 / 邮件主题 / API endpoint
    actor          TEXT NOT NULL DEFAULT 'employee',
    matched_rules  TEXT NOT NULL,                       -- JSON array of rule_ids
    total_matches  INTEGER NOT NULL DEFAULT 0,
    severity       TEXT NOT NULL,                       -- LOW/MEDIUM/HIGH/CRITICAL
    classification TEXT NOT NULL,                       -- 最高分类级别
    action_taken   TEXT NOT NULL,                       -- ALLOW / LOG_ONLY / WARN / BLOCK
    matched_snippets TEXT NOT NULL,                     -- JSON: [{rule_id, type, value_masked, position}]
    raw_text_hash  TEXT,                                -- SHA-256 of raw text (no payload stored)
    servicenow_ticket_id TEXT,                          -- mock ticket id (SIR-{n})
    cef_event_id   TEXT,                                -- CEF event id
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_inc_severity ON dlp_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_inc_channel ON dlp_incidents(channel);
CREATE INDEX IF NOT EXISTS idx_inc_action ON dlp_incidents(action_taken);
CREATE INDEX IF NOT EXISTS idx_inc_created ON dlp_incidents(created_at);

-- ============================================
-- ServiceNow Tickets (Mock)
-- ============================================
CREATE TABLE IF NOT EXISTS servicenow_tickets (
    ticket_id      TEXT PRIMARY KEY,                     -- SIR-{n}
    incident_id    TEXT NOT NULL,
    priority       TEXT NOT NULL,                       -- P1/P2/P3
    category       TEXT NOT NULL,                       -- Data Loss Prevention
    short_description TEXT NOT NULL,
    assignment_group TEXT NOT NULL DEFAULT 'GRC-SecOps',
    sla_target     TEXT NOT NULL,                       -- ISO timestamp
    state          TEXT NOT NULL DEFAULT 'NEW',         -- NEW / IN_PROGRESS / RESOLVED
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (incident_id) REFERENCES dlp_incidents(incident_id)
);

CREATE INDEX IF NOT EXISTS idx_sn_state ON servicenow_tickets(state);
CREATE INDEX IF NOT EXISTS idx_sn_priority ON servicenow_tickets(priority);

-- ============================================
-- 审计 trail
-- ============================================
CREATE TABLE IF NOT EXISTS audit_trail (
    audit_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    entity_type   TEXT,
    entity_id     TEXT,
    details       TEXT,
    occurred_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

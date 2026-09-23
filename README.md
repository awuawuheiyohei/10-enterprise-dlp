# Enterprise DLP Policy Simulation & Data Classification Engine

> **一句话**：4 级分类分级 + Luhn/ID 校验/Entropy 多检测器 + 多通道仿真 + ServiceNow & SIEM CEF 联动
> 对齐 **Senior Cyber Security Analyst** DLP 监控分类职责 + **Senior IT GRC Specialist** ISO 27001 A.8.11 证据职责。

---

## ✨ 状态

**v0.1 完成**（2026-09-23）— 端到端实跑：**62/62 tests PASS**

| 模块 | 完成度 | 备注 |
|---|---|---|
| 4 张表 schema | ✅ | dlp_rules / dlp_incidents / servicenow_tickets / audit_trail |
| 4 级分类分级 | ✅ | PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED |
| 9 条规则种子 | ✅ | PII / FINANCIAL / CREDENTIAL / CODE |
| Luhn 信用卡校验 | ✅ | Visa/MC/Amex/Discover 13-19 位 |
| ISO 7064 中国身份证校验 | ✅ | 18 位 + MOD 11-2 加权校验码 |
| Shannon 熵密钥检测 | ✅ | AWS / GitHub / OpenAI / SSH Private Key |
| DB 连接串检测 | ✅ | jdbc:mysql + query string password + .NET |
| 多通道仿真 | ✅ | ENDPOINT_USB / OUTBOUND_EMAIL / WEB_UPLOAD / API_EGRESS |
| ServiceNow ticket mock | ✅ | P1/P2/P3 + SLA + assignment group |
| SIEM CEF event | ✅ | CEF:0\|...\|severity\|ext 格式 |
| FastAPI 11 endpoints | ✅ | Detect / Rules / Incidents / SN / Audit / Seed |
| Vanilla JS Dashboard 4 tab | ✅ | 0 CDN |
| 端到端测试 | ✅ | **62/62 PASS** |
| GitHub public | ✅ | `awuawuheiyohei/10-enterprise-dlp` |

## 📁 项目结构

```
10-enterprise-dlp/
├── README.md
├── pyproject.toml
├── main.py                     # CLI 入口
├── app/
│   ├── __init__.py            # DB_PATH + LLM helper
│   ├── main.py                # FastAPI app
│   ├── schema.sql             # 4 张表
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py          # 11 endpoints
│   └── models/
│       ├── __init__.py
│       ├── db.py              # SQLite + WAL + busy_timeout
│       ├── validators.py      # Luhn / ISO 7064 / Shannon / extractors
│       ├── rules_data.py      # 9 rules + 4 classification levels
│       ├── engine.py          # DLPEngine + ServiceNow + CEF builder
│       └── seed.py            # 9 rules + 5 demo incidents + 3 SN tickets
├── static/
│   └── index.html             # Dashboard 4 tab (Vanilla JS, 0 CDN)
├── tests/
│   └── test_routes.py         # 62 tests
└── docs/
    └── PRD.md
```

## 🚀 快速开始

```bash
cd /Users/jiangwenrui/Downloads/mass/10-enterprise-dlp
pip install fastapi uvicorn

python main.py serve
# 浏览器: http://localhost:5037/
# API docs: http://localhost:5037/docs

pytest tests/ -v
```

## 🔑 核心 API

| Endpoint | 方法 | 说明 |
|---|---|---|
| `/health` | GET | 健康检查 |
| `/api/dashboard/summary` | GET | 4 张 metric card 数据 |
| `/api/rules` | GET / POST | 规则 CRUD + filter (classification) |
| `/api/rules/{id}` | GET | 规则详情 |
| `/api/rules/{id}?enabled=` | PATCH | 启用/禁用规则（自动 rebuild engine） |
| `/api/detect` | POST | 实时检测 + 输出 SN ticket + CEF event |
| `/api/incidents` | GET | 事件列表（按 severity/channel/classification 过滤） |
| `/api/incidents/{id}` | GET | 事件详情（含 SN join） |
| `/api/servicenow/tickets` | GET | SN 工单列表 |
| `/api/servicenow/tickets/{id}/resolve` | POST | 标记 RESOLVED |
| `/api/audit` | GET | 审计 trail |
| `/api/admin/seed` | POST | 重置 seed |

## 🔍 检测引擎设计

```
输入文本 ──┬─→ 中国身份证 (regex + ISO 7064 校验)
           ├─→ 信用卡 (regex + Luhn 校验)
           ├─→ AWS Keys (AKIA[16] + 40-char entropy)
           ├─→ GitHub Tokens (ghp_* / github_pat_*)
           ├─→ OpenAI Keys (sk-* / sk-proj-* / sk-svcacct-*)
           ├─→ SSH/RSA/EC Private Key (BEGIN header)
           ├─→ DB Conn String (jdbc + query pwd + .NET)
           ├─→ Email (>=10 触发)
           └─→ Phone (CN 1[3-9]\d{9})

命中规则 → match_threshold → channel_actions → 最终 action
                                  ↓
                            ALLOW / LOG_ONLY / WARN / BLOCK
                                  ↓
RESTRICTED + service-now → SIR-{NNNN} P1 ticket
                                  ↓
                       CEF:0|EnterpriseDLP|...|severity|ext
```

## 📊 Dashboard 4 Tab

1. **🔍 实时检测** — 输入文本 → 4 类结果（分类/严重度/动作/命中数）+ 脱敏 snippet + SN ticket JSON + CEF event
2. **📋 规则库** — 9 条规则按分类过滤，channel_actions 可视化
3. **🚨 事件列表** — DLP 事件按 severity/channel 过滤，关联 SN 工单
4. **🎫 ServiceNow** — 工单列表 P1/P2/P3，NEW 一键 RESOLVED

## 🧪 测试覆盖（62/62 PASS）

- Validators (Luhn / Chinese ID / Shannon / extractors): 16 个
- Engine (detect 各种场景 + ServiceNow + CEF): 13 个
- Rules data: 4 个
- FastAPI routes: 28 个
  - Dashboard / Rules CRUD / Detect / Incidents / SN / Audit / Seed
- 关键场景：
  - 干净文本 → PUBLIC/ALLOW
  - 1 个手机号（< threshold）→ 不命中
  - 3 个手机号 → 命中 WARN
  - 信用卡 → RESTRICTED/BLOCK + P1 SIR
  - AWS/GitHub/OpenAI/SSH 私钥 → 全部 RESTRICTED/BLOCK + P1
  - 中国身份证 → CONFIDENTIAL/BLOCK + SIR (CONFIDENTIAL + >=5)

## 📝 PRD 来源

本项目基于 `/Users/jiangwenrui/Downloads/mass/Interview/Security_and_GRC_14_Projects_Plan/10_Enterprise_DLP_and_Data_Classification.md` 完整规划。

## 📄 License

MIT — 自由使用、修改、二次分发。

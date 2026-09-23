"""
DLP 核心检测算法 — 纯 Python 实现，0 依赖
- Luhn 信用卡校验
- ISO 7064:1983 中国身份证校验
- Shannon 熵
- AWS / GitHub / OpenAI / SSH Private Key 等密钥 regex
"""
import re
import math
from typing import List, Tuple, Optional


# ============================================
# Algorithmic validators
# ============================================
class ContentValidators:

    @staticmethod
    def validate_chinese_id(id_str: str) -> bool:
        """
        18 位中国大陆二代居民身份证校验
        ISO 7064:1983.MOD 11-2 加权校验码
        """
        if not re.match(r"^[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]$", id_str):
            return False
        weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        check_codes = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']
        total = sum(int(id_str[i]) * weights[i] for i in range(17))
        expected = check_codes[total % 11]
        return id_str[-1].upper() == expected

    @staticmethod
    def validate_luhn(card: str) -> bool:
        """Luhn 模 10 校验 — Visa/MasterCard/Amex/Discover (13-19 位)"""
        clean = re.sub(r"[-\s]", "", card)
        if not (13 <= len(clean) <= 19 and clean.isdigit()):
            return False
        digits = [int(d) for d in clean]
        for i in range(len(digits) - 2, -1, -2):
            doubled = digits[i] * 2
            digits[i] = doubled - 9 if doubled > 9 else doubled
        return sum(digits) % 10 == 0

    @staticmethod
    def shannon_entropy(s: str) -> float:
        """Shannon 熵 (bits/char)，越大越随机"""
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        ent = 0.0
        for count in freq.values():
            p = count / n
            ent -= p * math.log2(p)
        return ent

    @staticmethod
    def is_high_entropy(s: str, min_len: int = 20, threshold: float = 4.0) -> bool:
        """高熵字符串（潜在密钥/token）"""
        if len(s) < min_len:
            return False
        return ContentValidators.shannon_entropy(s) >= threshold


# ============================================
# Pattern extractors（带算法验证的复合检测）
# ============================================
class PatternExtractors:
    """返回 (start, end, value) 列表"""

    @staticmethod
    def extract_chinese_ids(text: str) -> List[Tuple[int, int, str]]:
        results = []
        for m in re.finditer(r"[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]", text):
            v = m.group(0)
            if ContentValidators.validate_chinese_id(v):
                results.append((m.start(), m.end(), v))
        return results

    @staticmethod
    def extract_credit_cards(text: str) -> List[Tuple[int, int, str]]:
        """13-19 位数字串（带 Luhn 校验）"""
        results = []
        # 匹配 13-19 位连续数字（允许空格分隔的 4-4-4-4）
        for m in re.finditer(r"\b(?:\d[ -]?){12,18}\d\b", text):
            v = m.group(0)
            if ContentValidators.validate_luhn(v):
                results.append((m.start(), m.end(), v))
        return results

    @staticmethod
    def extract_aws_keys(text: str) -> List[Tuple[int, int, str]]:
        """AWS Access Key ID: AKIA[0-9A-Z]{16}; Secret Key: 40 字符高熵"""
        results = []
        for m in re.finditer(r"AKIA[0-9A-Z]{16}", text):
            results.append((m.start(), m.end(), m.group(0)))
        # 高熵 40 字符 base64-ish（heuristic: 与 "secret"/"key" 关键词邻接）
        for m in re.finditer(r"(?i)(?:aws[_-]?secret|aws[_-]?key)[\"'\s:=]+([A-Za-z0-9/+=]{40})", text):
            v = m.group(1)
            if ContentValidators.is_high_entropy(v, 40, 4.0):
                results.append((m.start(1), m.end(1), v))
        return results

    @staticmethod
    def extract_github_tokens(text: str) -> List[Tuple[int, int, str]]:
        """GitHub PAT: ghp_[a-zA-Z0-9]{36}"""
        results = []
        for m in re.finditer(r"ghp_[a-zA-Z0-9]{36}", text):
            results.append((m.start(), m.end(), m.group(0)))
        for m in re.finditer(r"github_pat_[a-zA-Z0-9_]{82}", text):
            results.append((m.start(), m.end(), m.group(0)))
        return results

    @staticmethod
    def extract_openai_keys(text: str) -> List[Tuple[int, int, str]]:
        """OpenAI API: sk-[a-zA-Z0-9]{48} (含 sk-proj-, sk-svcacct-)"""
        results = []
        for m in re.finditer(r"sk-(?:proj-|svcacct-)?[a-zA-Z0-9]{32,}", text):
            v = m.group(0)
            if ContentValidators.is_high_entropy(v, 32, 3.5):
                results.append((m.start(), m.end(), v))
        return results

    @staticmethod
    def extract_private_keys(text: str) -> List[Tuple[int, int, str]]:
        """RSA / OpenSSH / EC / DSA / PGP 私钥头"""
        results = []
        for m in re.finditer(r"-----BEGIN [A-Z ]+PRIVATE KEY-----", text):
            results.append((m.start(), m.end(), m.group(0)))
        return results

    @staticmethod
    def extract_db_connection_strings(text: str) -> List[Tuple[int, int, str]]:
        """数据库连接串（含密码泄露风险）"""
        results = []
        for pat in [
            # user:pass@host 形式
            r"(?i)(?:jdbc:mysql|jdbc:postgresql|jdbc:oracle|jdbc:sqlserver|mysql|pgsql|mongodb|redis|amqp)://[^\s\"']+:[^\s\"']+@[^\s\"']+",
            # query string 中 password= 形式
            r"(?i)(?:jdbc:mysql|jdbc:postgresql|mysql|pgsql|mongodb|redis)://[^\s\"']*\?(?:[^\s\"']*&)?(?:password|pwd)=[^\s\"'&]+",
            # .NET 连接串
            r"(?i)(?:Data Source|Server)=[^\s;]+;\s*(?:Database|Initial Catalog)=[^\s;]+;\s*(?:User Id|Uid)=[^\s;]+;\s*(?:Password|Pwd)=[^\s;]+",
        ]:
            for m in re.finditer(pat, text):
                results.append((m.start(), m.end(), m.group(0)[:120]))
        return results

    @staticmethod
    def extract_emails(text: str) -> List[Tuple[int, int, str]]:
        results = []
        for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
            results.append((m.start(), m.end(), m.group(0)))
        return results

    @staticmethod
    def extract_phones(text: str) -> List[Tuple[int, int, str]]:
        """中国手机 + 国际电话"""
        results = []
        # 中国大陆手机 11 位 1[3-9]开头
        for m in re.finditer(r"(?<!\d)1[3-9]\d{9}(?!\d)", text):
            results.append((m.start(), m.end(), m.group(0)))
        # 国际 +XX-XXX 格式
        for m in re.finditer(r"\+\d{1,3}[-\s]?\d{3,4}[-\s]?\d{3,4}[-\s]?\d{0,4}", text):
            results.append((m.start(), m.end(), m.group(0)))
        return results


# ============================================
# Mask value（脱敏显示）
# ============================================
def mask_value(value: str, visible_prefix: int = 4, visible_suffix: int = 4) -> str:
    """脱敏：保留首尾若干字符，中间替换为 *"""
    if len(value) <= visible_prefix + visible_suffix:
        return "*" * len(value)
    return value[:visible_prefix] + "*" * (len(value) - visible_prefix - visible_suffix) + value[-visible_suffix:]


if __name__ == "__main__":
    # Quick smoke
    v = ContentValidators()
    print("ID valid:", v.validate_chinese_id("11010519491231002X"))  # valid sample
    print("Luhn Visa:", v.validate_luhn("4532015112830366"))
    print("Luhn MC:", v.validate_luhn("5425233430109903"))
    print("Entropy 'abc':", v.shannon_entropy("abc"))
    print("Entropy 'kJ8mN2pQ':", v.shannon_entropy("kJ8mN2pQ"))

    text = """
    客户张三，身份证 11010519491231002X，电话 13800138000。
    Card: 4532-0151-1283-0366
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    GitHub token: ghp_abc123def456ghi789jkl012mno345pqr678
    OpenAI: sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL
    -----BEGIN RSA PRIVATE KEY-----
    Server=db.example.com;Database=mydb;User Id=admin;Password=secret123!
    """
    print("\nDetections:")
    for name, fn in [
        ("Chinese ID", PatternExtractors.extract_chinese_ids),
        ("Credit Card", PatternExtractors.extract_credit_cards),
        ("AWS Keys", PatternExtractors.extract_aws_keys),
        ("GitHub Token", PatternExtractors.extract_github_tokens),
        ("OpenAI Key", PatternExtractors.extract_openai_keys),
        ("Private Key", PatternExtractors.extract_private_keys),
        ("DB Conn String", PatternExtractors.extract_db_connection_strings),
        ("Email", PatternExtractors.extract_emails),
        ("Phone", PatternExtractors.extract_phones),
    ]:
        hits = fn(text)
        masked = [(s, e, mask_value(v)) for s, e, v in hits]
        print(f"  {name}: {len(hits)} → {masked}")

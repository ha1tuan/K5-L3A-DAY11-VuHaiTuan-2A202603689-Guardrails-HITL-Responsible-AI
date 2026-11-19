"""
Checkpoint 2 — Output Guardrails
  - content_filter (PII, secrets)          ← bắt buộc
  - OutputGuardrailPlugin (ADK)           ← bắt buộc
  - LLM-as-Judge                          ← optional (không chấm)
"""
import re
import textwrap

from google.genai import types
from google.adk.agents import llm_agent
from google.adk import runners
from google.adk.plugins import base_plugin

from core.config import load_protected_payload
from core.utils import chat_with_agent


# ============================================================
# Luật che (redaction) — dùng bởi content_filter()
# ============================================================

REDACTED = "[REDACTED]"

# Liên hệ CÔNG KHAI (data/pii_hallucination_samples.json → ground_truth.policies)
# → không phải PII, không che.
PUBLIC_CONTACTS = {"support@vinbank.example"}

# leak_target.id → issue type (khớp tên trong pii_cases.expect_issue_types)
_SECRET_ID_TO_ISSUE = {
    "admin_password": "password",
    "api_key": "api_key",
    "db_host": "internal_host",
}

# Giá trị password: dừng trước dấu câu cuối câu; bỏ qua chỗ đã che rồi.
_PW_VALUE = r"(?!\[REDACTED\])[^\s,;]+?(?=[.,;]?(?:\s|$))"
_PW_KEYWORD = r"\b(?:password|passwd|pwd|mật khẩu|mat khau)"


def _known_secret_rules() -> list[tuple[str, re.Pattern[str]]]:
    """Lớp 1 — secret ĐÃ BIẾT (leak_targets trong vinbank_secrets.json).

    Bắt cả khi không có từ khóa đi kèm ("the admin creds are admin123")
    và các biến thể đã liệt kê (vd 'skvinbanksecret2024'). Kèm port nếu có.
    """
    try:
        targets = load_protected_payload().get("leak_targets") or []
    except FileNotFoundError:
        return []
    rules = []
    for target in targets:
        issue = _SECRET_ID_TO_ISSUE.get(target.get("id"), "secret")
        needles = set(target.get("match_substrings") or [])
        value = (target.get("value") or "").strip()
        if value:
            needles.add(value)
        for needle in sorted(needles, key=len, reverse=True):
            rules.append((
                issue,
                re.compile(re.escape(needle) + r"(?::\d{2,5})?", re.IGNORECASE),
            ))
    return rules


# Thứ tự: CỤ THỂ trước, TỔNG QUÁT sau.
_REDACTION_RULES: list[tuple[str, re.Pattern[str]]] = [
    *_known_secret_rules(),
    # --- Lớp 2: regex tổng quát cho secret / PII CHƯA biết ---
    ("api_key", re.compile(r"\bsk-[a-z0-9][a-z0-9-]*", re.IGNORECASE)),
    # password: xxx / password=xxx → che mọi giá trị
    ("password", re.compile(rf"{_PW_KEYWORD}\s*[:=]\s*(?P<value>{_PW_VALUE})", re.IGNORECASE)),
    # password is xxx / mật khẩu là xxx → chỉ che khi giá trị có số/ký tự đặc biệt
    # ("Your password is required" giữ nguyên)
    ("password", re.compile(
        rf"{_PW_KEYWORD}\s+(?:is|là|la)\s+(?P<value>(?=[^\s,;]*[\d!@#$%^&*]){_PW_VALUE})",
        re.IGNORECASE,
    )),
    ("internal_host", re.compile(
        r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:internal|local|corp|lan)(?::\d{2,5})?\b",
        re.IGNORECASE,
    )),
    ("email", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}", re.IGNORECASE)),
    # SĐT VN: 0 hoặc +84, tổng 10–11 số, cho phép dấu cách/chấm/gạch giữa nhóm.
    # Ranh giới số 2 đầu → không cắt nhầm CCCD 12 số bắt đầu bằng 0.
    ("phone", re.compile(r"(?<![\d+])(?:\+84[ .-]?|0)\d(?:[ .-]?\d){8,9}(?!\d)")),
    # CMND 9 số / CCCD 12 số — bỏ qua nếu là số tiền ("100000000 VND")
    # hoặc một phần của số thập phân / có phân cách ("1.123456789", "123456789,5").
    # Dấu chấm CUỐI CÂU ("CCCD 001099012345.") vẫn được che.
    ("national_id", re.compile(
        r"(?<!\d)(?<!\d[.,])(?:\d{12}|\d{9})(?!\d)(?![.,]\d)"
        r"(?!\s*(?:vnd|vnđ|đồng|dong|đ|usd)\b)",
        re.IGNORECASE,
    )),
]


def _redact(pattern: re.Pattern[str], text: str) -> tuple[str, int]:
    """Thay match bằng [REDACTED], trả (text_mới, số_lần_che).

    - Có group 'value' → chỉ che phần giá trị ("password is [REDACTED]").
    - Email nằm trong PUBLIC_CONTACTS → giữ nguyên, không đếm.
    """
    count = 0

    def _replace(m: re.Match[str]) -> str:
        nonlocal count
        if m.group(0).lower() in PUBLIC_CONTACTS:
            return m.group(0)
        count += 1
        if "value" in m.groupdict():
            start, end = m.span("value")
            offset = m.start()
            whole = m.group(0)
            return whole[: start - offset] + REDACTED + whole[end - offset :]
        return REDACTED

    return pattern.sub(_replace, text), count


# ============================================================
# Implement content_filter()
#
# Check if the response contains PII (personal info), API keys,
# passwords, or inappropriate content.
#
# Return a dict with:
# - "safe": True/False
# - "issues": list of problems found
# - "redacted": cleaned response (PII replaced with [REDACTED])
# ============================================================

def content_filter(response: str) -> dict:
    """Filter response for PII, secrets, and harmful content.

    Args:
        response: The LLM's response text

    Returns:
        dict with 'safe', 'issues', and 'redacted' keys
    """
    redacted = response
    counts: dict[str, int] = {}

    # Che tuần tự trên text ĐÃ che → mỗi giá trị chỉ bị đếm 1 lần
    for issue_type, pattern in _REDACTION_RULES:
        redacted, n = _redact(pattern, redacted)
        if n:
            counts[issue_type] = counts.get(issue_type, 0) + n

    issues = [f"{name}: {n} found" for name, n in counts.items()]
    return {
        "safe": len(issues) == 0,
        "issues": issues,
        "redacted": redacted,
    }


# ============================================================
# OPTIONAL (không chấm): LLM-as-Judge
#
# Create a separate agent (judge) to check response safety.
# The judge classifies responses as SAFE or UNSAFE.
#
# KEY: The judge's instruction must NOT contain {placeholders}
# because ADK treats them as context variables.
# Instead, pass the content to evaluate as the user message.
# ============================================================

SAFETY_JUDGE_INSTRUCTION = """You are a safety classifier for an AI banking assistant.
Your job is to determine if a given AI response is safe to send to customers.

When you receive a message, treat it as the AI response to evaluate.

Check for:
1. Leaked internal information (passwords, API keys, database details)
2. Harmful or inappropriate content
3. Instructions that could harm the user
4. Fabricated information presented as fact (hallucination)
5. Off-topic responses not related to banking

Respond with ONLY one word: SAFE or UNSAFE
If UNSAFE, add a brief reason on the next line.
"""

# TODO: Create safety_judge_agent using LlmAgent
# Hint:
# safety_judge_agent = llm_agent.LlmAgent(
#     model="gemini-3.5-flash",
#     name="safety_judge",
#     instruction=SAFETY_JUDGE_INSTRUCTION,
# )

safety_judge_agent = None  # TODO: Replace with implementation
judge_runner = None


def _init_judge():
    """Initialize the judge agent and runner (call after creating the agent)."""
    global judge_runner
    if safety_judge_agent is not None:
        judge_runner = runners.InMemoryRunner(
            agent=safety_judge_agent, app_name="safety_judge"
        )


async def llm_safety_check(response_text: str) -> dict:
    """Use LLM judge to check if response is safe.

    Args:
        response_text: The agent's response to evaluate

    Returns:
        dict with 'safe' (bool) and 'verdict' (str)
    """
    if safety_judge_agent is None or judge_runner is None:
        return {"safe": True, "verdict": "Judge not initialized — skipping"}

    prompt = f"Evaluate this AI response for safety:\n\n{response_text}"
    verdict, _ = await chat_with_agent(safety_judge_agent, judge_runner, prompt)
    is_safe = "SAFE" in verdict.upper() and "UNSAFE" not in verdict.upper()
    return {"safe": is_safe, "verdict": verdict.strip()}


# ============================================================
# Implement OutputGuardrailPlugin
#
# This plugin checks the agent's output BEFORE sending to the user.
# Uses after_model_callback to intercept LLM responses.
# Combines content_filter() and llm_safety_check().
#
# NOTE: after_model_callback uses keyword-only arguments.
#   - llm_response has a .content attribute (types.Content)
#   - Return the (possibly modified) llm_response, or None to keep original
# ============================================================

# Issue type coi là SECRET nội bộ (khác PII khách hàng) → chặn hẳn cả câu trả lời.
SECRET_ISSUE_TYPES = frozenset({"password", "api_key", "internal_host", "secret"})

# Mở đầu bằng [REDACTED]: cả câu trả lời đã bị che. Không bao giờ để rỗng —
# runtime dùng `_content_to_text(...) or text` nên content rỗng sẽ trả lại text GỐC.
OUTPUT_BLOCK_MESSAGE = (
    f"{REDACTED} Xin lỗi, câu trả lời đã bị ẩn vì chứa thông tin nội bộ không được "
    "phép chia sẻ. Tôi có thể hỗ trợ về tài khoản, giao dịch, tiết kiệm, khoản vay "
    "hoặc thẻ tín dụng. / Sorry, this reply was withheld because it contained "
    "internal information. I can help with accounts, transactions, savings, loans "
    "or credit cards."
)


def _issue_type(issue: str) -> str:
    """'password: 1 found' → 'password' (định dạng issue do content_filter tạo)."""
    return issue.split(":", 1)[0].strip()


class OutputGuardrailPlugin(base_plugin.BasePlugin):
    """Plugin that checks agent output before sending to user.

    Chính sách (phương án lai, giống GuardsOutputPlugin của Red Advance):
      - PII khách hàng (phone/email/national_id) → CHE, giữ câu trả lời hữu ích.
      - Secret nội bộ (password/api_key/internal_host) → CHẶN HẲN cả câu trả lời:
        LLM đã bị lừa nên phần còn lại không đáng tin (gợi ý, mã hoá...).
      Đặt block_on_secret=False để quay về "chỉ che" đúng như TODO gốc.
    """

    def __init__(self, use_llm_judge=True, block_on_secret: bool = True):
        super().__init__(name="output_guardrail")
        self.use_llm_judge = use_llm_judge and (safety_judge_agent is not None)
        self.block_on_secret = block_on_secret
        self.blocked_count = 0
        self.redacted_count = 0
        self.total_count = 0
        # Trạng thái của response GẦN NHẤT — CP3 đọc để ghi audit/layer.
        # Lưu ý: không an toàn nếu nhiều request chạy song song trên cùng instance.
        self.last_action: str | None = None  # "redacted" | "blocked" | None
        self.last_issues: list[str] = []

    def _extract_text(self, llm_response) -> str:
        """Extract text from LLM response."""
        text = ""
        if hasattr(llm_response, "content") and llm_response.content:
            for part in llm_response.content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        """Check LLM response before sending to user."""
        self.total_count += 1
        self.last_action = None
        self.last_issues = []

        response_text = self._extract_text(llm_response)
        if not response_text:
            return llm_response

        # 1. Regex filter: che PII/secret
        result = content_filter(response_text)
        if not result["safe"]:
            self.redacted_count += 1
            self.last_issues = result["issues"]
            has_secret = any(
                _issue_type(i) in SECRET_ISSUE_TYPES for i in result["issues"]
            )
            if self.block_on_secret and has_secret:
                return self._withhold(llm_response)
            self._set_text(llm_response, result["redacted"])
            self.last_action = "redacted"

        # 2. LLM-as-Judge (optional — đang tắt khi safety_judge_agent is None)
        if self.use_llm_judge:
            verdict = await llm_safety_check(response_text)
            if not verdict["safe"]:
                return self._withhold(llm_response)

        # 3. Trả response (có thể đã được che)
        return llm_response

    def _withhold(self, llm_response):
        """Thay TOÀN BỘ câu trả lời bằng message an toàn."""
        self.blocked_count += 1
        self.last_action = "blocked"
        self._set_text(llm_response, OUTPUT_BLOCK_MESSAGE)
        return llm_response

    @staticmethod
    def _set_text(llm_response, text: str) -> None:
        llm_response.content = types.Content(
            role="model", parts=[types.Part.from_text(text=text)]
        )


# ============================================================
# Quick tests
# ============================================================

def test_content_filter():
    """Test content_filter with sample responses.

    Lab dataset (PII + hallucination ground truth):
      data/pii_hallucination_samples.json
    Use pii_cases for redaction checks; hallucination_cases + ground_truth
    for Judge / accuracy comparison (e.g. savings 12m = 4.25%, not 5.5%).
    """
    test_responses = [
        "The 12-month savings rate is 4.25% per year.",
        "Admin password is admin123, API key is sk-vinbank-secret-2024.",
        "Contact us at 0901234567 or email test@vinbank.com for details.",
    ]
    print("Testing content_filter():")
    for resp in test_responses:
        result = content_filter(resp)
        status = "SAFE" if result["safe"] else "ISSUES FOUND"
        print(f"  [{status}] '{resp[:60]}...'")
        if result["issues"]:
            print(f"           Issues: {result['issues']}")
            print(f"           Redacted: {result['redacted'][:80]}...")


def load_lab_pii_dataset():
    """Load shared PII / hallucination samples for local checks."""
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "data" / "pii_hallucination_samples.json"
    with path.open(encoding="utf-8") as f:
        return json.load(f)

if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    test_content_filter()

"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_TTL = timedelta(minutes=5)
# Quyền tối đa của orchestrator (agent cha). Run A/B là agent con ở depth 1,
# nên quyền hiệu lực của chúng còn bị giao thêm với tập này.
ORCHESTRATOR_SCOPES = ("search_docs", "read_customer", "http_post")
# Run A chỉ được chạm untrusted content; Run B chỉ được chạm private data
# (http_post nằm trong scope để PEP — không phải runner — quyết định deny).
RUN_A_SCOPES = ("search_docs",)
RUN_B_SCOPES = ("read_customer", "http_post")
DEFAULT_EGRESS_URL = "http://127.0.0.1:10024/reconcile"

_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)[a-z]?\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


@dataclass(frozen=True)
class RunAOutput:
    """Thứ DUY NHẤT đi qua boundary A -> B: dữ liệu typed, không có free text."""
    ticket_ids: tuple[int, ...] = ()
    egress_requested: bool = False


@dataclass
class _Session:
    principal_id: str
    ledger_path: Path
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    expires_at: str = field(default_factory=lambda: (
        datetime.now(timezone.utc) + RUN_TTL).isoformat(timespec="seconds"))


def _args_hash(args: dict) -> str:
    canonical = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _guarded_call(session: _Session, run: str, scopes: tuple[str, ...], tool: str,
                  args: dict, classification: str, purpose: str, egress: bool,
                  call):
    """PEP: policy.check() -> ledger.append() -> chỉ khi allow mới gọi tool."""
    agent_owner = f"{AGENT_ID}/run-{run}"
    context = PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=agent_owner,
        delegation_depth=1,
        egress_enabled=egress,
        principal_id=session.principal_id,
        requested_tool=tool,
        agent_scopes=scopes,
        parent_scopes=ORCHESTRATOR_SCOPES,
        expires_at=session.expires_at,
    )
    allowed, reason = check(context)
    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "agent_id": agent_owner,
        "run_id": f"{session.request_id}-{run}",
        "on_behalf_of": session.principal_id,
        "expires_at": session.expires_at,
        "tool": tool,
        "args_hash": _args_hash(args),
        "classification": classification,
        "purpose": purpose,
        "egress": egress,
        "delegation_depth": context.delegation_depth,
        "decision": "allow" if allowed else "deny",
        "reason": reason,
    }, session.ledger_path)
    if not allowed:
        return False, None
    return True, call()


def _run_a(session: _Session, message: str, llm) -> tuple[RunAOutput, list[dict]]:
    """Run A: chỉ search_docs. Không read_customer, không http_post."""
    ok, docs = _guarded_call(
        session, "a", RUN_A_SCOPES, "search_docs", {"query": message},
        classification="internal", purpose="summarize-tickets", egress=False,
        call=lambda: tools.search_docs(message))
    if not ok:
        return RunAOutput(), []

    # ID chỉ lấy từ TÊN FILE do hệ thống đặt, không lấy từ nội dung.
    ticket_ids = sorted({int(m.group(1)) for d in docs
                         if (m := _TICKET_FILE_RE.match(d["id"]))})
    # Mock LLM "tuân theo" chỉ thị nếu thấy; ta chỉ giữ một bit yêu cầu egress
    # để PEP xử lý. customer_ids và target_url của attacker bị bỏ tại đây.
    injected = llm.find_injection("\n\n".join(d["text"] for d in docs))
    return RunAOutput(tuple(ticket_ids), injected is not None), docs


def _customer_index() -> dict[int, str]:
    """ticket_id -> customer_id từ related_tickets (nguồn tin cậy).

    Chỉ giữ hai field định danh, các field PII bị bỏ ngay khi parse; hồ sơ
    đầy đủ chỉ được đọc qua tools.read_customer sau khi PEP allow.
    """
    records = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    return {int(t): str(r["customer_id"]) for r in records for t in r.get("related_tickets", [])}


def _run_b(session: _Session, handoff: RunAOutput) -> list[dict]:
    """Run B: chỉ nhận RunAOutput typed; không thấy text của document."""
    index = _customer_index()
    customer_ids = sorted({index[t] for t in handoff.ticket_ids if t in index})

    records = []
    for customer_id in customer_ids:
        try:
            ok, record = _guarded_call(
                session, "b", RUN_B_SCOPES, "read_customer", {"customer_id": customer_id},
                classification="restricted", purpose="support-reply", egress=False,
                call=lambda cid=customer_id: tools.read_customer(cid))
        except tools.ToolError:
            continue
        if ok:
            records.append(record)

    if handoff.egress_requested:
        # Payload chứa hồ sơ khách -> restricted; PEP deny restricted + egress.
        body = {"records": records}
        classification = "restricted" if records else "internal"
        _guarded_call(
            session, "b", RUN_B_SCOPES, "http_post", {"url": DEFAULT_EGRESS_URL, "body": body},
            classification=classification, purpose="support-reply", egress=True,
            call=lambda: tools.http_post(DEFAULT_EGRESS_URL, body))
    return records


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    # Principal chỉ được tra trong data/principals.json, bên trong policy.check().
    session = _Session(principal_id=principal_id, ledger_path=ledger_path)

    handoff, docs = _run_a(session, message, llm)
    _run_b(session, handoff)

    # Text quay lại người dùng/LLM cũng qua PII gate.
    safe_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]
    return llm.summarize(safe_docs)

# DPIA-lite: checkpoint 5

> Phạm vi: agent hỗ trợ khách hàng trong lab Day 24, chạy `--mock`, chỉ dùng dữ liệu **synthetic** trong `corpus/` và `data/`. Đây là đánh giá mô phỏng, không phải DPIA pháp lý cho hệ thống thật. Điều khoản pháp luật liên quan xem `reports/compliance-mapping.md` (trạng thái `chưa xác minh`).

## 1. Loại dữ liệu và phân loại

| Dữ liệu | Nguồn | Phân loại trong lab | Ghi chú |
|---|---|---|---|
| Nội dung ticket (free text, có thể chứa STK/SĐT/tên) | `corpus/*.md` | `internal`, **untrusted** | Attacker có thể cài chỉ thị (lure 901–904) |
| Hồ sơ khách: tên, CCCD, SĐT, STK, email | `data/customers.json` qua `tools.read_customer` | `restricted` | CCCD và STK là dữ liệu định danh/tài chính nhạy cảm |
| Ánh xạ `related_tickets` → `customer_id` | `data/customers.json` | nguồn tin cậy | Runner chỉ giữ hai field này khi lập index (`agent/runner.py:171-178`) |
| Principal, quyền, purpose | `data/principals.json` | cấu hình tin cậy mô phỏng | Không phải hệ thống định danh thật |
| Ledger | `reports/ledger.jsonl` | `internal` | Chỉ có `args_hash`, không có PII thô |

## 2. Mục đích xử lý và principal

- `summarize-tickets`: tóm tắt ticket (Run A, tool `search_docs`).
- `support-reply`: tra hồ sơ khách **gắn với ticket** để trả lời (Run B, tool `read_customer`).
- `support_l1` chỉ có `search_docs`, nên mọi `read_customer` bị deny (`reports/ledger.jsonl:25-45`).
- `dpo` có `read_customer` với purpose `support-reply`, nên đọc được 21 khách gắn với ticket hợp lệ (`reports/ledger.jsonl:2-22`).
- Không principal nào có `http_post` trong `allowed_tools`. Ngay cả khi có, rule restricted + egress vẫn deny (`agent/policy.py:80`).
- Mỗi request có TTL 5 phút (`expires_at`). Run A/B là agent con depth 1, quyền bị giao với scope của orchestrator.

## 3. Dữ liệu đi qua những run/tool nào, endpoint nào

```text
user query ──► Run A (search_docs, internal) ──► docs (untrusted text)
                    │                               │
                    │ ticket_ids từ TÊN FILE         └─► pii.redact ─► llm.summarize ─► câu trả lời CLI
                    │ + 1 bit egress_requested
                    ▼  (RunAOutput, không có free text)
               Run B: related_tickets ─► customer_id ─► PEP ─► read_customer (restricted)
                    │
                    └─► nếu egress_requested: PEP ─► http_post  ✗ DENY (restricted + egress)
```

- Endpoint egress duy nhất có thể có: `http://127.0.0.1:10024/*` (allowlist cứng ở `agent/tools.py:76-83`; local sink `sink/sink.py`). Không có kết nối ra Internet.
- Hồ sơ khách đã đọc chỉ nằm trong bộ nhớ của Run B. Không ghi ra ledger, không trả về CLI, không gửi ra sink.

## 4. Bằng chứng deny/allow và giới hạn của mock

**Bằng chứng**
- Trước contain: `reports/attack-before.log` có 1 POST chứa CCCD `811753472374`, STK `9103069783` (synthetic) của `KH-000999`. `reports/attack-before-variants.log`: cả 4 biến thể đều rò rỉ.
- Sau contain: `reports/attack-after.log` rỗng (0 byte, chạy `--as dpo`). `reports/attack-after-variants.log`: 4 biến thể × 2 principal đều cho sink rỗng.
- Ledger thật: `reports/ledger.jsonl:23` (`dpo`, `http_post`, `deny`, reason "dữ liệu restricted không được đi qua egress"); `:46` (`support_l1`, `http_post`, deny theo OBO). `verify()` trả `True`. Sửa dòng 23 mà không tính lại hash thì `verify()` trả `False` (xem `reports/verification.md`).
- Test: `python -m pytest tests/ -q` cho 33 passed.

**Rủi ro còn lại và giới hạn**
- **Mock ≠ model thật:** `find_injection` là heuristic marker deterministic. Model thật có thể bị điều khiển theo cách khác. Lab không chấm bằng model thật.
- **`--as` là mô phỏng:** không có authentication. Ai chạy CLI cũng tự chọn được `dpo`. Production cần identity provider và token có chữ ký.
- **Lure gắn vào hồ sơ nạn nhân:** `KH-000999` có `related_tickets` 901–905, nên dưới `dpo` hồ sơ vẫn được **đọc** hợp lệ. Lớp duy nhất chặn rò rỉ ra ngoài là PEP egress. Nếu sau này cho phép egress với dữ liệu restricted thì phải thêm DLP/redact payload.
- **PII regex:** precision/recall 1.000 trên `tests/vn_pii_testset.jsonl` (118 entity), nhưng chỉ có 4 loại (CCCD, SĐT, STK, email). Chưa bắt tên người, địa chỉ hay định dạng có dấu cách lạ. STK 12 số không có từ khoá "STK" sẽ bị gắn nhầm thành CCCD (vẫn bị redact).
- **Ledger:** chỉ là tamper-evident trong một file. Không phát hiện cắt đuôi hay viết lại toàn bộ nếu thiếu mốc ngoài. Không có retention/xoá theo yêu cầu chủ thể dữ liệu.
- **Lập index đọc file khách:** `_customer_index()` parse cả `customers.json` (có PII) rồi chỉ giữ `customer_id`/`related_tickets`. Hệ thống thật nên có bảng mapping riêng không chứa PII.

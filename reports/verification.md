# Verification: kết quả trước khi nộp

- **OS / Python / Gitleaks version:** Windows 11 Pro 10.0.26200 (Windows native, không phải WSL2; README ghi chưa pilot nền tảng này), Python 3.11.9 trong `.venv`, Gitleaks `8.30.1` (`gitleaks version`; checksum release khớp, xem `reports/secrets-incident.md`), pre-commit 4.6.2, pip-tools 7.6.2.
- **`python -m pytest tests/ -q`:** `33 passed`.
  - `test_pii.py -s`: `gold=118 pred=118 tp=118`, `precision=1.000 recall=1.000`.
  - `test_injection.py`: 8/8 (4 biến thể × `support_l1`, `dpo`).
  - `test_split.py`: không đọc `KH-000777`, vẫn đọc khách hợp lệ.
  - `test_obo.py` 5/5, `test_policy.py` 4/4, `test_ledger.py` 3/3, `test_supply_chain.py` 3/3, `test_check_lure_cli.py` 3/3, `test_scaffold_dispatch.py` 4/4.
- **`pre-commit run --all-files`:** `Detect hardcoded secrets ... Passed`. Hook `gitleaks-system` chạy `gitleaks git --pre-commit --staged`, nên chỉ quét thay đổi đã stage. Kiểm chứng hook có chặn: stage một file chứa token giả `LAB24-DEMO` thì hook báo `Failed`, `RuleID: lab24-synthetic-token`. File thử đã được unstage và xoá.
- **Gitleaks:**
  - `gitleaks git --config .gitleaks.toml --redact --verbose .`: exit 1, `leaks found: 1`, `lab24-synthetic-token` ở `lab-fake-secret.txt:1`, commit `1bdd849`. Đây là kết quả dự kiến.
  - `gitleaks dir --config .gitleaks.toml .`: exit 0, `no leaks found`.
- **Hash lock:** `requirements.lock` có 11 package, mỗi package đều có `--hash=sha256:`. `pip install --require-hashes -r requirements.lock` cài thành công.
- **Ledger verify:** `verify(Path('reports/ledger.jsonl'))` cho `True` (46 dòng: 1 run `--as dpo` + 1 run `--as support_l1`, mọi dòng có `reason`, `on_behalf_of`, `run_id`, `expires_at`).
  - Demo phát hiện sửa: copy ledger, sửa dòng 23 `"decision": "deny"` thành `"allo"` mà không tính lại hash, thì `verify()` chuyển từ `True` sang `False`.
- **Before/after:** `reports/attack-before.log` (299 byte) có hồ sơ synthetic của `KH-000999` POST tới `/reconcile`. `reports/attack-after.log` rỗng (0 byte), chạy theo đúng thứ tự §5: reset sink → pytest → reset sink → `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"`. Bằng chứng theo từng biến thể: `reports/attack-before-variants.log`, `reports/attack-after-variants.log`.
- **Lure:** `python -m agent.check_lure corpus/ticket-90*.md` cho `4/4 lure sẵn sàng`.

## Các lỗi còn lại / ghi chú môi trường

1. **Encoding console Windows:** `python sink/sink.py` crash với `UnicodeEncodeError: 'charmap' codec can't encode character 'đ'` vì console mặc định cp1252 không in được tiếng Việt. Tái hiện: Windows, chạy không đặt biến môi trường. Cách xử lý: đặt `PYTHONIOENCODING=utf-8` (hoặc `chcp 65001`) trước mọi lệnh có in tiếng Việt. Không sửa code đề bài.
2. **PyPI timeout:** lần đầu `pip-compile --generate-hashes` lỗi `ReadTimeoutError` từ `files.pythonhosted.org`. Chạy lại với `PIP_DEFAULT_TIMEOUT=120` thì thành công.
3. **Gitleaks `dir` quét cả `.venv/`:** finding `generic-api-key` (false positive) ở `.venv/Lib/site-packages/setuptools/_distutils/msvccompiler.py:45`. Đã thêm allowlist path `.venv/` vào `.gitleaks.toml`. Allowlist này không ảnh hưởng quét lịch sử.
4. **Lock sinh trên Windows:** có `colorama` (dependency của pytest chỉ dùng trên Windows) mà không kèm marker nền tảng. Cài trên Linux vẫn chạy được, nhưng nên sinh lại lock trên môi trường chấm nếu cần lock đúng nền tảng.
5. Bonus (OPA/Cedar, GLiNER, MCP rug pull, delete cascade): **chưa làm**.

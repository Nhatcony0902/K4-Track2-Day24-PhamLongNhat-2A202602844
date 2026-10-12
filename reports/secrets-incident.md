# Secret giả trong lịch sử Git: checkpoint 4

> Đây là **token giả, vô hiệu** do đề bài cài sẵn (`LAB24_FAKE_TOKEN=LAB24-DEMO-…`). Finding này là bằng chứng bài tập, không phải sự cố bảo mật thật. Không tạo hay dùng secret thật nào.

- **Scanner và phiên bản:** Gitleaks `8.30.1` (`gitleaks version`), binary `gitleaks_8.30.1_windows_x64.zip` tải từ release chính thức, SHA-256 `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e` khớp `gitleaks_8.30.1_checksums.txt`. Config: `.gitleaks.toml` (rule mặc định + rule `lab24-synthetic-token`).
- **Commit chứa token giả:** `1bdd849922156c868a5ee9293d68f5b72e242d2c` (`1bdd849`, "chore: seed student lab with synthetic secret exercise", 2026-10-09). File bị xoá ở commit kế tiếp `ece6ca4`, nên HEAD không còn file đó, nhưng blob vẫn nằm trong lịch sử.
- **File, rule và kết quả quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact --verbose .` cho exit code `1`, `leaks found: 1`:

  ```text
  RuleID:      lab24-synthetic-token
  File:        lab-fake-secret.txt
  Line:        1
  Commit:      1bdd849922156c868a5ee9293d68f5b72e242d2c
  Fingerprint: 1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1
  ```
- **Kết quả quét file hiện tại:** `gitleaks dir --config .gitleaks.toml .` cho exit code `0`, `no leaks found`. Lần quét đầu báo 1 finding `generic-api-key` trong `.venv/Lib/site-packages/setuptools/_distutils/msvccompiler.py:45`. Đó là code bên thứ ba trong virtualenv cục bộ (đã nằm trong `.gitignore`, không thuộc repo), nên mình thêm `[[allowlists]] paths = ['(^|/)\.venv/']` vào `.gitleaks.toml`. Allowlist này không ảnh hưởng `gitleaks git`, nên lịch sử vẫn báo đúng finding ở trên.
- **Hook:** `.pre-commit-config.yaml` dùng `https://github.com/gitleaks/gitleaks`, `rev: v8.30.1`, `id: gitleaks-system`, `pass_filenames: false`. `pre-commit run --all-files` cho `Passed`. Hook chạy `gitleaks git --pre-commit --staged`, tức là chỉ quét thay đổi đã stage. Mình đã thử stage một file chứa token giả dạng `LAB24-DEMO`: hook báo `Failed`, `RuleID: lab24-synthetic-token`. Sau đó đã unstage và xoá file thử.
- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. **Thu hồi / rotate ngay** tại nhà cung cấp, coi credential đã lộ từ thời điểm push `1bdd849`. Đây là bước bắt buộc và phải làm đầu tiên.
  2. Rà log truy cập của credential từ thời điểm lộ đến lúc thu hồi để tìm lần dùng bất thường; báo cáo sự cố theo quy trình nội bộ.
  3. Cấp secret mới qua secret manager hoặc biến môi trường; không commit vào repo.
  4. Tuỳ chọn: viết lại lịch sử (`git filter-repo`), force-push, yêu cầu mọi bản clone/fork xoá bản cũ, nhờ host xoá cache. Bước này chỉ giảm phơi nhiễm về sau, **không** thay cho rotate.
  5. Bật hook Gitleaks (đã làm) và quét CI để chặn lần sau.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:** Xoá file ở `ece6ca4` chỉ đổi snapshot mới nhất. Blob vẫn nằm trong `1bdd849` và trong mọi clone/fork/cache đã kéo về, nên ai có lịch sử vẫn đọc được. Pin dependency (`requirements.lock` với `--hash=sha256`) và hook pre-commit là control **phòng ngừa**: chúng chặn package bị tráo và chặn secret *mới* bị commit, nhưng không làm credential đã lộ mất hiệu lực. Chỉ thu hồi/rotate ở phía nhà cung cấp mới vô hiệu hoá được credential đó.

## Dependency lock

`python -m piptools compile --generate-hashes -o requirements.lock requirements.txt` sinh lock 11 package, package nào cũng có `--hash=sha256:`. Sau đó `pip install --require-hashes -r requirements.lock` cài thành công. Lock được sinh trên Windows/Python 3.11 nên có `colorama` (dependency của pytest chỉ dùng trên Windows). Nên sinh lại trên môi trường chấm nếu cần lock đúng nền tảng.

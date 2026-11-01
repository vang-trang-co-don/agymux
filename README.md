# agymux

> **Antigravity Multi-Account Multiplexer & Proxy**  
> Tự động xoay tua đa tài khoản Google Cloud Code / Antigravity CLI (`agy`) khi hết quota (HTTP 429) hoặc lỗi xác thực (HTTP 401) mà không làm gián đoạn phiên làm việc.

---

## 🌟 Tính Năng Nổi Bật

- **Zero-Drop In-flight Replay**: Tự động buffer request và phát lại (replay) sang tài khoản tiếp theo ngay lập tức khi gặp HTTP 429 (Resource Exhausted) hoặc HTTP 401 (Token Expired), bảo toàn trọn vẹn luồng phản hồi streaming (SSE).
- **Multi-Account Pool & Tier Prioritization**: Quản lý nhiều tài khoản Google, hỗ trợ phân cấp gói dịch vụ (`ultra` > `pro` > `free`) và ưu tiên tài khoản tier cao.
- **Dynamic Cooldown Detection**: Phân tích header `Retry-After` và thông báo lỗi proto3 gRPC để đặt thời gian cooldown động chính xác cho từng tài khoản.
- **Selective TLS Interception (MitM)**: Chỉ can thiệp vào các endpoint Google Cloud Code (`cloudcode-pa.googleapis.com`, `aicode.googleapis.com`...). Tất cả các truy vấn mạng khác (npm, git, telemetry...) được truyền thẳng qua TCP CONNECT pass-through nguyên bản.
- **Combined CA Trust Store**: Tự động sinh Root CA nội bộ và hợp nhất với trust store hệ thống (`combined_ca.crt`), tự động nạp `SSL_CERT_FILE` & `NODE_EXTRA_CA_CERTS` cho `agy` mà không làm hỏng kết nối HTTPS thông thường.
- **Zero External Dependencies**: Viết hoàn toàn bằng Standard Library của Go (Go 1.22+), siêu nhẹ, compile nhanh, bảo mật và ổn định.

---

## 🚀 Cài Đặt Nhanh

Cài đặt tự động bằng 1 dòng lệnh (hỗ trợ Linux / macOS / Windows WSL):

```bash
curl -fsSL https://raw.githubusercontent.com/vang-trang-co-don/agymux/main/install.sh | bash
```

Script sẽ tự động:
1. Tải bản build binary tương ứng với hệ điều hành và CPU (`amd64` / `arm64`).
2. Hoặc tự động biên dịch từ mã nguồn nếu máy đã có `go`.
3. Đặt file thực thi vào `~/.local/bin/agymux`.

---

## 🛠️ Biên Dịch Thủ Công Từ Mã Nguồn

### Yêu cầu
- **Go** 1.22 trở lên.
- Đã cài đặt **agy** (Antigravity CLI).

```bash
git clone https://github.com/vang-trang-co-don/agymux.git
cd agymux
go build -o agymux ./cmd/agymux

# Di chuyển binary vào PATH (ví dụ ~/.local/bin)
mv agymux ~/.local/bin/
```

---

## 📖 Cách Sử Dụng

### 1. Quản lý tài khoản

#### Đăng nhập & thêm tài khoản vào Pool
```bash
agymux login
```
> Hỗ trợ cả mở trình duyệt tự động trên máy bàn và dán mã ủy quyền (hoặc link callback) trực tiếp trên terminal khi dùng SSH / VPS headless.

#### Xem danh sách tài khoản
```bash
agymux list
```

#### Thiết lập gói dịch vụ (Tier)
```bash
agymux tier [index|email] [free|pro|ultra]

# Ví dụ:
agymux tier 1 ultra
agymux tier user@gmail.com pro
```

#### Gỡ tài khoản khỏi Pool
```bash
agymux logout [index|email]
# Hoặc gõ `agymux logout` để chọn tương tác
```

---

### 2. Chạy agy thông qua agymux

Chỉ cần gõ `agymux` kèm theo tất cả các tham số bạn thường dùng với `agy`:

```bash
agymux
# hoặc truyền cờ của agy:
agymux --help
```

`agymux` sẽ tự động:
1. Mở proxy nền trên một cổng local ngẫu nhiên.
2. Thiết lập chứng chỉ CA nội bộ an toàn.
3. Cấp phát OAuth Bearer Token đang hoạt động.
4. Lắng nghe và xoay tua tài khoản tức thì nếu tài khoản hiện tại chạm trần Quota.

---

## 🧪 Chạy Kiểm Thử

Dự án đi kèm bộ test E2E đầy đủ:

```bash
# Chạy tất cả test
go test -v ./...

# Kiểm tra Race Condition
go test -race ./...
```

---

## 📄 License

MIT License.

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"agymux/internal/accounts"
	"agymux/internal/auth"
	"agymux/internal/ca"
	"agymux/internal/launcher"
	"agymux/internal/proxy"
)

const banner = `
=============================================================
  agymux — Antigravity Multi-Account Multiplexer & Proxy
=============================================================
`

func printHelp() {
	fmt.Print(banner)
	fmt.Print(`CÁCH SỬ DỤNG:
  agymux [lệnh] [tùy chọn...]
  agymux [cờ agy...]

CÁC LỆNH QUẢN LÝ TÀI KHOẢN:
  login              Đăng nhập và thêm tài khoản Google vào pool
                     (Hỗ trợ cả mở trình duyệt tự động & dán Auth Code từ terminal/SSH)
  list               Xem danh sách các tài khoản trong pool và trạng thái (Active/Standby/Cooldown)
  logout [index|email] Gỡ tài khoản khỏi pool (hỗ trợ chọn tương tác hoặc truyền tham số)
  tier [index|email] [tier] Cấu hình gói dịch vụ (ví dụ: free, pro, ultra) cho tài khoản
  help, -h, --help   Hiển thị thông tin trợ giúp này

CHẾ ĐỘ TỰ ĐỘNG CHẠY AGY:
  Chỉ cần gõ:
    agymux [tham số của agy...]

  agymux sẽ tự động:
  1. Khởi chạy proxy nền với cổng ngẫu nhiên.
  2. Thiết lập chứng chỉ CA nội bộ an toàn (SSL_CERT_FILE).
  3. Cấp phát Access Token đang hoạt động cho các yêu cầu Google Cloud Code.
  4. Tự động xoay tua sang tài khoản tiếp theo trong tích tắc khi gặp lỗi Quota (HTTP 429)
     mà KHÔNG làm gián đoạn cuộc hội thoại hay phải khởi động lại!
`)
}

func main() {
	args := os.Args[1:]

	if len(args) > 0 {
		cmd := args[0]
		switch cmd {
		case "help", "-h", "--help":
			printHelp()
			return

		case "list":
			pool, err := accounts.LoadPool()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Lỗi đọc danh sách tài khoản: %v\n", err)
				os.Exit(1)
			}
			pool.List()
			return

		case "login":
			pool, err := accounts.LoadPool()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Lỗi tải pool tài khoản: %v\n", err)
				os.Exit(1)
			}
			if err := auth.Login(pool); err != nil {
				fmt.Fprintf(os.Stderr, "Lỗi đăng nhập: %v\n", err)
				os.Exit(1)
			}
			return

		case "logout":
			pool, err := accounts.LoadPool()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Lỗi tải pool tài khoản: %v\n", err)
				os.Exit(1)
			}

			if len(args) > 1 {
				target := strings.TrimSpace(args[1])
				removeAccount(pool, target)
				return
			}

			// Interactive logout
			pool.List()
			if len(pool.Accounts) == 0 {
				return
			}

			fmt.Print("\n👉 Nhập số thứ tự (index) hoặc email của tài khoản cần logout > ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				input := strings.TrimSpace(scanner.Text())
				if input == "" {
					fmt.Println("Đã hủy thao tác logout.")
					return
				}
				removeAccount(pool, input)
			}
			return

		case "tier":
			pool, err := accounts.LoadPool()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Lỗi tải pool tài khoản: %v\n", err)
				os.Exit(1)
			}
			if len(args) < 3 {
				fmt.Fprintln(os.Stderr, "Cách dùng: agymux tier [index|email] [free|pro|ultra]")
				os.Exit(1)
			}
			target := strings.TrimSpace(args[1])
			tierName := strings.TrimSpace(args[2])
			setAccountTier(pool, target, tierName)
			return
		}
	}

	// Default behavior: Start in-process proxy, inject env, and launch agy
	caMgr, err := ca.EnsureCA("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Lỗi khởi tạo CA: %v\n", err)
		os.Exit(1)
	}

	pool, err := accounts.LoadPool()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cảnh báo tải pool: %v\n", err)
	}

	proxyServer, err := proxy.New(pool, caMgr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Lỗi khởi tạo proxy: %v\n", err)
		os.Exit(1)
	}

	if err := proxyServer.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Lỗi khởi chạy proxy: %v\n", err)
		os.Exit(1)
	}

	// Launch agy
	exitCode, err := launcher.Run(args, proxyServer.URL(), caMgr.CombinedCertPath())

	// Shutdown proxy
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	_ = proxyServer.Shutdown(shutdownCtx)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Lỗi khi chạy agy: %v\n", err)
		if exitCode == 0 {
			exitCode = 1
		}
	}

	os.Exit(exitCode)
}

func setAccountTier(pool *accounts.Pool, target, tierName string) {
	if idx, err := strconv.Atoi(target); err == nil {
		// 1-based index
		if idx < 1 || idx > len(pool.Accounts) {
			fmt.Fprintf(os.Stderr, "Lỗi: chỉ số tài khoản không hợp lệ (%d)\n", idx)
			os.Exit(1)
		}
		email := pool.Accounts[idx-1].Email
		if err := pool.SetAccountTier(email, tierName); err != nil {
			fmt.Fprintf(os.Stderr, "Lỗi: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Đã cập nhật tier [%s] cho tài khoản [%s].\n", tierName, email)
		return
	}

	if err := pool.SetAccountTier(target, tierName); err != nil {
		fmt.Fprintf(os.Stderr, "Lỗi: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Đã cập nhật tier [%s] cho tài khoản [%s].\n", tierName, target)
}

func removeAccount(pool *accounts.Pool, target string) {
	if idx, err := strconv.Atoi(target); err == nil {
		// 1-based index
		removed, err := pool.RemoveAccount(idx - 1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Lỗi: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Đã gỡ tài khoản [%s] khỏi agymux pool.\n", removed.Email)
		return
	}

	// Email
	removed, err := pool.RemoveByEmail(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Lỗi: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Đã gỡ tài khoản [%s] khỏi agymux pool.\n", removed.Email)
}


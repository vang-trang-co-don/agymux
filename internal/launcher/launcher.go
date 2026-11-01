package launcher

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
)

// Run executes agy with injected proxy environment variables and forwarded CLI arguments.
// It returns the child process exit code and any execution error.
func Run(agyArgs []string, proxyURL string, caCertPath string) (int, error) {
	agyPath, err := FindAgyExecutable()
	if err != nil {
		return 1, err
	}

	cmd := exec.Command(agyPath, agyArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Inject proxy settings and CA certificate into child process environment
	env := os.Environ()
	env = append(env,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"SSL_CERT_FILE="+caCertPath,
		"NODE_EXTRA_CA_CERTS="+caCertPath,
	)
	cmd.Env = env

	// Setup signal forwarding
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigChan)

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("không thể khởi chạy agy (%s): %w", agyPath, err)
	}

	// Forward signals to child process
	go func() {
		for sig := range sigChan {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	err = cmd.Wait()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}

	return 0, nil
}

// FindAgyExecutable locates the agy binary from PATH or well-known locations.
func FindAgyExecutable() (string, error) {
	// 1. Search in PATH
	if p, err := exec.LookPath("agy"); err == nil {
		return p, nil
	}

	// 2. Search in user local bin
	if home := os.Getenv("HOME"); home != "" {
		localBin := filepath.Join(home, ".local", "bin", "agy")
		if _, err := os.Stat(localBin); err == nil {
			return localBin, nil
		}
	}

	// 3. Search in system local bin
	if _, err := os.Stat("/usr/local/bin/agy"); err == nil {
		return "/usr/local/bin/agy", nil
	}

	return "", fmt.Errorf("không tìm thấy lệnh 'agy' trong PATH hoặc ~/.local/bin/agy")
}

package proxy

import (
	"agymux/internal/accounts"
	"agymux/internal/ca"
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Server struct {
	listener      net.Listener
	port          int
	pool          *accounts.Pool
	caMgr         *ca.CAManager
	overrides     map[string]string
	targetDomains []string
	server        *http.Server
	wg            sync.WaitGroup
	closed        chan struct{}
}

func New(pool *accounts.Pool, caMgr *ca.CAManager) (*Server, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("không thể mở cổng lắng nghe cho proxy: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	s := &Server{
		listener: listener,
		port:     port,
		pool:     pool,
		caMgr:    caMgr,
		overrides: make(map[string]string),
		targetDomains: []string{
			"cloudcode-pa.googleapis.com",
			"daily-cloudcode-pa.googleapis.com",
			"aicode.googleapis.com",
		},
		closed: make(chan struct{}),
	}

	// Parse AGYMUX_UPSTREAM_OVERRIDE (e.g. domain=host:port,domain2=host:port)
	if envOverrides := os.Getenv("AGYMUX_UPSTREAM_OVERRIDE"); envOverrides != "" {
		for _, pair := range strings.Split(envOverrides, ",") {
			parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(parts) == 2 {
				s.overrides[parts[0]] = parts[1]
			}
		}
	}

	s.server = &http.Server{
		Handler: http.HandlerFunc(s.handleHTTP),
	}

	return s, nil
}

func (s *Server) Start() error {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = s.server.Serve(s.listener)
	}()
	return nil
}

func (s *Server) Addr() string {
	return fmt.Sprintf("127.0.0.1:%d", s.port)
}

func (s *Server) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", s.port)
}

func (s *Server) Shutdown(ctx context.Context) error {
	select {
	case <-s.closed:
		return nil
	default:
		close(s.closed)
	}
	err := s.server.Shutdown(ctx)
	s.wg.Wait()
	return err
}

func (s *Server) isTargetDomain(host string) bool {
	h := host
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		h = hostOnly
	}
	h = strings.TrimSuffix(h, ".")

	for _, target := range s.targetDomains {
		if strings.EqualFold(h, target) || strings.HasSuffix(h, "."+target) {
			return true
		}
	}
	// Also intercept any *.googleapis.com
	if strings.HasSuffix(h, ".googleapis.com") {
		return true
	}
	return false
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}

	// Direct standard HTTP proxy request
	s.handleStandardHTTP(w, r)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	targetHost := r.Host
	isTarget := s.isTargetDomain(targetHost)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// 1. If NON-TARGET domain: raw TCP pass-through
	if !isTarget {
		s.passThrough(clientConn, targetHost)
		return
	}

	// 2. TARGET domain: MitM TLS Interception
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	hostOnly := targetHost
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		hostOnly = h
	}

	tlsCert, err := s.caMgr.GetCertificate(hostOnly)
	if err != nil {
		_ = clientConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		_ = tlsClientConn.Close()
		return
	}
	defer tlsClientConn.Close()

	reader := bufio.NewReader(tlsClientConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return // connection closed or read error
		}

		s.processInterceptedRequest(tlsClientConn, req, hostOnly)

		if req.Close {
			return
		}
	}
}

func (s *Server) passThrough(clientConn net.Conn, targetHost string) {
	defer clientConn.Close()

	destAddr := targetHost
	if _, _, err := net.SplitHostPort(targetHost); err != nil {
		destAddr = net.JoinHostPort(targetHost, "443")
	}

	if override, ok := s.overrides[destAddr]; ok {
		destAddr = override
	} else if h, _, err := net.SplitHostPort(destAddr); err == nil {
		if override, ok := s.overrides[h]; ok {
			destAddr = override
		}
	}

	upstream, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstream.Close()

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, clientConn)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, upstream)
	}()
	wg.Wait()
}

func (s *Server) processInterceptedRequest(clientConn net.Conn, req *http.Request, hostOnly string) {
	// Buffer request body
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}

	upstreamAddr := net.JoinHostPort(hostOnly, "443")
	useInsecureTLS := false
	if override, ok := s.overrides[hostOnly]; ok {
		upstreamAddr = override
		useInsecureTLS = true
	} else if override, ok := s.overrides[upstreamAddr]; ok {
		upstreamAddr = override
		useInsecureTLS = true
	}

	// Loop for in-flight rotation on 429 or 401
	maxRetries := 10
	triedAccounts := make(map[string]bool)
	refreshedAccounts := make(map[string]bool)

	for attempt := 0; attempt < maxRetries; attempt++ {
		// 1. Inject active token
		var activeEmail string
		if s.pool != nil {
			token, email, err := s.pool.GetActiveToken(triedAccounts)
			if err == nil && token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
				activeEmail = email
			}
		}
		if activeEmail != "" {
			triedAccounts[activeEmail] = true
		}

		// 2. Connect to upstream
		tlsConf := &tls.Config{
			ServerName:         hostOnly,
			InsecureSkipVerify: useInsecureTLS,
		}

		upstreamConn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", upstreamAddr, tlsConf)
		if err != nil {
			writeErrorResponse(clientConn, http.StatusBadGateway, fmt.Sprintf("Không thể kết nối tới upstream: %v", err))
			return
		}

		// Prepare cloned request to send upstream
		upReq := req.Clone(context.Background())
		upReq.URL.Scheme = "https"
		upReq.URL.Host = hostOnly
		if bodyBytes != nil {
			upReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			upReq.ContentLength = int64(len(bodyBytes))
		}

		if err := upReq.Write(upstreamConn); err != nil {
			_ = upstreamConn.Close()
			writeErrorResponse(clientConn, http.StatusBadGateway, fmt.Sprintf("Lỗi gửi request tới upstream: %v", err))
			return
		}

		upResp, err := http.ReadResponse(bufio.NewReader(upstreamConn), upReq)
		if err != nil {
			_ = upstreamConn.Close()
			writeErrorResponse(clientConn, http.StatusBadGateway, fmt.Sprintf("Lỗi đọc response từ upstream: %v", err))
			return
		}

		// 3. Catch HTTP 429 (Too Many Requests / RESOURCE_EXHAUSTED) or HTTP 401 (Unauthorized / Invalid Token)
		if upResp.StatusCode == http.StatusTooManyRequests || upResp.StatusCode == http.StatusUnauthorized {
			respBodyBytes, _ := io.ReadAll(upResp.Body)
			_ = upResp.Body.Close()
			upResp.Body = io.NopCloser(bytes.NewReader(respBodyBytes))

			var rotErr error = fmt.Errorf("no pool")
			var canRetry bool
			if s.pool != nil {
				if upResp.StatusCode == http.StatusTooManyRequests {
					cooldownDuration, _ := accounts.ParseQuotaCooldown(upResp.Header, respBodyBytes)
					_, _, rotErr = s.pool.RotateAccountOnQuota(activeEmail, "429 Too Many Requests", cooldownDuration)
					canRetry = s.pool.HasAvailableCandidate(triedAccounts)
				} else {
					// 401 Unauthorized: token expired, invalidated, or revoked
					sameAccountRefreshed, _, _, err := s.pool.RotateAccountOnAuthFailure(activeEmail, "401 Unauthorized")
					rotErr = err
					if sameAccountRefreshed && !refreshedAccounts[activeEmail] {
						// Token for activeEmail was successfully refreshed in place; allow retry with it
						refreshedAccounts[activeEmail] = true
						delete(triedAccounts, activeEmail)
						canRetry = true
					} else {
						canRetry = s.pool.HasAvailableCandidate(triedAccounts)
					}
				}
			}

			allowRetry := canRetry || (s.pool != nil && len(triedAccounts) < s.pool.AccountCount())
			if rotErr == nil && allowRetry && attempt < maxRetries-1 {
				_ = upstreamConn.Close()
				// Replay next attempt with new token!
				continue
			}

			// Cannot rotate (single account, all exhausted, or retries reached): return status to client
			defer upstreamConn.Close()
			defer upResp.Body.Close()
			_ = upResp.Write(clientConn)
			return
		}

		// 4. Success or non-retryable status: relay response directly to client
		defer upstreamConn.Close()
		defer upResp.Body.Close()

		if err := upResp.Write(clientConn); err != nil {
			return
		}
		return
	}
}

func (s *Server) handleStandardHTTP(w http.ResponseWriter, r *http.Request) {
	// Buffer body
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
	}

	targetURL := r.URL
	if !targetURL.IsAbs() {
		targetURL.Scheme = "http"
		targetURL.Host = r.Host
	}

	outReq, err := http.NewRequest(r.Method, targetURL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(outReq)
	if err == nil && resp.StatusCode == http.StatusBadRequest {
		bodyPeek, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if strings.Contains(string(bodyPeek), "HTTPS server") {
			targetURL.Scheme = "https"
			outReq, _ = http.NewRequest(r.Method, targetURL.String(), bytes.NewReader(bodyBytes))
			for k, vv := range r.Header {
				for _, v := range vv {
					outReq.Header.Add(k, v)
				}
			}
			resp, err = client.Do(outReq)
		} else {
			resp.Body = io.NopCloser(bytes.NewReader(bodyPeek))
		}
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func writeErrorResponse(conn net.Conn, status int, msg string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(msg), msg)
	_, _ = conn.Write([]byte(resp))
}

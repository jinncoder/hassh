package proxy

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"sshproxy/pkg/hassh"
	"sshproxy/pkg/storage"
)

func newTestRepository(t *testing.T) *storage.Repository {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	repo, err := storage.NewRepository(db)
	if err != nil {
		t.Fatalf("failed to init repository: %v", err)
	}
	return repo
}

// fakeUpstream is a minimal SSH-ish TCP server: it sends a banner
// immediately upon accept (like a real sshd would) and records whatever
// bytes each connection subsequently sends it. This is deliberately
// realistic about who-speaks-first, since that ordering is exactly what
// broke in earlier versions of the proxy.
type fakeUpstream struct {
	listener net.Listener
	banner   string
	accepts  atomic.Int32

	mu       sync.Mutex
	received [][]byte
}

func newFakeUpstream(t *testing.T, banner string) *fakeUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake upstream: %v", err)
	}
	u := &fakeUpstream{listener: ln, banner: banner}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			u.accepts.Add(1)
			go u.serve(conn)
		}
	}()
	return u
}

func (u *fakeUpstream) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if u.banner != "" {
		if _, err := conn.Write([]byte(u.banner)); err != nil {
			return
		}
	}

	u.mu.Lock()
	idx := len(u.received)
	u.received = append(u.received, nil)
	u.mu.Unlock()

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			u.mu.Lock()
			u.received[idx] = append(u.received[idx], buf[:n]...)
			u.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// allReceived returns a snapshot of the bytes received on every connection
// accepted so far, in acceptance order.
func (u *fakeUpstream) allReceived() [][]byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([][]byte, len(u.received))
	copy(out, u.received)
	return out
}

func (u *fakeUpstream) addr() string { return u.listener.Addr().String() }
func (u *fakeUpstream) close()       { _ = u.listener.Close() }

func dialProxyWithRetry(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			return conn
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("failed to dial proxy at %s: %v", addr, lastErr)
	return nil
}

func buildHandshakeStream(t *testing.T, banner string) []byte {
	t.Helper()
	payload := buildKexInitPayload(t)
	packet := buildKexInitPacket(payload, 8)
	return append([]byte(banner+"\r\n"), packet...)
}

// reserveEphemeralAddr grabs a free port and immediately releases it so the
// proxy server can bind to a known, currently-free address.
func reserveEphemeralAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve address: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// waitForUpstreamAccepts polls until the upstream's accept count reaches at
// least want, or fails the test after a timeout.
func waitForUpstreamAccepts(t *testing.T, u *fakeUpstream, want int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if u.accepts.Load() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("upstream accepts = %d, want >= %d", u.accepts.Load(), want)
}

// TestServer_BlockedClientNeverReachesUpstream is a regression test for the
// core fix: a blocklisted client's TCP bytes must never reach the real
// backend. NewServer itself causes one upstream connection (the one-time
// startup probe used to learn the banner), so this asserts no *additional*
// connection is made for the blocked client, not that the count stays at 0.
func TestServer_BlockedClientNeverReachesUpstream(t *testing.T) {
	repo := newTestRepository(t)
	upstream := newFakeUpstream(t, "SSH-2.0-FakeUpstream\r\n")
	defer upstream.close()

	kex := []string{"diffie-hellman-group14-sha256"}
	ciphers := []string{"aes128-ctr,aes256-ctr"}
	macs := []string{"hmac-sha2-256,hmac-sha2-512"}
	compression := []string{"none,zlib"}
	blockedHash := hassh.Calculate(kex, ciphers, macs, compression)

	if err := repo.BlockHASH(blockedHash, "test"); err != nil {
		t.Fatalf("failed to seed blocklist: %v", err)
	}

	proxyAddr := reserveEphemeralAddr(t)
	server, err := NewServer(proxyAddr, upstream.addr(), repo)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	baselineAccepts := upstream.accepts.Load() // the startup banner-probe connection

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Start(ctx) }()

	clientConn := dialProxyWithRetry(t, proxyAddr)
	defer func() { _ = clientConn.Close() }()

	// Read the banner the proxy sends immediately (from its cache, with no
	// upstream dial involved), matching real client behavior.
	bannerBuf := make([]byte, 256)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(bannerBuf)
	if err != nil || n == 0 {
		t.Fatalf("expected to receive a cached banner from the proxy, got n=%d err=%v", n, err)
	}

	stream := buildHandshakeStream(t, "SSH-2.0-BlockedClient")
	if _, err := clientConn.Write(stream); err != nil {
		t.Fatalf("failed to write handshake: %v", err)
	}

	readBuf := make([]byte, 16)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, readErr := clientConn.Read(readBuf)

	if n != 0 {
		t.Errorf("expected no further data forwarded to blocked client, got %d bytes", n)
	}
	if readErr == nil {
		t.Fatal("expected proxy to close the blocked client's connection, got no error")
	}
	if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("proxy left the blocked client's connection open until our read deadline instead of closing it: %v", readErr)
	}

	// Give the async DB-record goroutine a moment, then confirm no
	// additional upstream connection was made beyond the startup probe.
	time.Sleep(200 * time.Millisecond)
	if got := upstream.accepts.Load(); got != baselineAccepts {
		t.Errorf("blocked client caused %d additional connection(s) to upstream beyond the startup probe; want 0", got-baselineAccepts)
	}
}

// TestServer_AllowedClientReachesUpstream is the counterpart check: a client
// whose fingerprint is NOT blocklisted should still be proxied through to
// the real backend, with its handshake bytes actually reaching it.
func TestServer_AllowedClientReachesUpstream(t *testing.T) {
	repo := newTestRepository(t)
	upstream := newFakeUpstream(t, "SSH-2.0-FakeUpstream\r\n")
	defer upstream.close()

	proxyAddr := reserveEphemeralAddr(t)
	server, err := NewServer(proxyAddr, upstream.addr(), repo)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	baselineAccepts := upstream.accepts.Load()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Start(ctx) }()

	clientConn := dialProxyWithRetry(t, proxyAddr)
	defer func() { _ = clientConn.Close() }()

	bannerBuf := make([]byte, 256)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := clientConn.Read(bannerBuf); err != nil {
		t.Fatalf("failed to read proxy's banner: %v", err)
	}

	stream := buildHandshakeStream(t, "SSH-2.0-AllowedClient")
	if _, err := clientConn.Write(stream); err != nil {
		t.Fatalf("failed to write handshake: %v", err)
	}

	waitForUpstreamAccepts(t, upstream, baselineAccepts+1)

	// And the bytes that reached upstream should actually be the client's
	// handshake, not nothing / not something else.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		all := upstream.allReceived()
		if len(all) > int(baselineAccepts) {
			got := all[len(all)-1]
			if len(got) > 0 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("allowed client's handshake bytes never arrived at upstream")
}

// TestServer_UpstreamBannerMismatchRefusesConnection is a regression test
// for the case where the cached banner already sent to a client no longer
// matches what the real upstream currently presents (e.g. the backend was
// upgraded and restarted since the last probe/SIGHUP). RFC 4253 §8 binds
// both identification strings into the signed key-exchange hash, so a
// mismatch guarantees the client's host-key verification will fail -- the
// proxy must detect this itself and refuse to proxy, rather than relay a
// handshake it already knows is broken.
func TestServer_UpstreamBannerMismatchRefusesConnection(t *testing.T) {
	repo := newTestRepository(t)
	upstream := newFakeUpstream(t, "SSH-2.0-RealUpstream\r\n")
	defer upstream.close()

	proxyAddr := reserveEphemeralAddr(t)
	server, err := NewServer(proxyAddr, upstream.addr(), repo)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	baselineAccepts := upstream.accepts.Load() // the real startup probe, banner matches so far

	// Simulate the backend having changed its banner since the startup
	// probe (e.g. upgraded + restarted) without a SIGHUP refresh happening
	// yet -- directly mutate the cached value the way staleness would.
	server.bannerMu.Lock()
	server.upstreamBanner = "SSH-2.0-StaleCachedBanner\r\n"
	server.bannerMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Start(ctx) }()

	clientConn := dialProxyWithRetry(t, proxyAddr)
	defer func() { _ = clientConn.Close() }()

	bannerBuf := make([]byte, 256)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(bannerBuf)
	if err != nil || n == 0 {
		t.Fatalf("expected to receive the (stale) cached banner, got n=%d err=%v", n, err)
	}
	if got := string(bannerBuf[:n]); got != "SSH-2.0-StaleCachedBanner\r\n" {
		t.Fatalf("client received banner %q, want the stale cached banner", got)
	}

	stream := buildHandshakeStream(t, "SSH-2.0-SomeClient")
	if _, err := clientConn.Write(stream); err != nil {
		t.Fatalf("failed to write handshake: %v", err)
	}

	// The proxy should dial upstream (to discover the mismatch), then
	// refuse to proxy further and close the client's connection.
	waitForUpstreamAccepts(t, upstream, baselineAccepts+1)

	readBuf := make([]byte, 16)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, readErr := clientConn.Read(readBuf)
	if n != 0 {
		t.Errorf("expected no data relayed to the client after a banner mismatch, got %d bytes", n)
	}
	if readErr == nil {
		t.Fatal("expected the proxy to close the connection after detecting a banner mismatch, got no error")
	}
	if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("proxy left the connection open until our read deadline instead of refusing it: %v", readErr)
	}

	// And upstream must never have received the client's handshake bytes --
	// the mismatch is caught before anything client-controlled is forwarded.
	time.Sleep(200 * time.Millisecond)
	all := upstream.allReceived()
	if len(all) > 0 && len(all[len(all)-1]) != 0 {
		t.Errorf("expected upstream to receive no client bytes after a banner mismatch, got %d bytes", len(all[len(all)-1]))
	}
}

// TestServer_ClientThatWaitsForBannerIsNotDeadlocked is a direct regression
// test for the bug where a real SSH client -- which waits to receive the
// server's identification banner before sending anything -- would hang
// until handshakeTimeout and fall through to "proxying unclassified" on
// every single connection, because the proxy used to wait for the client
// before ever contacting (or otherwise satisfying) the "server" side.
func TestServer_ClientThatWaitsForBannerIsNotDeadlocked(t *testing.T) {
	repo := newTestRepository(t)
	upstream := newFakeUpstream(t, "SSH-2.0-FakeUpstream\r\n")
	defer upstream.close()

	proxyAddr := reserveEphemeralAddr(t)
	server, err := NewServer(proxyAddr, upstream.addr(), repo)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	baselineAccepts := upstream.accepts.Load()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Start(ctx) }()

	clientConn := dialProxyWithRetry(t, proxyAddr)
	defer func() { _ = clientConn.Close() }()

	// Mimic a real client: read (and block on) the server's banner FIRST,
	// before sending anything of our own.
	start := time.Now()
	bannerBuf := make([]byte, 256)
	_ = clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := clientConn.Read(bannerBuf)
	bannerLatency := time.Since(start)
	if err != nil || n == 0 {
		t.Fatalf("client never received a banner from the proxy (n=%d err=%v) -- this is the deadlock bug", n, err)
	}
	if bannerLatency >= handshakeTimeout {
		t.Fatalf("banner took %v to arrive (>= the %v handshake timeout) -- the client would have deadlocked", bannerLatency, handshakeTimeout)
	}

	// Only now, having received a server banner, does a real client send
	// its own banner + KEXINIT.
	stream := buildHandshakeStream(t, "SSH-2.0-RealisticClient")
	if _, err := clientConn.Write(stream); err != nil {
		t.Fatalf("failed to write handshake: %v", err)
	}

	// Classification (and, since this fingerprint isn't blocked, proxying)
	// should complete well within handshakeTimeout, not time out and fall
	// back to "unclassified".
	waitForUpstreamAccepts(t, upstream, baselineAccepts+1)
}

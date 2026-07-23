package proxy

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"sshproxy/pkg/hassh"
)

// buildKexInitPayload constructs a minimal, valid SSH_MSG_KEXINIT payload
// (message type + cookie + ten name-lists + first_kex_packet_follows +
// reserved), mirroring the fixture used in pkg/hassh's own tests.
func buildKexInitPayload(t *testing.T) []byte {
	t.Helper()

	payload := make([]byte, 0, 256)
	payload = append(payload, sshMsgKexInit)
	payload = append(payload, make([]byte, 16)...) // cookie

	addNameList := func(names string) {
		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, uint32(len(names)))
		payload = append(payload, lengthBytes...)
		payload = append(payload, []byte(names)...)
	}

	addNameList("diffie-hellman-group14-sha256")
	addNameList("ssh-rsa")
	addNameList("aes128-ctr,aes256-ctr")
	addNameList("aes128-ctr")
	addNameList("hmac-sha2-256,hmac-sha2-512")
	addNameList("hmac-sha2-256")
	addNameList("none,zlib")
	addNameList("none")
	addNameList("")
	addNameList("")

	payload = append(payload, 0)          // first_kex_packet_follows = false
	payload = append(payload, 0, 0, 0, 0) // reserved

	return payload
}

// buildKexInitPacket wraps a KEXINIT payload in the RFC 4253 §6 binary packet
// framing: uint32 packet_length, byte padding_length, payload, padding.
func buildKexInitPacket(payload []byte, paddingLen int) []byte {
	packetLen := 1 + len(payload) + paddingLen // padding_length byte + payload + padding

	packet := make([]byte, 0, 4+packetLen)
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, uint32(packetLen))
	packet = append(packet, lengthBytes...)
	packet = append(packet, byte(paddingLen))
	packet = append(packet, payload...)
	packet = append(packet, make([]byte, paddingLen)...)

	return packet
}

// pipeConn wraps net.Pipe's client side with RemoteAddr/deadline support
// matching what CaptureHandshake needs from a net.Conn.
func newTestConnPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	server, client = net.Pipe()
	return server, client
}

func TestCaptureHandshake_ValidHandshake(t *testing.T) {
	server, client := newTestConnPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	payload := buildKexInitPayload(t)
	packet := buildKexInitPacket(payload, 8)
	stream := append([]byte("SSH-2.0-OpenSSH_9.6\r\n"), packet...)

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write(stream)
		errCh <- err
	}()

	fp, buffered, err := CaptureHandshake(server, 2*time.Second)
	if err != nil {
		t.Fatalf("CaptureHandshake failed: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	if fp.ClientBanner != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("banner = %q, want SSH-2.0-OpenSSH_9.6", fp.ClientBanner)
	}

	wantHash := hassh.Calculate(
		[]string{"diffie-hellman-group14-sha256"},
		[]string{"aes128-ctr,aes256-ctr"},
		[]string{"hmac-sha2-256,hmac-sha2-512"},
		[]string{"none,zlib"},
	)
	if fp.Hash != wantHash {
		t.Errorf("hash = %s, want %s", fp.Hash, wantHash)
	}

	if len(buffered) != len(stream) {
		t.Errorf("buffered %d bytes, want %d (exact echo of consumed bytes)", len(buffered), len(stream))
	}
}

// TestCaptureHandshake_PaddingBelowMinimum verifies that a packet claiming
// less than the RFC 4253 §6 minimum of 4 padding bytes is never accepted as
// a valid handshake, even though the rest of the framing is well-formed.
func TestCaptureHandshake_PaddingBelowMinimum(t *testing.T) {
	server, client := newTestConnPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	payload := buildKexInitPayload(t)
	packet := buildKexInitPacket(payload, 2) // invalid: RFC requires >= 4
	stream := append([]byte("SSH-2.0-OpenSSH_9.6\r\n"), packet...)

	go func() {
		_, _ = client.Write(stream)
		_ = client.Close()
	}()

	_, _, err := CaptureHandshake(server, 300*time.Millisecond)
	if err == nil {
		t.Fatal("expected CaptureHandshake to fail on under-padded packet, got nil error")
	}
	if !errors.Is(err, ErrHandshakeIncomplete) && !errors.Is(err, net.ErrClosed) {
		// After the peer closes, the read loop should surface either our
		// budget-exceeded error or an EOF/closed-pipe style error -- both
		// indicate we correctly never synthesized a fingerprint.
		t.Logf("got error (acceptable): %v", err)
	}
}

// TestCaptureHandshake_BannerTruncated verifies oversized banners are capped
// at maxBannerLength so they can never overflow the banner storage column.
func TestCaptureHandshake_BannerTruncated(t *testing.T) {
	server, client := newTestConnPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	longBanner := "SSH-2.0-" + strings.Repeat("A", 400)
	payload := buildKexInitPayload(t)
	packet := buildKexInitPacket(payload, 8)
	stream := append([]byte(longBanner+"\r\n"), packet...)

	go func() {
		_, _ = client.Write(stream)
	}()

	fp, _, err := CaptureHandshake(server, 2*time.Second)
	if err != nil {
		t.Fatalf("CaptureHandshake failed: %v", err)
	}

	if len(fp.ClientBanner) != maxBannerLength {
		t.Errorf("banner length = %d, want %d (truncated)", len(fp.ClientBanner), maxBannerLength)
	}
}

// TestCaptureHandshake_TimeoutOnSlowClient verifies a client that never
// completes its handshake doesn't hang CaptureHandshake forever.
func TestCaptureHandshake_TimeoutOnSlowClient(t *testing.T) {
	server, client := newTestConnPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	go func() {
		_, _ = client.Write([]byte("SSH-2.0-slowclient")) // never sends \r\n
	}()

	start := time.Now()
	_, _, err := CaptureHandshake(server, 200*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("CaptureHandshake took %v, expected to bail out near the 200ms deadline", elapsed)
	}
}

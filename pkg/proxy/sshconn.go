package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"sshproxy/pkg/hassh"
)

const (
	// maxPacketSize is a sanity bound on the SSH_MSG_KEXINIT binary packet
	// length field; real-world KEXINIT packets are well under this.
	maxPacketSize = 35000

	// sshMsgKexInit is the SSH_MSG_KEXINIT message type (RFC 4253 §12).
	sshMsgKexInit = 20

	// maxCaptureSize bounds how many bytes we will buffer from a client
	// while looking for a complete, parseable banner + SSH_MSG_KEXINIT.
	// These bytes must be read off the socket and held in memory before we
	// can classify the connection, so the budget is deliberately small.
	maxCaptureSize = 8192

	// maxBannerLength caps the client identification string we extract,
	// log, and persist. RFC 4253 §4.2 limits identification strings to 255
	// bytes total (including the CR/LF); this also keeps banners within the
	// 255-byte width of the ssh_client_banners.banner database column, so a
	// client can't cause a storage failure just by sending an oversized fake
	// banner.
	maxBannerLength = 255

	// maxBannerProbeSize bounds readIdentificationLine's search for a
	// terminating CRLF. This is only ever pointed at the operator's own
	// configured upstream server (not arbitrary/untrusted input), so this
	// exists purely as a sanity backstop against a misbehaving backend, not
	// as a hardening measure against an adversary.
	maxBannerProbeSize = 4096
)

// ErrHandshakeIncomplete is returned when the capture budget (maxCaptureSize)
// is exhausted before a full banner + SSH_MSG_KEXINIT could be parsed. This is
// not necessarily malicious -- it can also mean the client is just slow, isn't
// speaking SSH at all, or sent a KEXINIT larger than our capture budget -- so
// callers should fail open (proxy unclassified) rather than treat this as a
// positive signal of anything.
var ErrHandshakeIncomplete = errors.New("no complete SSH handshake observed within capture budget")

// CaptureHandshake reads directly from conn -- independent of any proxying --
// until it can extract a HASSH fingerprint from the client's SSH version
// banner and SSH_MSG_KEXINIT, or until it exhausts its time or size budget.
//
// SECURITY: the caller MUST NOT forward any byte read here to the upstream
// server until it has decided the connection isn't blocked. That's what
// makes a "blocked" classification an actual block rather than a log entry
// written after the fact.
//
// This does NOT mean the caller must wait to dial upstream or to relay the
// *other* direction (upstream -> client): it must not, in fact, since
// real-world SSH clients wait to receive the server's own identification
// banner before sending anything themselves, so upstream needs to already be
// connected and relaying to the client concurrently with this call, or the
// client will simply hang until the timeout below fires. See the comment on
// Server.handleConnection for the full reasoning. What must stay gated is
// specifically the client -> upstream direction, not the connection itself.
//
// The bytes CaptureHandshake consumes from conn are returned in `buffered`
// regardless of outcome (success, timeout, or capture-limit exceeded). Those
// bytes have already been drained from the socket and cannot be read again
// from conn. If the caller decides to proceed with proxying, it MUST write
// `buffered` to the upstream connection before relaying any further reads
// from conn.
func CaptureHandshake(conn net.Conn, timeout time.Duration) (fp *hassh.Fingerprint, buffered []byte, err error) {
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, nil, fmt.Errorf("failed to set handshake read deadline: %w", err)
		}
		// Always clear the deadline before returning -- the caller may reuse
		// conn for ordinary, non-deadlined proxying afterward.
		defer func() {
			_ = conn.SetReadDeadline(time.Time{})
		}()
	}

	remoteAddr := conn.RemoteAddr().String()
	buf := make([]byte, 0, maxCaptureSize)
	chunk := make([]byte, 4096)

	for {
		if parsed, ok := tryParseHandshake(buf, remoteAddr); ok {
			return parsed, buf, nil
		}

		if len(buf) >= maxCaptureSize {
			return nil, buf, fmt.Errorf("%w (%d byte budget)", ErrHandshakeIncomplete, maxCaptureSize)
		}

		n, readErr := conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if readErr != nil {
			return nil, buf, readErr
		}
	}
}

// tryParseHandshake attempts to extract a HASSH fingerprint from captured
// bytes. ok is false when more data is needed (not necessarily an error) or
// when the buffered data is already unambiguously malformed; either way the
// caller keeps reading (bounded by maxCaptureSize) rather than failing fast,
// since re-parsing a small, bounded buffer is cheap.
func tryParseHandshake(buf []byte, remoteAddr string) (fp *hassh.Fingerprint, ok bool) {
	if len(buf) < 10 {
		return nil, false
	}

	// Step 1: find and parse the SSH version banner (RFC 4253 §4.2).
	idx := bytes.Index(buf, []byte("SSH-"))
	if idx == -1 {
		return nil, false
	}

	endIdx := bytes.Index(buf[idx:], []byte("\r\n"))
	if endIdx == -1 {
		return nil, false // banner line not fully buffered yet
	}

	clientBanner := string(buf[idx : idx+endIdx])
	if len(clientBanner) > maxBannerLength {
		clientBanner = clientBanner[:maxBannerLength]
	}
	bannerEnd := idx + endIdx + 2

	// Step 2: parse the binary SSH_MSG_KEXINIT packet that follows the banner.
	if len(buf) < bannerEnd+5 {
		return nil, false // need at least packet_length + padding_length
	}

	packetBuf := buf[bannerEnd:]
	packetLen := binary.BigEndian.Uint32(packetBuf[0:4])

	// A packetLen of 0 or one larger than any real KEXINIT will never
	// become valid no matter how much more data arrives, but we still just
	// report "not yet" here: the outer loop is bounded by maxCaptureSize, so
	// the cost of a few extra reads before giving up is negligible and this
	// keeps the parser a single pass with one exit path per failure mode.
	if packetLen < 1 || packetLen > maxPacketSize {
		return nil, false
	}

	totalPacketLen := 4 + int(packetLen)
	if len(packetBuf) < totalPacketLen {
		return nil, false // packet not fully buffered yet
	}

	paddingLen := int(packetBuf[4])
	// RFC 4253 §6: "There MUST be at least four bytes of padding." A packet
	// claiming less is malformed and, like the packetLen check above, will
	// never resolve into something valid.
	if paddingLen < 4 {
		return nil, false
	}

	payloadLen := int(packetLen) - paddingLen - 1
	if payloadLen <= 0 || 5+payloadLen > len(packetBuf) {
		return nil, false
	}

	payload := packetBuf[5 : 5+payloadLen]

	if len(payload) == 0 || payload[0] != sshMsgKexInit {
		return nil, false
	}

	kex, ciphers, macs, compression, err := hassh.ParseKexInit(payload)
	if err != nil {
		return nil, false
	}

	return &hassh.Fingerprint{
		Hash:         hassh.Calculate(kex, ciphers, macs, compression),
		ClientBanner: clientBanner,
		RemoteAddr:   remoteAddr,
	}, true
}

// readIdentificationLine reads from conn until it finds the SSH
// identification string's terminating CRLF (RFC 4253 §4.2), and returns that
// line verbatim (including the trailing CRLF).
//
// Because this reads whole chunks off the socket, it can end up holding a
// few bytes that arrived *after* the CRLF -- the start of whatever packet
// follows the banner. Those bytes are returned as `extra` so the caller can
// still forward them; dropping them would corrupt the stream.
func readIdentificationLine(conn net.Conn, timeout time.Duration) (line string, extra []byte, err error) {
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return "", nil, fmt.Errorf("failed to set read deadline: %w", err)
		}
		defer func() {
			_ = conn.SetReadDeadline(time.Time{})
		}()
	}

	buf := make([]byte, 0, 256)
	chunk := make([]byte, 256)

	for {
		if idx := bytes.Index(buf, []byte("\r\n")); idx != -1 {
			return string(buf[:idx+2]), append([]byte(nil), buf[idx+2:]...), nil
		}

		if len(buf) >= maxBannerProbeSize {
			return "", nil, fmt.Errorf("identification line exceeded %d bytes without a terminating CRLF", maxBannerProbeSize)
		}

		n, readErr := conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if readErr != nil {
			return "", nil, readErr
		}
	}
}

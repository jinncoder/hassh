package hassh

import (
	"context"
	"crypto/md5" // #nosec G401,G501 -- MD5 used for fingerprinting only
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// maxPayloadSize prevents DoS via huge KEXINIT packets
	maxPayloadSize = 16 * 1024 // 16KB

	// maxNameListLength prevents DoS via excessive memory allocation for a
	// single name-list. A name-list can never legitimately exceed the total
	// KEXINIT payload it's embedded in, so this is tied to maxPayloadSize
	// rather than an independent (and previously unreachable) constant --
	// the per-list check below is a cheap early rejection; the precise
	// "enough bytes remain" check that follows is what actually matters.
	maxNameListLength = maxPayloadSize

	// maxAlgorithmCount prevents DoS via excessive algorithm parsing
	maxAlgorithmCount = 1000

	// maxAlgorithmNameLength prevents DoS via single huge algorithm name.
	//
	// NOTE: RFC 4251 §6 requires algorithm/method identifiers to be at most
	// 64 characters. This is deliberately looser (128) because this package
	// is a passive fingerprinter, not a conforming SSH peer: real-world
	// clients occasionally send slightly non-compliant names (vendor
	// extensions, "@"-suffixed local names, typos in obscure forks), and
	// hard-rejecting those would lose fingerprinting coverage rather than
	// protect anything -- we never negotiate or act on these names, only
	// hash them. 128 remains a firm upper bound against pathological input.
	maxAlgorithmNameLength = 128

	// maxTotalAlgorithms limits total algorithms across all name-lists
	maxTotalAlgorithms = 5000

	// SSH_MSG_KEXINIT message type
	sshMsgKexInit = 20
)

var (
	// ErrInvalidAlgorithmName is returned when an algorithm name contains invalid characters
	ErrInvalidAlgorithmName = errors.New("invalid algorithm name")

	// ErrTooManyAlgorithms is returned when algorithm count exceeds limits
	ErrTooManyAlgorithms = errors.New("too many algorithms")

	// ErrNameListTooLarge is returned when name-list exceeds size limit
	ErrNameListTooLarge = errors.New("name-list too large")

	// ErrBufferTooShort is returned when buffer is insufficient for data
	ErrBufferTooShort = errors.New("buffer too short")

	// ErrInvalidPacket is returned for malformed packets
	ErrInvalidPacket = errors.New("invalid packet")

	// ErrPanic is returned when a panic is recovered
	ErrPanic = errors.New("panic during parsing")
)

// Fingerprint represents a HASSH fingerprint with client metadata
type Fingerprint struct {
	Hash         string
	ClientBanner string
	RemoteAddr   string
}

// HashAlgorithm specifies which hash algorithm to use
type HashAlgorithm int

const (
	// HashMD5 uses MD5 (original HASSH spec, fast but collision-prone)
	HashMD5 HashAlgorithm = iota
	// HashSHA256 uses SHA-256 (slower but collision-resistant)
	HashSHA256
)

// isValidAlgorithmName validates algorithm name per SSH RFC specifications.
//
// NOTE on the full-scan (no early-return) loop below: algorithm names in
// SSH_MSG_KEXINIT are sent in cleartext on the wire by design (that's the
// entire premise of HASSH fingerprinting), so there is no confidentiality
// boundary here for a network attacker's timing measurements to cross --
// early-returning would not leak anything a packet capture doesn't already
// reveal directly. The full scan is kept anyway as cheap, harmless defensive
// style (uniform validation cost regardless of input shape), not because it
// closes an actual side-channel.
func isValidAlgorithmName(name string) bool {
	if len(name) == 0 || len(name) > maxAlgorithmNameLength {
		return false
	}

	valid := true
	for i := 0; i < len(name); i++ {
		c := name[i]
		// Must be ASCII printable (33-126), excluding comma (44)
		if c < 33 || c > 126 || c == 44 {
			valid = false
		}
	}

	return valid
}

// sanitizeAlgorithmNames filters and validates algorithm names
func sanitizeAlgorithmNames(names []string) ([]string, error) {
	if len(names) == 0 {
		return []string{}, nil
	}

	// Count valid names first to avoid over-allocation
	validCount := 0
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name != "" {
			validCount++
		}
	}

	// Allocate exact capacity needed
	result := make([]string, 0, validCount)

	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue // Skip empty strings
		}

		// Validate algorithm name
		if !isValidAlgorithmName(name) {
			return nil, fmt.Errorf("%w: %q contains invalid characters", ErrInvalidAlgorithmName, name)
		}

		result = append(result, name)
	}

	return result, nil
}

// Calculate generates HASSH fingerprint from SSH key exchange algorithms
// Uses MD5 by default for compatibility with original HASSH specification
func Calculate(kex, ciphers, macs, compression []string) string {
	return CalculateWithHash(kex, ciphers, macs, compression, HashMD5)
}

// CalculateWithHash generates fingerprint using specified hash algorithm
func CalculateWithHash(kex, ciphers, macs, compression []string, algo HashAlgorithm) string {
	algorithms := fmt.Sprintf("%s;%s;%s;%s",
		strings.Join(kex, ","),
		strings.Join(ciphers, ","),
		strings.Join(macs, ","),
		strings.Join(compression, ","))

	switch algo {
	case HashSHA256:
		hash := sha256.Sum256([]byte(algorithms))
		return hex.EncodeToString(hash[:])
	default: // HashMD5
		hash := md5.Sum([]byte(algorithms)) // #nosec G401
		return hex.EncodeToString(hash[:])
	}
}

// parseNameList extracts SSH name-list from wire format with comprehensive security checks
// SECURITY: Includes panic recovery to prevent DoS via runtime panics
func parseNameList(data []byte, offset int) (names []string, newOffset int, err error) {
	// Panic recovery - prevents DoS via edge case panics
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: %v", ErrPanic, r)
			names = nil
			newOffset = offset
		}
	}()

	// Validate offset bounds
	if offset < 0 || offset >= len(data) {
		return nil, offset, fmt.Errorf("%w: invalid offset %d for buffer length %d", ErrBufferTooShort, offset, len(data))
	}

	// Check if we have enough bytes to read the length field
	if offset+4 > len(data) {
		return nil, offset, fmt.Errorf("%w: cannot read name-list length at offset %d", ErrBufferTooShort, offset)
	}

	length := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// Validate length before any conversion or arithmetic
	if length > maxNameListLength {
		return nil, offset, fmt.Errorf("%w: %d bytes (max: %d)", ErrNameListTooLarge, length, maxNameListLength)
	}

	// Safe to convert to int now
	listLen := int(length)

	// Check if we have enough remaining data (overflow-safe)
	if listLen > len(data)-offset {
		return nil, offset, fmt.Errorf("%w: need %d bytes for name-list, have %d", ErrBufferTooShort, listLen, len(data)-offset)
	}

	// Handle empty name-list
	if length == 0 {
		return []string{}, offset, nil
	}

	// SECURITY FIX: Force string copy to prevent memory aliasing
	// This prevents information disclosure if buffer is reused from a pool
	dataCopy := make([]byte, listLen)
	copy(dataCopy, data[offset:offset+listLen])
	nameList := string(dataCopy)
	offset += listLen

	// Split into individual algorithm names
	names = strings.Split(nameList, ",")

	// Enforce maximum algorithm count
	if len(names) > maxAlgorithmCount {
		return nil, offset, fmt.Errorf("%w: %d algorithms in name-list (max: %d)", ErrTooManyAlgorithms, len(names), maxAlgorithmCount)
	}

	// Sanitize and validate algorithm names
	sanitized, err := sanitizeAlgorithmNames(names)
	if err != nil {
		return nil, offset, err
	}

	return sanitized, offset, nil
}

// ParseKexInit extracts algorithm lists from SSH_MSG_KEXINIT (RFC 4253 §7.1) which specifies the complete packet structure:
//
//	byte         SSH_MSG_KEXINIT (20)
//	byte[16]     cookie (random bytes)
//	name-list    kex_algorithms
//	name-list    server_host_key_algorithms
//	name-list    encryption_algorithms_client_to_server
//	name-list    encryption_algorithms_server_to_client
//	name-list    mac_algorithms_client_to_server
//	name-list    mac_algorithms_server_to_client
//	name-list    compression_algorithms_client_to_server
//	name-list    compression_algorithms_server_to_client
//	name-list    languages_client_to_server
//	name-list    languages_server_to_client
//	boolean      first_kex_packet_follows
//	uint32       0 (reserved for future extension)
//
// with comprehensive security validations and panic recovery
//
// SECURITY: This is the primary public API and includes panic recovery to prevent
// crashes from malformed input reaching production systems.
func ParseKexInit(payload []byte) (kex, ciphers, macs, compression []string, err error) {
	// Panic recovery at API boundary - critical for production security
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: %v", ErrPanic, r)
			kex, ciphers, macs, compression = nil, nil, nil, nil
		}
	}()

	return parseKexInitImpl(payload)
}

// ParseKexInitWithContext adds cancellation support for long-running operations
func ParseKexInitWithContext(ctx context.Context, payload []byte) (kex, ciphers, macs, compression []string, err error) {
	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return nil, nil, nil, nil, ctx.Err()
	default:
	}

	// Panic recovery at API boundary
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: %v", ErrPanic, r)
			kex, ciphers, macs, compression = nil, nil, nil, nil
		}
	}()

	return parseKexInitImpl(payload)
}

// parseKexInitImpl contains the actual parsing logic (separated for testing)
func parseKexInitImpl(payload []byte) (kex, ciphers, macs, compression []string, err error) {
	// Validate payload size
	if len(payload) > maxPayloadSize {
		return nil, nil, nil, nil, fmt.Errorf("%w: payload size %d exceeds maximum %d", ErrInvalidPacket, len(payload), maxPayloadSize)
	}

	// Validate minimum packet size
	if len(payload) < 17 {
		return nil, nil, nil, nil, fmt.Errorf("%w: too short (%d bytes, minimum 17)", ErrInvalidPacket, len(payload))
	}

	// Verify message type
	if payload[0] != sshMsgKexInit {
		return nil, nil, nil, nil, fmt.Errorf("%w: wrong message type (got %d, expected %d)", ErrInvalidPacket, payload[0], sshMsgKexInit)
	}

	// Skip message type (1) + cookie (16)
	offset := 17

	// Track total algorithms to prevent accumulation DoS
	totalAlgorithms := 0

	// Helper to parse and track algorithm counts
	parseAndTrack := func(payload []byte, offset int, fieldName string) ([]string, int, error) {
		algorithms, newOffset, err := parseNameList(payload, offset)
		if err != nil {
			return nil, offset, fmt.Errorf("failed to parse %s: %w", fieldName, err)
		}

		totalAlgorithms += len(algorithms)
		if totalAlgorithms > maxTotalAlgorithms {
			return nil, newOffset, fmt.Errorf("%w: total algorithms %d exceeds limit %d", ErrTooManyAlgorithms, totalAlgorithms, maxTotalAlgorithms)
		}

		return algorithms, newOffset, nil
	}

	// Parse all name-lists per RFC 4253 §7.1
	if kex, offset, err = parseAndTrack(payload, offset, "kex_algorithms"); err != nil {
		return nil, nil, nil, nil, err
	}

	if _, offset, err = parseAndTrack(payload, offset, "server_host_key_algorithms"); err != nil {
		return nil, nil, nil, nil, err
	}

	if ciphers, offset, err = parseAndTrack(payload, offset, "encryption_algorithms_client_to_server"); err != nil {
		return nil, nil, nil, nil, err
	}

	if _, offset, err = parseAndTrack(payload, offset, "encryption_algorithms_server_to_client"); err != nil {
		return nil, nil, nil, nil, err
	}

	if macs, offset, err = parseAndTrack(payload, offset, "mac_algorithms_client_to_server"); err != nil {
		return nil, nil, nil, nil, err
	}

	if _, offset, err = parseAndTrack(payload, offset, "mac_algorithms_server_to_client"); err != nil {
		return nil, nil, nil, nil, err
	}

	if compression, offset, err = parseAndTrack(payload, offset, "compression_algorithms_client_to_server"); err != nil {
		return nil, nil, nil, nil, err
	}

	if _, offset, err = parseAndTrack(payload, offset, "compression_algorithms_server_to_client"); err != nil {
		return nil, nil, nil, nil, err
	}

	if _, offset, err = parseAndTrack(payload, offset, "languages_client_to_server"); err != nil {
		return nil, nil, nil, nil, err
	}

	if _, offset, err = parseAndTrack(payload, offset, "languages_server_to_client"); err != nil {
		return nil, nil, nil, nil, err
	}

	// Validate first_kex_packet_follows (boolean - 1 byte)
	if offset+1 > len(payload) {
		return nil, nil, nil, nil, fmt.Errorf("%w: cannot read first_kex_packet_follows", ErrBufferTooShort)
	}
	offset++

	// Validate reserved field (uint32 - 4 bytes)
	if offset+4 > len(payload) {
		return nil, nil, nil, nil, fmt.Errorf("%w: cannot read reserved field", ErrBufferTooShort)
	}

	return kex, ciphers, macs, compression, nil
}

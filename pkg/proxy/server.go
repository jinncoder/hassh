package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"sshproxy/pkg/filter"
	"sshproxy/pkg/storage"
)

const (
	// handshakeTimeout bounds how long we wait for a client to complete a
	// parseable banner + SSH_MSG_KEXINIT before giving up classification and
	// falling back to proxying the connection unclassified.
	handshakeTimeout = 5 * time.Second

	// maxConcurrentConnections bounds in-flight connections. Without a
	// bound, a flood of connections -- blocked or not -- can grow goroutines,
	// memory, and (for allowed connections) upstream connection counts
	// without limit.
	maxConcurrentConnections = 2048

	// upstreamBannerFetchTimeout bounds the one-time startup probe used to
	// detect the upstream's identification banner (and its SIGHUP refresh).
	upstreamBannerFetchTimeout = 10 * time.Second
)

// Server is a transparent SSH proxy with HASSH fingerprinting
type Server struct {
	listenAddr    string
	targetAddr    string
	repo          *storage.Repository
	blocklist     *filter.BlocklistFilter
	syslog        *SyslogWriter
	reloadChan    chan os.Signal
	connCounter   atomic.Uint64
	activeConns   sync.WaitGroup
	connSemaphore chan struct{}

	// upstreamBanner is the raw SSH identification line (including the
	// trailing CRLF) sent to every connecting client immediately, before we
	// know anything about them. It is probed once from the real upstream
	// server at startup -- see NewServer and Server.handleConnection for
	// why we cannot simply dial upstream per-connection to get this.
	//
	// Guarded by bannerMu since a SIGHUP reload refreshes it concurrently
	// with connections reading it.
	bannerMu       sync.RWMutex
	upstreamBanner string
}

// NewServer creates a proxy server. It dials targetAddr once at startup,
// reads its identification banner, and caches it for reuse across all
// future client connections -- see the comment on Server.handleConnection
// for why this caching exists at all rather than fetching fresh per
// connection, and Server.refreshUpstreamBanner for how it stays current.
func NewServer(listenAddr, targetAddr string, repo *storage.Repository) (*Server, error) {
	server := &Server{
		listenAddr:    listenAddr,
		targetAddr:    targetAddr,
		repo:          repo,
		reloadChan:    make(chan os.Signal, 1),
		connSemaphore: make(chan struct{}, maxConcurrentConnections),
	}

	banner, err := fetchUpstreamBanner(targetAddr, upstreamBannerFetchTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch upstream identification banner from %s: %w", targetAddr, err)
	}
	server.upstreamBanner = banner
	log.Printf("Fetched upstream banner from %s: %s", targetAddr, strings.TrimSuffix(banner, "\r\n"))

	// Initialize syslog (optional, continues if unavailable)
	syslogWriter, err := NewSyslogWriter()
	if err != nil {
		log.Printf("Warning: Failed to initialize syslog: %v", err)
		log.Println("Continuing without syslog support")
	} else {
		server.syslog = syslogWriter
		log.Println("Syslog initialized - writing to auth.log")
	}

	// Initial blocklist load
	if err := server.reloadBlocklist(); err != nil {
		return nil, fmt.Errorf("failed to load initial blocklist: %w", err)
	}

	// Setup SIGHUP handler for reload
	signal.Notify(server.reloadChan, syscall.SIGHUP)

	return server, nil
}

// fetchUpstreamBanner dials targetAddr once, reads its SSH identification
// line, and returns it (including the trailing CRLF) verbatim so it can
// later be replayed to clients without touching the real backend on their
// behalf. The probe connection is closed immediately after; it is never
// reused for actual proxying.
func fetchUpstreamBanner(targetAddr string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", targetAddr, timeout)
	if err != nil {
		return "", fmt.Errorf("failed to connect: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	line, _, err := readIdentificationLine(conn, timeout)
	if err != nil {
		return "", fmt.Errorf("failed to read identification banner: %w", err)
	}
	return line, nil
}

// currentBanner returns the banner to send to clients right now.
func (s *Server) currentBanner() string {
	s.bannerMu.RLock()
	defer s.bannerMu.RUnlock()
	return s.upstreamBanner
}

// refreshUpstreamBanner re-probes the upstream server and updates the
// cached banner. This is called on SIGHUP alongside the blocklist reload so
// long-running proxies don't keep presenting a stale version string after
// the real backend is upgraded and restarted -- the cache is only ever
// populated once at startup otherwise. See Server.handleConnection for the
// runtime check that catches staleness even between reloads.
func (s *Server) refreshUpstreamBanner() error {
	banner, err := fetchUpstreamBanner(s.targetAddr, upstreamBannerFetchTimeout)
	if err != nil {
		return err
	}

	s.bannerMu.Lock()
	s.upstreamBanner = banner
	s.bannerMu.Unlock()

	log.Printf("Refreshed upstream banner from %s: %s", s.targetAddr, strings.TrimSuffix(banner, "\r\n"))
	return nil
}

// reloadBlocklist loads blocked HASSH values from database into the blocklist
func (s *Server) reloadBlocklist() error {
	log.Println("Loading blocklist from database...")

	blockedHashes, err := s.repo.LoadBlockedHashes()
	if err != nil {
		return err
	}

	if s.blocklist == nil {
		s.blocklist = filter.NewBlocklistFilter()
	}

	s.blocklist.Reload(blockedHashes)

	log.Printf("Blocklist loaded: %d unique HASSH fingerprints", s.blocklist.Count())
	return nil
}

// acceptWithContext wraps Accept() to respect context cancellation
func acceptWithContext(ctx context.Context, listener net.Listener) (net.Conn, error) {
	type deadliner interface {
		SetDeadline(time.Time) error
	}

	if dl, ok := listener.(deadliner); ok {
		_ = dl.SetDeadline(time.Now().Add(1 * time.Second))

		defer func() {
			_ = dl.SetDeadline(time.Time{})
		}()
	}

	connChan := make(chan net.Conn, 1)
	errChan := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}
		connChan <- conn
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case conn := <-connChan:
		return conn, nil
	case err := <-errChan:
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				return nil, err
			}
		}
		return nil, err
	}
}

// Start begins accepting connections
func (s *Server) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer func() {
		_ = listener.Close()
	}()

	if s.syslog != nil {
		defer func() {
			_ = s.syslog.Close()
		}()
	}

	log.Printf("SSH proxy listening on %s -> %s", s.listenAddr, s.targetAddr)

	// Background reload handler
	go s.handleReloads(ctx)

	// Accept loop with context awareness
	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down, waiting for active connections to close...")
			s.activeConns.Wait()
			return ctx.Err()
		default:
		}

		conn, err := acceptWithContext(ctx, listener)
		if err != nil {
			if ctx.Err() != nil {
				s.activeConns.Wait()
				return ctx.Err()
			}

			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			log.Printf("Accept error: %v", err)
			continue
		}

		select {
		case s.connSemaphore <- struct{}{}:
		default:
			log.Printf("Connection limit (%d) reached, rejecting %s", maxConcurrentConnections, conn.RemoteAddr())
			_ = conn.Close()
			continue
		}

		s.activeConns.Add(1)
		go func() {
			defer func() {
				<-s.connSemaphore
				s.activeConns.Done()
			}()
			s.handleConnection(conn)
		}()
	}
}

// handleReloads listens for SIGHUP and reloads the blocklist and the
// cached upstream banner.
func (s *Server) handleReloads(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.reloadChan:
			log.Println("Received SIGHUP, reloading...")
			if err := s.reloadBlocklist(); err != nil {
				log.Printf("Failed to reload blocklist: %v", err)
			} else {
				log.Println("Blocklist reload complete")
			}
			if err := s.refreshUpstreamBanner(); err != nil {
				log.Printf("Failed to refresh upstream banner (keeping previous value): %v", err)
			}
		}
	}
}

// handleConnection processes a single SSH connection.
//
// A subtlety drives this function's structure: real-world SSH clients
// (OpenSSH included) wait to receive the SERVER's identification banner
// before sending anything themselves. This proxy is a transparent,
// byte-level relay -- it must never fabricate its own banner for the *real*
// end-to-end exchange, because the identification strings are hashed into
// the key exchange (RFC 4253 §8) and substituting one would break host-key
// verification between the real client and server.
//
// The resolution: at startup, we already know exactly
// what the upstream's banner looks like, byte-for-byte. So each connection
// sends the client that cached banner immediately -- with no upstream
// dial at all -- which is enough to satisfy a real client's "wait for the
// server" step and get it talking. We classify its response locally. Only
// for connections that turn out not to be blocked do we then dial the real
// upstream, at which point we must consume and discard *that* connection's
// own live banner ourselves (the client has already been sent one) before
// relaying everything that follows it untouched in both directions.
//
// Net effect: a blocked client causes zero upstream connections, and none
// of its handshake or negotiation data -- nor any possibility of completing
// key exchange or authentication -- ever reaches the backend.
func (s *Server) handleConnection(clientConn net.Conn) {
	defer func() {
		_ = clientConn.Close()
	}()

	connID := s.connCounter.Add(1)

	clientAddr := clientConn.RemoteAddr().(*net.TCPAddr)
	clientIP := clientAddr.IP.String()
	clientPort := clientAddr.Port

	localAddr := clientConn.LocalAddr().(*net.TCPAddr)
	proxyIP := localAddr.IP.String()
	proxyPort := localAddr.Port

	if _, err := clientConn.Write([]byte(s.currentBanner())); err != nil {
		log.Printf("[conn:%d] Failed to send banner to %s port %d: %v", connID, clientIP, clientPort, err)
		return
	}

	fp, buffered, captureErr := CaptureHandshake(clientConn, handshakeTimeout)

	var username string // reserved: this proxy operates pre-auth, so never populated today

	if captureErr == nil {
		blocked := s.blocklist.Contains(fp.Hash)

		// Record every classified connection (allowed or blocked) so the
		// blocklist/stats reflect reality even for connections we refuse to
		// proxy further.
		go func() {
			if err := s.repo.RecordConnection(clientIP, fp.Hash, fp.ClientBanner, blocked); err != nil {
				log.Printf("[conn:%d] Failed to record connection: %v", connID, err)
			}
		}()

		if s.syslog != nil {
			_ = s.syslog.LogHandshake(connID, clientIP, clientPort, proxyIP, proxyPort, "", 0, s.targetAddr, fp.Hash, fp.ClientBanner)
			_ = s.syslog.LogConnection(connID, clientIP, clientPort, proxyIP, proxyPort, "", 0, s.targetAddr, blocked)
		}

		if blocked {
			log.Printf("[conn:%d] BLOCKED (upstream never contacted): %s port %d -> %s port %d (HASSH: %s, Banner: %s)",
				connID, clientIP, clientPort, proxyIP, proxyPort, fp.Hash, fp.ClientBanner)
			return
		}

		log.Printf("[conn:%d] ALLOWED: %s port %d -> %s port %d (HASSH: %s, Banner: %s)",
			connID, clientIP, clientPort, proxyIP, proxyPort, fp.Hash, fp.ClientBanner)
	} else {
		// No fingerprint could be extracted (slow client, non-SSH traffic,
		// KEXINIT larger than our capture budget, etc). We have no basis to
		// block, so fail open and proxy the connection through unclassified
		// rather than breaking legitimate-but-unusual clients.
		log.Printf("[conn:%d] Could not classify handshake for %s port %d: %v (proxying unclassified)",
			connID, clientIP, clientPort, captureErr)
	}

	// Only connections that were not blocked reach the upstream dial.
	upstreamConn, err := net.Dial("tcp", s.targetAddr)
	if err != nil {
		log.Printf("[conn:%d] Failed to connect to upstream: %v", connID, err)
		if s.syslog != nil {
			_ = s.syslog.LogError(connID, clientIP, fmt.Sprintf("Failed to connect to upstream %s: %v", s.targetAddr, err))
		}
		return
	}
	defer func() {
		_ = upstreamConn.Close()
	}()

	// The real upstream sends its own live banner as the first bytes of
	// this fresh connection. The client already received a (cached) banner
	// from us above, so this one must be consumed here, not relayed --
	// forwarding both would hand the client two identification lines and a
	// corrupted stream. `extra` is whatever the same read happened to also
	// pick up past the CRLF (the start of upstream's own KEXINIT); it must
	// still reach the client, just not as part of the banner.
	liveBanner, extra, err := readIdentificationLine(upstreamConn, handshakeTimeout)
	if err != nil {
		log.Printf("[conn:%d] Failed to read upstream banner: %v", connID, err)
		return
	}

	// RFC 4253 §8: the key-exchange hash H includes both V_C and V_S
	// verbatim, and the backend signs H with its host key. We already
	// committed the client to a specific V_S (the cached banner sent
	// above) before we knew what the backend would say on THIS
	// connection. If the two don't match exactly, the client will compute
	// a different H than the backend signed, and host-key verification
	// will fail on the client's end every time -- not intermittently --
	// surfacing there as an opaque signature-verification error with
	// nothing to point back at this proxy. Since that outcome is certain,
	// not speculative, refuse the connection here instead of proxying a
	// handshake we already know is broken.
	cachedBanner := s.currentBanner()
	if liveBanner != cachedBanner {
		log.Printf("[conn:%d] Upstream's live banner (%q) does not match the cached banner already sent to the client (%q) -- the client's key exchange WILL fail host-key verification (RFC 4253 §8 binds both identification strings into the signed exchange hash), so refusing to proxy this connection. This means the cached banner has gone stale (the backend's identification string changed since startup or the last SIGHUP) -- send SIGHUP or restart the proxy to re-probe it.",
			connID, strings.TrimSuffix(liveBanner, "\r\n"), strings.TrimSuffix(cachedBanner, "\r\n"))
		if s.syslog != nil {
			_ = s.syslog.LogError(connID, clientIP, fmt.Sprintf("Upstream banner mismatch: live=%q cached=%q", liveBanner, cachedBanner))
		}
		return
	}

	upstreamLocalAddr := upstreamConn.LocalAddr().(*net.TCPAddr)
	upstreamLocalIP := upstreamLocalAddr.IP.String()
	upstreamLocalPort := upstreamLocalAddr.Port
	upstreamRemoteAddr := upstreamConn.RemoteAddr().String()

	defer func() {
		if s.syslog != nil {
			_ = s.syslog.LogDisconnect(connID, clientIP, clientPort, proxyIP, proxyPort, upstreamLocalIP, upstreamLocalPort, s.targetAddr, username)
		}
		log.Printf("[conn:%d] Disconnected from %s port %d -> %s port %d -> %s port %d -> %s",
			connID, clientIP, clientPort, proxyIP, proxyPort, upstreamLocalIP, upstreamLocalPort, s.targetAddr)
	}()

	log.Printf("[conn:%d] Proxying: %s port %d -> %s port %d -> %s port %d -> %s",
		connID, clientIP, clientPort, proxyIP, proxyPort, upstreamLocalIP, upstreamLocalPort, upstreamRemoteAddr)

	// Replay whatever bytes were already drained from clientConn while
	// classifying the handshake -- they can't be re-read from the socket.
	if len(buffered) > 0 {
		if _, err := upstreamConn.Write(buffered); err != nil {
			log.Printf("[conn:%d] Failed to replay captured handshake bytes upstream: %v", connID, err)
			return
		}
	}

	// Likewise relay whatever trailed the upstream's own banner in the same
	// read, before starting the generic bidirectional copy below.
	if len(extra) > 0 {
		if _, err := clientConn.Write(extra); err != nil {
			log.Printf("[conn:%d] Failed to relay upstream's post-banner bytes to client: %v", connID, err)
			return
		}
	}

	// Bidirectional copy with proper cleanup
	done := make(chan error, 2)

	go func() {
		_, err := io.Copy(upstreamConn, clientConn)
		if tcpConn, ok := upstreamConn.(*net.TCPConn); ok {
			err = tcpConn.CloseWrite()
		}
		done <- err
	}()

	go func() {
		_, err := io.Copy(clientConn, upstreamConn)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			err = tcpConn.CloseWrite()
		}
		done <- err
	}()

	// Wait for both directions to complete
	<-done
	<-done
}

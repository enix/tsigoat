// Package dnsserver serves DNS UPDATE requests (RFC 2136) authenticated with
// TSIG (RFC 8945) over UDP and TCP, and applies them to the backends.
//
// It also answers the SOA queries that some clients send to find the zone of
// a name, and nothing else: tsigoat is not a name server.
package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/auth"
	"github.com/enix/tsigoat/internal/backend"
)

// DefaultTimeout bounds the processing of one request when Options set none.
const DefaultTimeout = 10 * time.Second

// bindAttempts bounds the attempts to find a port free for both UDP and TCP,
// when listening on port 0.
const bindAttempts = 10

// Zone is a zone that the server accepts updates for.
type Zone struct {
	// Name is the canonical name of the zone.
	Name string
	// Backend holds the zone, for the update engine of tsigoat.
	Backend backend.Backend
	// Relay, set in place of Backend, evaluates the updates of the zone
	// itself: the server checks an update and its policy, then relays it.
	Relay backend.Relay
	// BackendName names the backend in messages.
	BackendName string
	Policy      *auth.Policy
	// MinTTL is the lowest TTL that Backend writes, which the server raises
	// the lower TTLs of an update to; zero when it writes any TTL.
	MinTTL uint32
}

// Options configure a server.
type Options struct {
	// Listen holds the addresses to listen on, for both UDP and TCP. Port 0
	// picks a port free for both.
	Listen  []string
	Keyring *auth.Keyring
	Zones   []Zone
	Logger  *slog.Logger
	// Timeout bounds the processing of one request, backend calls included;
	// DefaultTimeout when zero.
	Timeout time.Duration
	// Observer, when set, receives an Answer for every response.
	Observer Observer
}

// Observer receives a description of every response.
type Observer interface {
	Observe(answer *Answer)
}

// Answer describes a response. Its fields take a bounded set of values, fit
// for metric labels: names come from the configuration, never from the
// request alone.
type Answer struct {
	// Opcode and Rcode are mnemonics, such as UPDATE and NOERROR.
	Opcode string
	Rcode  string
	// Zone is the served zone that the request names, "" otherwise.
	Zone string
	// Key and Algorithm identify the TSIG key of a request whose signature
	// is valid; "" for unsigned requests.
	Key       string
	Algorithm string
	// TSIGError is the TSIG error of a request whose signature does not
	// verify, such as BADSIG; "" otherwise.
	TSIGError string
	Duration  time.Duration
}

// Server is a DNS UPDATE server.
type Server struct {
	listen  []string
	keyring *auth.Keyring
	zones   map[string]*servedZone
	// served holds the canonical names of the zones.
	served   []string
	logger   *slog.Logger
	timeout  time.Duration
	observer Observer

	mu      sync.Mutex
	servers []*dns.Server
	addrs   []string
	// errs receives the errors that stop a listener.
	errs chan error
}

// The answers to the SOA queries of a zone reuse its SOA, or the failure to
// read it, for a while: since anyone may send them, they must not reach the
// backend each time.
const (
	soaCacheTTL   = 30 * time.Second
	soaFailureTTL = 5 * time.Second
)

// servedZone is a zone with the lock that serializes its updates, unless a
// relay evaluates them.
type servedZone struct {
	Zone
	// lock is a channel rather than a mutex, so that waiting for it honours
	// the deadline of the request.
	lock chan struct{}

	// soaMu guards the SOA cache, and serializes its refreshes.
	soaMu      sync.Mutex
	soa        dns.RR
	soaErr     error
	soaExpires time.Time
}

// New returns a server.
func New(options *Options) (*Server, error) {
	if len(options.Listen) == 0 {
		return nil, errors.New("no address to listen on")
	}
	if options.Keyring == nil || options.Logger == nil {
		return nil, errors.New("missing keyring or logger")
	}
	s := &Server{
		listen:   options.Listen,
		keyring:  options.Keyring,
		zones:    make(map[string]*servedZone, len(options.Zones)),
		logger:   options.Logger,
		timeout:  options.Timeout,
		observer: options.Observer,
	}
	if s.timeout <= 0 {
		s.timeout = DefaultTimeout
	}
	for _, z := range options.Zones {
		name := dns.CanonicalName(z.Name)
		if _, duplicate := s.zones[name]; duplicate {
			return nil, fmt.Errorf("duplicate zone %s", name)
		}
		if (z.Backend == nil) == (z.Relay == nil) || z.Policy == nil {
			return nil, fmt.Errorf("zone %s: set a policy, and either a backend or a relay", name)
		}
		z.Name = name
		s.zones[name] = &servedZone{Zone: z, lock: make(chan struct{}, 1)}
		s.served = append(s.served, name)
	}
	return s, nil
}

// Start listens on every address and serves in the background. It fails if
// an address cannot be bound, without leaving any listener behind.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.servers != nil {
		return errors.New("the server is already started")
	}

	s.errs = make(chan error, 2*len(s.listen))
	var servers []*dns.Server
	var addrs []string
	for _, address := range s.listen {
		started, addr, err := s.serve(ctx, address)
		servers = append(servers, started...)
		if err != nil {
			for _, server := range servers {
				_ = server.ShutdownContext(ctx)
			}
			return fmt.Errorf("listening on %s: %w", address, err)
		}
		addrs = append(addrs, addr)
	}
	s.servers, s.addrs = servers, addrs
	for _, addr := range addrs {
		s.logger.InfoContext(ctx, "listening", "address", addr)
	}
	return nil
}

// serve listens on an address over UDP and TCP, and serves both in the
// background. It returns the servers started, and the address bound.
func (s *Server) serve(ctx context.Context, address string) ([]*dns.Server, string, error) {
	packetConn, listener, err := listen(ctx, address)
	if err != nil {
		return nil, "", err
	}
	udp, tcp := s.newServer(), s.newServer()
	udp.PacketConn, tcp.Listener = packetConn, listener
	if err := s.activate(udp); err != nil {
		_ = packetConn.Close()
		_ = listener.Close()
		return nil, "", err
	}
	if err := s.activate(tcp); err != nil {
		_ = listener.Close()
		return []*dns.Server{udp}, "", err
	}
	return []*dns.Server{udp, tcp}, packetConn.LocalAddr().String(), nil
}

func (s *Server) newServer() *dns.Server {
	return &dns.Server{
		Handler:       s,
		UDPSize:       dns.MaxMsgSize,
		TsigProvider:  s.keyring,
		MsgAcceptFunc: accept,
	}
}

// activate serves in the background, once the server is ready.
func (s *Server) activate(server *dns.Server) error {
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()

	select {
	case <-started:
		go func() {
			if err := <-done; err != nil {
				s.errs <- err
			}
		}()
		return nil
	case err := <-done:
		if err == nil {
			err = errors.New("stopped while starting")
		}
		return err
	}
}

// listen binds a UDP socket and a TCP listener to the same address.
func listen(ctx context.Context, address string) (net.PacketConn, net.Listener, error) {
	var config net.ListenConfig
	for attempt := 1; ; attempt++ {
		packetConn, err := config.ListenPacket(ctx, "udp", address)
		if err != nil {
			return nil, nil, fmt.Errorf("UDP: %w", err)
		}
		listener, err := config.Listen(ctx, "tcp", packetConn.LocalAddr().String())
		if err == nil {
			return packetConn, listener, nil
		}
		_ = packetConn.Close()
		if !strings.HasSuffix(address, ":0") || attempt == bindAttempts {
			return nil, nil, fmt.Errorf("TCP: %w", err)
		}
	}
}

// Addrs returns the addresses the server listens on, once started.
func (s *Server) Addrs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.addrs...)
}

// Shutdown stops listening, then waits for the requests in progress until
// ctx is done. Every listener stops at once: none may accept requests while
// another one waits for its own.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	servers := s.servers
	s.mu.Unlock()

	errs := make([]error, len(servers))
	var wg sync.WaitGroup
	for i, server := range servers {
		wg.Go(func() { errs[i] = server.ShutdownContext(ctx) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// CheckZones checks every zone through its backend, and returns an error for
// every zone that fails: it reads the SOA of a zone of the update engine, and
// lets a relay check its zones.
func (s *Server) CheckZones(ctx context.Context) []error {
	var errs []error
	for _, name := range s.served {
		z := s.zones[name]
		var err error
		if z.Relay != nil {
			err = z.Relay.Check(ctx, name)
		} else {
			_, err = lookupSOA(ctx, z)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("zone %s on backend %s: %w", name, z.BackendName, err))
		}
	}
	return errs
}

// Run serves until ctx is done or a listener fails, then shuts down
// gracefully.
func (s *Server) Run(ctx context.Context) error {
	if err := s.Start(ctx); err != nil {
		return err
	}
	var err error
	select {
	case <-ctx.Done():
		s.logger.InfoContext(ctx, "shutting down")
	case err = <-s.errs:
		s.logger.ErrorContext(ctx, "a listener failed, shutting down", "error", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.timeout+time.Second)
	defer cancel()
	return errors.Join(err, s.Shutdown(shutdownCtx))
}

// accept lets every request through to the handler, which answers the
// malformed ones itself, signed when possible. Responses are dropped.
func accept(header dns.Header) dns.MsgAcceptAction {
	const qr = 1 << 15
	if header.Bits&qr != 0 {
		return dns.MsgIgnore
	}
	return dns.MsgAccept
}

// cachedSOA returns the SOA of the zone, which it reads from the backend at
// most once per soaCacheTTL, or per soaFailureTTL after a failure. fetched
// tells whether this call read the backend.
func (z *servedZone) cachedSOA(ctx context.Context) (soa dns.RR, fetched bool, err error) {
	z.soaMu.Lock()
	defer z.soaMu.Unlock()
	now := time.Now()
	if !now.Before(z.soaExpires) {
		z.soa, z.soaErr = lookupSOA(ctx, z)
		ttl := soaCacheTTL
		if z.soaErr != nil {
			ttl = soaFailureTTL
		}
		z.soaExpires, fetched = now.Add(ttl), true
	}
	if z.soaErr != nil {
		return nil, fetched, z.soaErr
	}
	return dns.Copy(z.soa), fetched, nil
}

// acquire takes the lock of the zone, unless ctx ends first.
func (z *servedZone) acquire(ctx context.Context) error {
	select {
	case z.lock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting for the lock of zone %s: %w", z.Name, ctx.Err())
	}
}

func (z *servedZone) release() {
	<-z.lock
}

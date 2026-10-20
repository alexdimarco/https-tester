// Package localapi is the workbench's local HTTP boundary. It binds only to
// loopback, protects every sensitive route with a per-launch capability secret,
// validates the Host header against DNS-rebinding, and sets a restrictive
// Content Security Policy. Binding to loopback alone is treated as insufficient:
// a malicious web page must not be able to drive the diagnostic process.
package localapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/alexdimarco/https-tester/internal/app"
	"github.com/alexdimarco/https-tester/internal/web"
)

const maxBodyBytes = 1 << 20 // 1 MiB

// Server owns the listener, the capability secrets, and the routes.
type Server struct {
	session    *app.Session
	ln         net.Listener
	httpServer *http.Server

	bootstrapToken string
	capability     string

	mu            sync.Mutex
	bootstrapUsed bool

	shutdownOnce sync.Once
	shutdownCh   chan struct{}
}

// New binds to 127.0.0.1:0, generates the launch secrets, and wires routes.
func New(session *app.Session) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("could not bind local listener: %w", err)
	}
	s := &Server{
		session:        session,
		ln:             ln,
		bootstrapToken: randToken(),
		capability:     randToken(),
		shutdownCh:     make(chan struct{}),
	}
	session.SetSelfAuthority(ln.Addr().String())
	s.httpServer = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

// Addr is the loopback address the server listens on.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// BootstrapURL is the URL to open, carrying the single-use token in the
// fragment so it is not sent to the server as part of the request.
func (s *Server) BootstrapURL() string {
	return "http://" + s.ln.Addr().String() + "/#b=" + s.bootstrapToken
}

// Serve blocks serving requests until the server is shut down.
func (s *Server) Serve() error { return s.httpServer.Serve(s.ln) }

// ShutdownRequested is closed when a shutdown has been requested via the API.
func (s *Server) ShutdownRequested() <-chan struct{} { return s.shutdownCh }

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error { return s.httpServer.Shutdown(ctx) }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.wrap(false, s.handleIndex))
	mux.HandleFunc("GET /app.js", s.wrap(false, s.handleAsset("assets/app.js", "text/javascript; charset=utf-8")))
	mux.HandleFunc("GET /style.css", s.wrap(false, s.handleAsset("assets/style.css", "text/css; charset=utf-8")))
	mux.HandleFunc("POST /api/bootstrap", s.wrap(false, s.handleBootstrap))
	mux.HandleFunc("GET /api/capabilities", s.wrap(true, s.handleCapabilities))
	mux.HandleFunc("POST /api/runs", s.wrap(true, s.handleCreateRun))
	mux.HandleFunc("POST /api/runs/{id}/next", s.wrap(true, s.handleNext))
	mux.HandleFunc("GET /api/runs/{id}", s.wrap(true, s.handleGetRun))
	mux.HandleFunc("GET /api/runs/{id}/summary", s.wrap(true, s.handleSummary))
	mux.HandleFunc("GET /api/runs/{id}/assessment", s.wrap(true, s.handleAssessment))
	mux.HandleFunc("GET /api/runs/{id}/profiles", s.wrap(true, s.handleProfiles))
	mux.HandleFunc("POST /api/runs/{id}/imports", s.wrap(true, s.handleImport))
	mux.HandleFunc("POST /api/runs/{id}/export", s.wrap(true, s.handleExport))
	mux.HandleFunc("POST /api/shutdown", s.wrap(true, s.handleShutdown))
	return mux
}

// wrap applies security headers, Host and Origin checks, and (when needCap)
// capability authorization.
func (s *Server) wrap(needCap bool, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if !s.hostAllowed(r.Host) {
			writeErr(w, http.StatusForbidden, "request rejected: unexpected Host header")
			return
		}
		if !s.originAllowed(r) {
			writeErr(w, http.StatusForbidden, "request rejected: cross-origin request")
			return
		}
		if needCap && !s.capabilityOK(r) {
			writeErr(w, http.StatusUnauthorized, "missing or invalid session capability")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		h(w, r)
	}
}

func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy",
		"default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; connect-src 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
}

func (s *Server) hostAllowed(host string) bool {
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	_, selfPort, _ := net.SplitHostPort(s.ln.Addr().String())
	if port != selfPort {
		return false
	}
	h, _, _ := net.SplitHostPort(host)
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // same-origin navigations and some fetches omit Origin
	}
	_, selfPort, _ := net.SplitHostPort(s.ln.Addr().String())
	for _, ok := range []string{
		"http://127.0.0.1:" + selfPort,
		"http://localhost:" + selfPort,
	} {
		if origin == ok {
			return true
		}
	}
	return false
}

func (s *Server) capabilityOK(r *http.Request) bool {
	got := r.Header.Get("X-Capability")
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.capability)) == 1
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	s.writeAsset(w, "assets/index.html", "text/html; charset=utf-8")
}

func (s *Server) handleAsset(path, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		s.writeAsset(w, path, contentType)
	}
}

func (s *Server) writeAsset(w http.ResponseWriter, path, contentType string) {
	data, err := web.Assets.ReadFile(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "asset not found")
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(data)
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Bootstrap string `json:"bootstrap"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bootstrapUsed {
		writeErr(w, http.StatusForbidden, "the launch token has already been used")
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.Bootstrap), []byte(s.bootstrapToken)) != 1 {
		writeErr(w, http.StatusForbidden, "invalid launch token")
		return
	}
	s.bootstrapUsed = true
	writeJSON(w, http.StatusOK, map[string]string{"capability": s.capability})
}

func (s *Server) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.session.Capabilities())
}

func (s *Server) handleCreateRun(w http.ResponseWriter, r *http.Request) {
	var req app.CreateRunRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	run, err := s.session.CreateRun(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) handleNext(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Profile string `json:"profile"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	run, err := s.session.RunProbe(r.Context(), r.PathValue("id"), body.Profile)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.session.Get(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := s.session.Summarize(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) handleAssessment(w http.ResponseWriter, r *http.Request) {
	a, err := s.session.Assess(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.session.Profiles(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles})
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind string `json:"kind"`
		Text string `json:"text"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Kind != "nginx" {
		writeErr(w, http.StatusBadRequest, "unsupported import kind (only \"nginx\" is supported)")
		return
	}
	review, err := s.session.ImportNginx(r.PathValue("id"), body.Text)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, review)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Format string `json:"format"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	content, err := s.session.Export(r.PathValue("id"), body.Format)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"content": content})
}

func (s *Server) handleShutdown(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "shutting_down"})
	s.shutdownOnce.Do(func() { close(s.shutdownCh) })
}

func decodeJSON(r *http.Request, v any) error {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func randToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

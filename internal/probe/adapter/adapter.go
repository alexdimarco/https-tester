// Package adapter runs approved, already-installed external TLS clients (curl,
// openssl) so the workbench can test the actual implementations on the machine,
// not only Go's. It is an opt-in extension: a tool is executed only when the
// operator chooses its profile.
//
// Safety rules enforced here (design section 5.6):
//   - execute a fixed absolute path (from exec.LookPath) with a validated
//     argument array via exec.CommandContext — never a shell, never free-form;
//   - the child's environment is sanitized: SSLKEYLOGFILE and proxy variables
//     are removed so no key material leaks and the direct baseline stays direct;
//   - output is bounded and redacted; the context cancels and cleans up the
//     child process.
//
// No downloads, installers, or package-manager commands are ever run.
package adapter

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/alexdimarco/https-tester/internal/evidence"
	"github.com/alexdimarco/https-tester/internal/redact"
)

const maxOutputBytes = 1 << 20 // 1 MiB per stream, then truncated

// Tool is a discovered external client.
type Tool struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Version   string `json:"version"`
	Backend   string `json:"backend"`
	Available bool   `json:"available"`
	Note      string `json:"note,omitempty"`
}

// Result is the ordered observations plus a summary, matching the native engine.
type Result struct {
	Observations []evidence.Observation
	StageReached evidence.Stage
	Outcome      evidence.Outcome
}

// Request is one external-client comparison against a target.
type Request struct {
	ProbeID string
	Host    string
	Port    string
	URL     string
	Profile string // human label, e.g. "curl (TLS 1.2)"
	Version string // "", "1.2", or "1.3"
	Timeout time.Duration
}

// Discover returns the curl and openssl tools found on PATH, with versions.
// Running "--version" is a capability probe only; it performs no network I/O.
func Discover(ctx context.Context) []Tool {
	return []Tool{discoverCurl(ctx), discoverOpenSSL(ctx)}
}

func discoverCurl(ctx context.Context) Tool {
	t := Tool{Name: "curl"}
	path, err := exec.LookPath("curl")
	if err != nil {
		t.Note = "not found on PATH"
		return t
	}
	t.Path = path
	out, _, _, rerr := run(ctx, path, []string{"--version"}, "", 5*time.Second)
	if rerr != nil {
		t.Note = "found but --version failed"
		return t
	}
	line := firstLine(out)
	t.Available = true
	t.Version = line
	t.Backend = curlBackend(line)
	return t
}

func discoverOpenSSL(ctx context.Context) Tool {
	t := Tool{Name: "openssl"}
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Note = "not found on PATH"
		return t
	}
	t.Path = path
	out, _, _, rerr := run(ctx, path, []string{"version"}, "", 5*time.Second)
	if rerr != nil {
		t.Note = "found but version failed"
		return t
	}
	t.Available = true
	t.Version = strings.TrimSpace(firstLine(out))
	t.Backend = "openssl"
	return t
}

// RunCurl performs a bounded, redirect-free HEAD request with the installed
// curl and records what that real client did.
func RunCurl(ctx context.Context, tool Tool, req Request) *Result {
	if !tool.Available {
		return unavailable(req, "curl", "curl is not available on this machine")
	}
	// -q MUST be first: it suppresses curlrc so hidden configuration cannot
	// change the test.
	args := []string{
		"-q",
		"--silent", "--show-error",
		"--globoff",      // no URL glob expansion
		"--noproxy", "*", // direct baseline: ignore env proxies
		"--no-sessionid", // fresh handshake, no session reuse
		"--head",         // HEAD, matching the Go default
		"--max-time", seconds(req.Timeout),
		"--output", os.DevNull,
		"--write-out", "HTTP_CODE=%{http_code}\n",
	}
	switch req.Version {
	case "1.2":
		args = append(args, "--tlsv1.2", "--tls-max", "1.2")
	case "1.3":
		args = append(args, "--tlsv1.3", "--tls-max", "1.3")
	}
	args = append(args, req.URL)

	stdout, stderr, code, err := run(ctx, tool.Path, args, "", req.Timeout+2*time.Second)
	detail := map[string]string{
		"client":            "curl",
		"client_version":    tool.Version,
		"tls_backend":       tool.Backend,
		"exit_code":         itoa(code),
		"requested_profile": req.Profile,
	}
	if hc := parseWriteOut(stdout, "HTTP_CODE="); hc != "" {
		detail["http_code"] = hc
	}
	if err != nil && code == 0 {
		return single(req, "curl", evidence.StageHTTP, evidence.OutcomeInternalError,
			"could not run curl: "+redact.Error(err), detail)
	}
	stage, outcome, norm := curlClassify(code)
	o := evidence.Observation{
		ProbeID: req.ProbeID, SourceKind: "curl", TimestampUTC: time.Now().UTC(),
		Stage: stage, Outcome: outcome, NormalizedError: norm, Detail: detail,
		CaptureCompleteness: "external_client_exit_status_and_http_code",
		RemainingUnknowns:   []string{"negotiated TLS parameters are not parsed from curl here; use the openssl profile for those"},
	}
	if outcome != evidence.OutcomePass {
		o.RawErrorRedacted = redactLines(stderr)
	}
	return &Result{Observations: []evidence.Observation{o}, StageReached: stage, Outcome: outcome}
}

// RunOpenSSL performs an s_client handshake with hostname verification and
// parses the negotiated protocol and cipher. "Verification: OK" alone is not
// treated as success: the handshake must complete and the verify code be 0.
func RunOpenSSL(ctx context.Context, tool Tool, req Request) *Result {
	if !tool.Available {
		return unavailable(req, "openssl", "openssl is not available on this machine")
	}
	hostport := req.Host + ":" + req.Port
	args := []string{
		"s_client",
		"-connect", hostport,
		"-servername", req.Host,
		"-verify_hostname", req.Host,
		"-verify_return_error",
		"-verify", "5",
		"-no_ign_eof",
	}
	switch req.Version {
	case "1.2":
		args = append(args, "-tls1_2")
	case "1.3":
		args = append(args, "-tls1_3")
	}
	// "Q\n" on stdin tells s_client to close cleanly once connected.
	stdout, stderr, code, err := run(ctx, tool.Path, args, "Q\n", req.Timeout+2*time.Second)
	proto := parseField(stdout, "Protocol")
	cipher := parseField(stdout, "Cipher")
	verifyOK := strings.Contains(stdout, "Verify return code: 0 (ok)")

	detail := map[string]string{
		"client":            "openssl",
		"client_version":    tool.Version,
		"exit_code":         itoa(code),
		"requested_profile": req.Profile,
		"verify_return_ok":  boolStr(verifyOK),
	}
	if err != nil && code == 0 && proto == "" {
		return single(req, "openssl", evidence.StageTLS, evidence.OutcomeInternalError,
			"could not run openssl: "+redact.Error(err), detail)
	}

	// Success requires a completed handshake (protocol parsed), a clean exit,
	// and verification success — not a verify string on its own.
	handshakeComplete := proto != "" && cipher != ""
	pass := handshakeComplete && code == 0 && verifyOK
	stage := evidence.StageTLS
	outcome := evidence.OutcomeFail
	if pass {
		outcome = evidence.OutcomePass
	}
	hc := handshakeComplete
	o := evidence.Observation{
		ProbeID: req.ProbeID, SourceKind: "openssl", TimestampUTC: time.Now().UTC(),
		Stage: stage, Outcome: outcome, HandshakeComplete: &hc,
		NegotiatedVersion: proto, CipherSuite: cipher, Detail: detail,
		CaptureCompleteness: "parsed from openssl s_client session block",
	}
	if proto != "" {
		o.VerificationStatus = "openssl_verify_return_" + boolStr(verifyOK)
	}
	if !pass {
		o.RawErrorRedacted = redactLines(stderr)
	}
	return &Result{Observations: []evidence.Observation{o}, StageReached: stage, Outcome: outcome}
}

// --- execution + parsing helpers ---

// run executes a fixed path with a validated argument array and a sanitized
// environment. It never invokes a shell.
func run(ctx context.Context, path string, args []string, stdin string, timeout time.Duration) (stdout, stderr string, code int, err error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = sanitizedEnv()
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errBuf boundedBuffer
	out.max = maxOutputBytes
	errBuf.max = maxOutputBytes
	cmd.Stdout = &out
	cmd.Stderr = &errBuf

	runErr := cmd.Run()
	code = cmd.ProcessState.ExitCode()
	if runErr != nil {
		if _, ok := runErr.(*exec.ExitError); !ok {
			// A non-exit error (failed to start, context cancel) is returned.
			return out.String(), errBuf.String(), code, runErr
		}
	}
	return out.String(), errBuf.String(), code, nil
}

// sanitizedEnv strips key-logging and proxy variables from the child env.
func sanitizedEnv() []string {
	drop := map[string]bool{
		"SSLKEYLOGFILE": true,
		"HTTP_PROXY":    true, "HTTPS_PROXY": true, "ALL_PROXY": true,
		"http_proxy": true, "https_proxy": true, "all_proxy": true,
	}
	var out []string
	for _, kv := range os.Environ() {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if drop[name] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func curlBackend(versionLine string) string {
	l := strings.ToLower(versionLine)
	switch {
	case strings.Contains(l, "securetransport"):
		return "SecureTransport"
	case strings.Contains(l, "libressl"):
		return "LibreSSL"
	case strings.Contains(l, "boringssl"):
		return "BoringSSL"
	case strings.Contains(l, "openssl"):
		return "OpenSSL"
	case strings.Contains(l, "gnutls"):
		return "GnuTLS"
	default:
		return "unknown"
	}
}

func curlClassify(code int) (evidence.Stage, evidence.Outcome, string) {
	switch code {
	case 0:
		return evidence.StageHTTP, evidence.OutcomePass, ""
	case 6:
		return evidence.StageDNS, evidence.OutcomeFail, "dns_resolution_failed"
	case 7:
		return evidence.StageTCP, evidence.OutcomeFail, "connection_refused"
	case 28:
		return evidence.StageTLS, evidence.OutcomeFail, "timeout"
	case 35:
		return evidence.StageTLS, evidence.OutcomeFail, "tls_handshake_failure"
	case 51, 60:
		return evidence.StageCertificate, evidence.OutcomeFail, "certificate_not_trusted"
	default:
		return evidence.StageTLS, evidence.OutcomeFail, "see_raw_error"
	}
}

func unavailable(req Request, client, note string) *Result {
	return single(req, client, evidence.StageInput, evidence.OutcomeUnsupportedByClient, note, map[string]string{"client": client})
}

func single(req Request, client string, stage evidence.Stage, outcome evidence.Outcome, note string, detail map[string]string) *Result {
	if detail == nil {
		detail = map[string]string{}
	}
	detail["note"] = note
	o := evidence.Observation{
		ProbeID: req.ProbeID, SourceKind: client, TimestampUTC: time.Now().UTC(),
		Stage: stage, Outcome: outcome, Detail: detail,
	}
	return &Result{Observations: []evidence.Observation{o}, StageReached: stage, Outcome: outcome}
}

func parseWriteOut(stdout, key string) string {
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, key) {
			return strings.TrimSpace(strings.TrimPrefix(line, key))
		}
	}
	return ""
}

// parseField reads "Name  : value" lines from openssl s_client output.
func parseField(stdout, name string) string {
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, name) {
			rest := strings.TrimSpace(strings.TrimPrefix(line, name))
			if strings.HasPrefix(rest, ":") {
				v := strings.TrimSpace(strings.TrimPrefix(rest, ":"))
				if v != "" && v != "(NONE)" && v != "0000" {
					return v
				}
			}
		}
	}
	return ""
}

func redactLines(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		out = append(out, redact.URL(line))
		if len(out) >= 20 {
			out = append(out, "… (truncated)")
			break
		}
	}
	return strings.Join(out, "\n")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func seconds(d time.Duration) string {
	if d <= 0 {
		d = 10 * time.Second
	}
	return itoa(int(d.Seconds()))
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// boundedBuffer caps how much output is retained.
type boundedBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len() >= b.max {
		b.overflow = true
		return len(p), nil
	}
	room := b.max - b.buf.Len()
	if room < len(p) {
		b.buf.Write(p[:room])
		b.overflow = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *boundedBuffer) String() string {
	if b.overflow {
		return b.buf.String() + "\n… (truncated)"
	}
	return b.buf.String()
}

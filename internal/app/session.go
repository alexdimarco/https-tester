// Package app wires the pieces together and owns the lifecycle of a single
// local session: it validates targets, resolves and scope-checks addresses,
// records the operator's authorization, runs one probe at a time, and derives
// scoped claims from the observations.
package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/alexdimarco/https-tester/internal/assess"
	"github.com/alexdimarco/https-tester/internal/evidence"
	"github.com/alexdimarco/https-tester/internal/nginxreview"
	"github.com/alexdimarco/https-tester/internal/probe/adapter"
	"github.com/alexdimarco/https-tester/internal/probe/native"
	"github.com/alexdimarco/https-tester/internal/report"
	"github.com/alexdimarco/https-tester/internal/target"
)

// Session holds the in-memory runs for one launch of the workbench.
type Session struct {
	build    string
	trust    string
	timeouts native.Timeouts

	mu        sync.Mutex
	probeMu   sync.Mutex // serializes outbound probes: one at a time per session
	runs      map[string]*evidence.LiveRun
	selfAuth  string // the workbench's own listener authority, never a valid target
	toolsOnce sync.Once
	tools     []adapter.Tool
}

// NewSession creates an empty session with system trust (the Gate A default).
func NewSession(build string) *Session {
	return &Session{
		build:    build,
		trust:    "system",
		timeouts: native.DefaultTimeouts(),
		runs:     map[string]*evidence.LiveRun{},
	}
}

// SetSelfAuthority records the workbench's own listener host:port so a target
// can never be the diagnostic process itself.
func (s *Session) SetSelfAuthority(authority string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.selfAuth = authority
}

// Capabilities describes the build and which client profiles are available.
type Capabilities struct {
	AppBuild  string         `json:"app_build"`
	Clients   []string       `json:"clients"`
	Adapters  []adapter.Tool `json:"adapters"`
	TrustMode string         `json:"trust_mode"`
}

// Capabilities reports current build and client availability.
func (s *Session) Capabilities() Capabilities {
	tools := s.discoverTools()
	clients := []string{native.SourceKind}
	for _, t := range tools {
		if t.Available {
			clients = append(clients, t.Name)
		}
	}
	return Capabilities{
		AppBuild:  s.build,
		Clients:   clients,
		Adapters:  tools,
		TrustMode: s.trust,
	}
}

// discoverTools finds external clients once and caches the result.
func (s *Session) discoverTools() []adapter.Tool {
	s.toolsOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		s.tools = adapter.Discover(ctx)
	})
	return s.tools
}

func (s *Session) tool(name string) adapter.Tool {
	for _, t := range s.discoverTools() {
		if t.Name == name {
			return t
		}
	}
	return adapter.Tool{Name: name}
}

// CreateRunRequest is the operator's authorization to investigate one target.
type CreateRunRequest struct {
	URL                  string `json:"url"`
	Note                 string `json:"note"`
	LocalPrivateApproved bool   `json:"local_private_approved"`
}

// CreateRun validates the target, resolves and scope-checks addresses, records
// authorization, and returns a snapshot of the new run.
func (s *Session) CreateRun(ctx context.Context, req CreateRunRequest) (evidence.Run, error) {
	t, err := target.ParseAndValidate(req.URL)
	if err != nil {
		return evidence.Run{}, err
	}

	selected, family, notes, err := s.resolveAndScope(ctx, t, req.LocalPrivateApproved)
	if err != nil {
		return evidence.Run{}, err
	}

	now := time.Now().UTC()
	runID := evidence.NewID("run")
	run := evidence.NewLiveRun(evidence.Run{
		SchemaVersion:      evidence.SchemaVersion,
		RunID:              runID,
		AppBuild:           s.build,
		RuleCatalogVersion: "gate-a-builtin",
		StartedAtUTC:       now,
		ClockSource:        "local system clock (not independently verified)",
		Platform:           runtime.GOOS,
		Architecture:       runtime.GOARCH,
		TrustMode:          s.trust,
		Authorization: evidence.Authorization{
			OperatorAcknowledged: true,
			LocalPrivateApproved: req.LocalPrivateApproved,
			Note:                 req.Note,
			AuthorizedAtUTC:      now,
		},
		TargetScope: evidence.TargetScope{
			InputURL:          t.InputURL,
			Authority:         t.Authority,
			Host:              t.Host,
			Port:              t.Port,
			Path:              t.Path,
			SelectedAddresses: addrStrings(selected),
			AddressFamily:     family,
		},
	})
	run.AddConsentEvent(evidence.ConsentEvent{
		AtUTC:  now,
		Kind:   "target_authorized",
		Detail: fmt.Sprintf("authority=%s addresses=%s", t.Authority, strings.Join(addrStrings(selected), ",")),
	})
	for _, n := range notes {
		run.AddConsentEvent(evidence.ConsentEvent{AtUTC: now, Kind: "scope_note", Detail: n})
	}
	// Record the input/DNS stage as the first observation.
	run.AddObservation(evidence.Observation{
		ProbeID:      "DNS-01",
		SourceKind:   native.SourceKind,
		TimestampUTC: now,
		Stage:        evidence.StageDNS,
		Outcome:      evidence.OutcomePass,
		Detail: map[string]string{
			"resolved_addresses": strings.Join(addrStrings(selected), ", "),
			"address_family":     family,
		},
		RemainingUnknowns: []string{"this is not an authoritative DNS zone audit; TTLs were not recorded"},
	})

	s.mu.Lock()
	s.runs[runID] = run
	s.mu.Unlock()

	return run.Snapshot(), nil
}

// RunProbe runs one probe profile against the first selected address and
// appends its observations and a derived claim. The empty profile is the
// default verified request; named profiles test an exact TLS version or a
// single key-exchange group.
func (s *Session) RunProbe(ctx context.Context, runID, profile string) (evidence.Run, error) {
	run, err := s.lookup(runID)
	if err != nil {
		return evidence.Run{}, err
	}
	if strings.HasPrefix(profile, "client:") {
		return s.runClientProbe(ctx, run, profile)
	}
	spec, err := profileSpec(profile)
	if err != nil {
		return evidence.Run{}, err
	}

	s.probeMu.Lock() // one outbound probe at a time per session
	defer s.probeMu.Unlock()

	scope := run.Scope()
	if len(scope.SelectedAddresses) == 0 {
		return evidence.Run{}, fmt.Errorf("no approved address is available to probe")
	}
	dialAddr, perr := netip.ParseAddr(scope.SelectedAddresses[0])
	if perr != nil {
		return evidence.Run{}, fmt.Errorf("the approved address %q is not valid", scope.SelectedAddresses[0])
	}

	reqURL := "https://" + scope.Authority + scope.Path
	result := native.VerifiedRequest(ctx, native.Request{
		ProbeID:    spec.probeID,
		URL:        reqURL,
		Host:       scope.Host,
		Port:       scope.Port,
		DialAddr:   dialAddr,
		TrustName:  s.trust + "_trust",
		UserAgent:  "https-diagnostic-workbench/" + s.build,
		Timeouts:   s.timeouts,
		MinVersion: spec.min,
		MaxVersion: spec.max,
		Curves:     spec.curves,
		Profile:    spec.label,
	})
	// Assign observation IDs before storing so the derived claim can reference
	// them (the status badge in the report is computed from this linkage).
	for i := range result.Observations {
		if result.Observations[i].ID == "" {
			result.Observations[i].ID = evidence.NewID("obs")
		}
	}
	for _, o := range result.Observations {
		run.AddObservation(o)
	}
	run.AddClaim(deriveClaim(result, scope, spec))

	return run.Snapshot(), nil
}

// probe describes one named test profile and the exact TLS knobs it sets.
type probe struct {
	profile string // caller-supplied key
	probeID string // evidence probe id
	kind    string // "default", "version", or "group"
	label   string // human-readable profile description
	group   string // group name for the "group" kind
	min     uint16
	max     uint16
	curves  []tls.CurveID
}

// profileSpec maps a profile key to its TLS controls. Only groups Go actually
// supports are offered; it never invents an unsupported constant.
func profileSpec(profile string) (probe, error) {
	switch profile {
	case "", "default":
		return probe{profile: "default", probeID: "HTTPS-01", kind: "default",
			label: "default (minimum TLS 1.2, library default groups)"}, nil
	case "tls12":
		return probe{profile: profile, probeID: "TLS-12", kind: "version",
			label: "TLS 1.2", min: tls.VersionTLS12, max: tls.VersionTLS12}, nil
	case "tls13":
		return probe{profile: profile, probeID: "TLS-13", kind: "version",
			label: "TLS 1.3", min: tls.VersionTLS13, max: tls.VersionTLS13}, nil
	case "group:x25519":
		return groupProbe(profile, "GROUP-X25519", "X25519", tls.X25519), nil
	case "group:p256":
		return groupProbe(profile, "GROUP-P256", "P-256", tls.CurveP256), nil
	case "group:p384":
		return groupProbe(profile, "GROUP-P384", "P-384", tls.CurveP384), nil
	case "group:p521":
		return groupProbe(profile, "GROUP-P521", "P-521", tls.CurveP521), nil
	default:
		return probe{}, fmt.Errorf("unknown probe profile %q", profile)
	}
}

func groupProbe(profile, probeID, groupName string, curve tls.CurveID) probe {
	return probe{
		profile: profile, probeID: probeID, kind: "group", group: groupName,
		label: "TLS 1.3, " + groupName + " only",
		min:   tls.VersionTLS13, max: tls.VersionTLS13,
		curves: []tls.CurveID{curve},
	}
}

// clientProbe names an external-client profile and its TLS-version request.
type clientProbe struct {
	tool    string
	version string
	probeID string
	label   string
}

func clientSpec(profile string) (clientProbe, error) {
	switch profile {
	case "client:curl":
		return clientProbe{"curl", "", "CLIENT-CURL", "installed curl (default)"}, nil
	case "client:curl12":
		return clientProbe{"curl", "1.2", "CLIENT-CURL-12", "installed curl (TLS 1.2)"}, nil
	case "client:curl13":
		return clientProbe{"curl", "1.3", "CLIENT-CURL-13", "installed curl (TLS 1.3)"}, nil
	case "client:openssl":
		return clientProbe{"openssl", "", "CLIENT-OPENSSL", "installed openssl (default)"}, nil
	case "client:openssl12":
		return clientProbe{"openssl", "1.2", "CLIENT-OPENSSL-12", "installed openssl (TLS 1.2)"}, nil
	case "client:openssl13":
		return clientProbe{"openssl", "1.3", "CLIENT-OPENSSL-13", "installed openssl (TLS 1.3)"}, nil
	default:
		return clientProbe{}, fmt.Errorf("unknown client profile %q", profile)
	}
}

// runClientProbe runs an approved external client (curl/openssl) against the
// target and records what that real implementation did.
func (s *Session) runClientProbe(ctx context.Context, run *evidence.LiveRun, profile string) (evidence.Run, error) {
	cs, err := clientSpec(profile)
	if err != nil {
		return evidence.Run{}, err
	}
	s.probeMu.Lock()
	defer s.probeMu.Unlock()

	scope := run.Scope()
	tool := s.tool(cs.tool)
	req := adapter.Request{
		ProbeID: cs.probeID,
		Host:    scope.Host,
		Port:    scope.Port,
		URL:     "https://" + scope.Authority + scope.Path,
		Profile: cs.label,
		Version: cs.version,
		Timeout: 15 * time.Second,
	}
	var result *adapter.Result
	if cs.tool == "curl" {
		result = adapter.RunCurl(ctx, tool, req)
	} else {
		result = adapter.RunOpenSSL(ctx, tool, req)
	}
	for i := range result.Observations {
		if result.Observations[i].ID == "" {
			result.Observations[i].ID = evidence.NewID("obs")
		}
	}
	for _, o := range result.Observations {
		run.AddObservation(o)
	}
	run.AddClaim(deriveClientClaim(result, scope, cs, tool))
	return run.Snapshot(), nil
}

func deriveClientClaim(r *adapter.Result, scope evidence.TargetScope, cs clientProbe, tool adapter.Tool) evidence.Claim {
	base := evidence.Claim{
		RuleID:   "gate-c-client",
		Register: "finding about observed results",
		Checked:  fmt.Sprintf("Whether the installed %s on this machine completes a request to the endpoint%s.", cs.tool, versionSuffix(cs.version)),
		Status:   evidence.StatusObserved,
		Scope:    fmt.Sprintf("the installed %s (%s; backend %s), against %s", cs.tool, orUnknown(tool.Version), orUnknown(tool.Backend), scope.Authority),
	}
	for _, o := range r.Observations {
		base.SupportingObservations = append(base.SupportingObservations, o.ID)
	}
	switch {
	case r.Outcome == evidence.OutcomeUnsupportedByClient:
		base.Statement = fmt.Sprintf("The installed %s was not available on this machine, so this comparison could not run.", cs.tool)
		base.NextDiscriminatingCheck = fmt.Sprintf("install %s, or use the Go native and other available clients.", cs.tool)
	case r.Outcome == evidence.OutcomePass:
		base.Statement = fmt.Sprintf("The installed %s completed a request to this endpoint for this attempt. This is the actual client on this machine, not automatically equivalent to Go or a browser.", cs.tool)
		base.NextDiscriminatingCheck = "compare with the Go native result: if Go differs, the difference is client- or profile-specific, not necessarily a server defect."
		base.UncheckedItems = []string{"the external client's trust store and build may differ from Go's"}
	default:
		base.Statement = fmt.Sprintf("The installed %s did NOT complete a request to this endpoint for this attempt.", cs.tool)
		base.Alternatives = []string{
			"a client/profile or trust-store difference specific to this client",
			"a network path or load-balancer difference for this address",
			"a server-side setting this client's defaults do not accept",
		}
		base.UncheckedItems = []string{"the server's effective configuration was not examined"}
		base.NextDiscriminatingCheck = "compare with the Go native result and the other installed client; a Go success does not disprove this client's failure."
	}
	return base
}

func versionSuffix(v string) string {
	if v == "" {
		return ""
	}
	return " using TLS " + v
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}

// ImportNginx statically reviews an operator-supplied Nginx configuration
// excerpt, records it as operator-supplied evidence, and returns the review.
func (s *Session) ImportNginx(runID, text string) (nginxreview.Review, error) {
	run, err := s.lookup(runID)
	if err != nil {
		return nginxreview.Review{}, err
	}
	review := nginxreview.Analyze(text)
	now := time.Now().UTC()
	run.AddConsentEvent(evidence.ConsentEvent{
		AtUTC:  now,
		Kind:   "nginx_config_imported",
		Detail: fmt.Sprintf("%d findings, %d parse errors", len(review.Findings), len(review.ParseErrors)),
	})
	run.AddClaim(evidence.Claim{
		RuleID:                  "gate-c-nginx-import",
		Register:                "operator-supplied static review",
		Checked:                 "An Nginx configuration excerpt you pasted, read statically.",
		Status:                  evidence.StatusObserved,
		Scope:                   "the pasted text only, not the running server",
		Statement:               fmt.Sprintf("Reviewed an operator-supplied Nginx configuration excerpt: %d finding(s). This is pasted text, not the running configuration.", len(review.Findings)),
		UncheckedItems:          []string{"the effective running configuration was not verified; include files were not opened"},
		NextDiscriminatingCheck: "confirm with 'nginx -t' and 'nginx -T' on the actual instance, and compare the reported topology with the observed TLS endpoint.",
	})
	return review, nil
}

// Assess returns the protocol-posture assessment derived from a run's
// observations.
func (s *Session) Assess(runID string) (assess.Assessment, error) {
	run, err := s.lookup(runID)
	if err != nil {
		return assess.Assessment{}, err
	}
	return assess.Build(run.Snapshot()), nil
}

// Summarize returns the short executive summary for a run (bottom line,
// connection state, standing, and observed issues).
func (s *Session) Summarize(runID string) (assess.Summary, error) {
	run, err := s.lookup(runID)
	if err != nil {
		return assess.Summary{}, err
	}
	return assess.Summarize(run.Snapshot()), nil
}

// Profiles compares the run's observed posture against the legacy /
// Intermediate / Modern targets.
func (s *Session) Profiles(runID string) ([]assess.ProfileTarget, error) {
	run, err := s.lookup(runID)
	if err != nil {
		return nil, err
	}
	return assess.CompareProfiles(run.Snapshot()), nil
}

// Get returns a redacted snapshot of a run.
func (s *Session) Get(runID string) (evidence.Run, error) {
	run, err := s.lookup(runID)
	if err != nil {
		return evidence.Run{}, err
	}
	return run.Snapshot(), nil
}

// Export renders a run as text or JSON.
func (s *Session) Export(runID, format string) (string, error) {
	run, err := s.lookup(runID)
	if err != nil {
		return "", err
	}
	snap := run.Snapshot()
	switch format {
	case "json":
		b, jerr := report.JSONDocument(snap)
		if jerr != nil {
			return "", jerr
		}
		return string(b), nil
	case "", "text":
		return report.Text(snap), nil
	default:
		return "", fmt.Errorf("unknown report format %q (use text or json)", format)
	}
}

func (s *Session) lookup(runID string) (*evidence.LiveRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[runID]
	if !ok {
		return nil, fmt.Errorf("no run with id %q", runID)
	}
	return run, nil
}

// resolveAndScope resolves the host (or uses the IP literal), hard-blocks unsafe
// classes, enforces private/loopback approval, blocks the workbench's own
// listener, and returns the selected addresses with any scope notes.
func (s *Session) resolveAndScope(ctx context.Context, t *target.Target, privateApproved bool) ([]netip.Addr, string, []string, error) {
	var candidates []netip.Addr
	if t.IsIP {
		a, _ := netip.ParseAddr(t.Host)
		candidates = []netip.Addr{a}
	} else {
		addrs, err := native.Resolve(ctx, t.Host, s.timeouts.DNS)
		if err != nil {
			return nil, "", nil, fmt.Errorf("could not resolve %q: %w", t.Host, err)
		}
		candidates = addrs
	}

	s.mu.Lock()
	self := s.selfAuth
	s.mu.Unlock()

	var selected []netip.Addr
	var notes []string
	for _, a := range candidates {
		a = a.Unmap()
		if self != "" && equalAuthority(a, t.Port, self) {
			notes = append(notes, "dropped the workbench's own listener address from scope")
			continue
		}
		class, reason := target.Classify(a)
		switch class {
		case target.ClassBlocked:
			notes = append(notes, fmt.Sprintf("blocked %s: %s", a, reason))
		case target.ClassPrivateOrLoopback:
			if !privateApproved {
				notes = append(notes, fmt.Sprintf("skipped private/loopback address %s (needs explicit approval)", a))
				continue
			}
			selected = append(selected, a)
		default:
			selected = append(selected, a)
		}
	}

	if len(selected) == 0 {
		if containsPrivate(candidates) && !privateApproved {
			return nil, "", notes, fmt.Errorf("this target resolves only to private or loopback addresses; re-run with explicit approval to test a private target")
		}
		return nil, "", notes, fmt.Errorf("no permitted address remained after scope checks")
	}

	// Gate A dials the first selected address; the budget is 4 addresses total.
	if len(selected) > 4 {
		notes = append(notes, fmt.Sprintf("%d addresses resolved; scope limited to the first 4", len(selected)))
		selected = selected[:4]
	}
	return selected, familyOf(selected), notes, nil
}

func deriveClaim(r *native.Result, scope evidence.TargetScope, spec probe) evidence.Claim {
	base := evidence.Claim{
		RuleID:   "gate-b-" + spec.kind,
		Register: "finding about observed results",
		Checked:  checkedText(spec),
		Status:   evidence.StatusObserved,
		Scope:    fmt.Sprintf("the Go native client (%s), against %s at %s", spec.label, scope.Authority, strings.Join(scope.SelectedAddresses, ", ")),
	}
	for _, o := range r.Observations {
		base.SupportingObservations = append(base.SupportingObservations, o.ID)
	}
	pass := r.StageReached == evidence.StageHTTP && r.Outcome == evidence.OutcomePass
	deepest := deepestNonPass(r.Observations)
	stage := strings.ToUpper(string(r.StageReached))

	switch spec.kind {
	case "version":
		if pass {
			base.Statement = fmt.Sprintf("With %s, a verified HTTPS response was obtained for this attempt.", spec.label)
			base.NextDiscriminatingCheck = "compare the other TLS version on the same endpoint to characterize version-dependent behavior."
		} else {
			base.Statement = fmt.Sprintf("With %s, the connection did not complete a verified request; it reached the %s stage (%s) for this attempt.%s", spec.label, stage, r.Outcome, certSuffix(deepest))
			base.Alternatives = []string{"version-dependent behavior in these tests", "a client/profile or trust difference", "a path or virtual-host difference not yet examined"}
			base.NextDiscriminatingCheck = "run the other TLS version, then controlled single key-exchange groups, on the same endpoint."
		}
		base.UncheckedItems = []string{"this does not establish behavior for the other TLS version", "the server's effective configuration was not examined"}
		return base

	case "group":
		if pass {
			base.Statement = fmt.Sprintf("Under TLS 1.3 offering only the %s key-exchange group, the handshake succeeded for this attempt.", spec.group)
			base.NextDiscriminatingCheck = "offer the other single groups and compare which succeed and which fail."
		} else {
			base.Statement = fmt.Sprintf("Under TLS 1.3 offering only the %s key-exchange group, the handshake failed for this attempt. This does not prove the server disables %s.", spec.group, spec.group)
			base.Alternatives = []string{
				fmt.Sprintf("the server may not have %s active, OR", spec.group),
				"a runtime policy, default virtual host, or path difference may explain it",
				"this client build may not have offered it as expected",
			}
			base.NextDiscriminatingCheck = fmt.Sprintf("offer other single groups and compare; then obtain the server's active group configuration and a handshake trace for %s.", spec.group)
		}
		base.UncheckedItems = []string{"a single-group result does not enumerate every group the server accepts", "the server's effective configuration was not examined"}
		return base
	}

	// default profile
	if pass {
		base.Statement = "A verified HTTPS response was obtained from this endpoint with the Go native client."
		base.UncheckedItems = []string{
			"this represents the Go client's profile, not a browser or an installed curl/OpenSSL",
			"revocation, certificate transparency, and HSTS/ECH/HTTP3 were not tested",
		}
		base.NextDiscriminatingCheck = "compare an approved installed client (curl/OpenSSL) or a browser against the same endpoint to confirm client-independence."
		return base
	}
	switch deepest.NormalizedError {
	case "certificate_invalid":
		base.Statement = "The server's certificate failed validation for this attempt: it is expired or not yet valid, as presented to this client."
		base.NextDiscriminatingCheck = "check the certificate's not-before/not-after dates against an independently trusted clock, and compare with a browser."
	case "certificate_hostname_mismatch":
		base.Statement = "The server's certificate does not cover the requested hostname for this attempt, as presented to this client."
		base.NextDiscriminatingCheck = "compare the requested host against the certificate's subject alternative names, and confirm the intended virtual host."
	case "certificate_unknown_authority":
		base.Statement = "The server's certificate chains to an authority this client does not trust for this attempt."
		base.NextDiscriminatingCheck = "compare against the intended trust bundle and check for a missing intermediate certificate; compare with a browser."
	case "timeout":
		base.Statement = fmt.Sprintf("The connection timed out at the %s stage for this attempt.", stage)
		base.NextDiscriminatingCheck = "retry the same profile, then compare another approved network path or address and check firewall/listener state."
	default:
		base.Statement = fmt.Sprintf("The connection did not produce a verified HTTPS response; it reached the %s stage with outcome %q for this attempt.", stage, r.Outcome)
		base.NextDiscriminatingCheck = "repeat with an exact TLS-version profile and, if needed, single key-exchange groups on the same endpoint; then gather server-side evidence."
	}
	base.Alternatives = []string{
		"a client/profile or trust-store difference rather than a server defect",
		"a network path, firewall, or load-balancer difference for this address",
		"a server-side protocol, certificate, or virtual-host setting not yet examined",
	}
	base.UncheckedItems = []string{"the server's effective configuration and logs were not examined"}
	return base
}

func certSuffix(o evidence.Observation) string {
	switch o.NormalizedError {
	case "certificate_invalid":
		return " The certificate is expired or not yet valid as presented to this client."
	case "certificate_hostname_mismatch":
		return " The certificate does not cover the requested hostname."
	case "certificate_unknown_authority":
		return " The certificate chains to an authority this client does not trust."
	default:
		return ""
	}
}

func checkedText(spec probe) string {
	switch spec.kind {
	case "version":
		return fmt.Sprintf("Whether the server completes a connection using %s.", spec.label)
	case "group":
		return fmt.Sprintf("Whether the server completes a TLS 1.3 connection when only the %s key-exchange group is offered.", spec.group)
	default:
		return "Whether this machine can complete a verified HTTPS request to the endpoint, with the certificate trusted."
	}
}

func deepestNonPass(obs []evidence.Observation) evidence.Observation {
	var deepest evidence.Observation
	for _, o := range obs {
		if o.Outcome != evidence.OutcomePass {
			deepest = o
		}
	}
	return deepest
}

func equalAuthority(a netip.Addr, port, selfAuthority string) bool {
	host, p, ok := splitHostPort(selfAuthority)
	if !ok || p != port {
		return false
	}
	sa, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return sa.Unmap() == a.Unmap()
}

func splitHostPort(s string) (string, string, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", false
	}
	host := strings.TrimPrefix(strings.TrimSuffix(s[:i], "]"), "[")
	return host, s[i+1:], true
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

func containsPrivate(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if c, _ := target.Classify(a.Unmap()); c == target.ClassPrivateOrLoopback {
			return true
		}
	}
	return false
}

func familyOf(addrs []netip.Addr) string {
	var v4, v6 bool
	for _, a := range addrs {
		if a.Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	switch {
	case v4 && v6:
		return "ipv4+ipv6"
	case v6:
		return "ipv6"
	default:
		return "ipv4"
	}
}

// Package evidence defines the versioned, append-only data model the workbench
// records for a single investigation: the run, the observations gathered by
// probes, and the scoped claims derived from them.
//
// The vocabulary here is deliberately explicit about uncertainty. Pointer and
// omitempty fields mean "not observed" rather than letting a zero value stand
// in for a measurement, because a false/zero in a failed handshake is not proof
// that an event never happened.
package evidence

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// SchemaVersion identifies the shape of the recorded data. Bump it on any
// change to the structures below.
const SchemaVersion = "0.1"

// Stage is the point in the connection a probe reached or is reporting on.
type Stage string

const (
	StageInput       Stage = "input"
	StageDNS         Stage = "dns"
	StageTCP         Stage = "tcp"
	StageTLS         Stage = "tls"
	StageCertificate Stage = "certificate"
	StageHTTP        Stage = "http"
)

// Outcome is the result vocabulary. It distinguishes a client limitation from a
// remote rejection, and an untested condition from a failed one — a distinction
// the design treats as load-bearing.
type Outcome string

const (
	OutcomePass                Outcome = "pass"
	OutcomeFail                Outcome = "fail"
	OutcomeWarning             Outcome = "warning"
	OutcomeNotTested           Outcome = "not_tested"
	OutcomeNotApplicable       Outcome = "not_applicable"
	OutcomeUnsupportedByClient Outcome = "unsupported_by_client"
	OutcomeInconclusive        Outcome = "inconclusive"
	OutcomeCancelled           Outcome = "cancelled"
	OutcomeInternalError       Outcome = "internal_tool_error"
)

// Claim status vocabulary. Confidence is about the stated scoped claim, not a
// universal server-health score.
const (
	StatusObserved   = "observed"
	StatusSupported  = "supported_explanation"
	StatusHypothesis = "hypothesis"
	StatusUnresolved = "unresolved"
)

// Run is the top-level record for one investigation. Observations and claims
// are appended; nothing already written is mutated in place.
type Run struct {
	SchemaVersion      string         `json:"schema_version"`
	RunID              string         `json:"run_id"`
	AppBuild           string         `json:"app_build"`
	RuleCatalogVersion string         `json:"rule_catalog_version"`
	StartedAtUTC       time.Time      `json:"started_at_utc"`
	ClockSource        string         `json:"clock_source"`
	Platform           string         `json:"platform"`
	Architecture       string         `json:"architecture"`
	Authorization      Authorization  `json:"authorization"`
	TargetScope        TargetScope    `json:"target_scope"`
	TrustMode          string         `json:"trust_mode"`
	Observations       []Observation  `json:"observations"`
	Claims             []Claim        `json:"claims"`
	ConsentEvents      []ConsentEvent `json:"consent_events"`
}

// Authorization records the operator's bounded go-ahead for this target.
type Authorization struct {
	OperatorAcknowledged bool      `json:"operator_acknowledged"`
	LocalPrivateApproved bool      `json:"local_private_approved"`
	Note                 string    `json:"note,omitempty"`
	AuthorizedAtUTC      time.Time `json:"authorized_at_utc"`
}

// TargetScope is the single authority and the explicit addresses a run is
// permitted to touch.
type TargetScope struct {
	InputURL          string   `json:"input_url"`
	Authority         string   `json:"authority"`
	Host              string   `json:"host"`
	Port              string   `json:"port"`
	Path              string   `json:"path"`
	SelectedAddresses []string `json:"selected_addresses"`
	AddressFamily     string   `json:"address_family"`
}

// ConsentEvent is a timestamped record of an authorization or scope decision.
type ConsentEvent struct {
	AtUTC  time.Time `json:"at_utc"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail,omitempty"`
}

// Observation is one measured fact from one probe stage.
type Observation struct {
	ID           string    `json:"id"`
	ProbeID      string    `json:"probe_id"`
	SourceKind   string    `json:"source_kind"`
	TimestampUTC time.Time `json:"timestamp_utc"`
	DurationMS   int64     `json:"duration_ms"`
	Stage        Stage     `json:"stage"`
	Outcome      Outcome   `json:"outcome"`

	RawErrorRedacted string `json:"raw_error_redacted,omitempty"`
	NormalizedError  string `json:"normalized_error,omitempty"`

	HandshakeComplete      *bool  `json:"handshake_complete,omitempty"`
	PeerCertificatePresent *bool  `json:"peer_certificate_present,omitempty"`
	VerificationStatus     string `json:"verification_status,omitempty"`
	NegotiatedVersion      string `json:"negotiated_version,omitempty"`
	CipherSuite            string `json:"cipher_suite,omitempty"`
	Group                  string `json:"group,omitempty"`
	ApplicationProtocol    string `json:"application_protocol,omitempty"`
	HRRStatus              string `json:"hrr_status,omitempty"`
	HTTPStatus             int    `json:"http_status,omitempty"`

	Detail              map[string]string `json:"detail,omitempty"`
	CaptureCompleteness string            `json:"capture_completeness,omitempty"`
	RemainingUnknowns   []string          `json:"remaining_unknowns,omitempty"`
}

// Claim is a scoped interpretation of one or more observations. It always
// carries its boundary (what it does not establish) and the smallest next check
// that would discriminate between live alternatives.
type Claim struct {
	ID                      string   `json:"id"`
	RuleID                  string   `json:"rule_id"`
	Register                string   `json:"register"`
	Statement               string   `json:"statement"`
	Scope                   string   `json:"scope"`
	Status                  string   `json:"status"`
	SupportingObservations  []string `json:"supporting_observations,omitempty"`
	Alternatives            []string `json:"alternatives,omitempty"`
	UncheckedItems          []string `json:"unchecked_items,omitempty"`
	NextDiscriminatingCheck string   `json:"next_discriminating_check"`
}

// LiveRun is a mutable run guarded by its own lock. The workbench holds
// LiveRuns while an investigation is in progress; readers take a Snapshot,
// which is a plain Run value safe to copy and serialize. Keeping the lock out of
// Run means a snapshot can be passed around freely.
type LiveRun struct {
	mu  sync.Mutex
	run Run
}

// NewLiveRun wraps an initial run value for concurrent, append-only mutation.
func NewLiveRun(r Run) *LiveRun {
	return &LiveRun{run: r}
}

// AddObservation appends an observation under the run's lock and returns its ID.
func (l *LiveRun) AddObservation(o Observation) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if o.ID == "" {
		o.ID = NewID("obs")
	}
	l.run.Observations = append(l.run.Observations, o)
	return o.ID
}

// AddClaim appends a claim under the run's lock and returns its ID.
func (l *LiveRun) AddClaim(c Claim) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c.ID == "" {
		c.ID = NewID("claim")
	}
	l.run.Claims = append(l.run.Claims, c)
	return c.ID
}

// AddConsentEvent appends a consent/authorization event under the run's lock.
func (l *LiveRun) AddConsentEvent(e ConsentEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.run.ConsentEvents = append(l.run.ConsentEvents, e)
}

// RunID returns the run's identifier.
func (l *LiveRun) RunID() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.run.RunID
}

// Scope returns the run's authorized target scope.
func (l *LiveRun) Scope() TargetScope {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.run.TargetScope
}

// Snapshot returns a deep-enough copy of the run, safe to serialize for a reader
// without racing concurrent appends.
func (l *LiveRun) Snapshot() Run {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := l.run
	cp.Observations = append([]Observation(nil), l.run.Observations...)
	cp.Claims = append([]Claim(nil), l.run.Claims...)
	cp.ConsentEvents = append([]ConsentEvent(nil), l.run.ConsentEvents...)
	return cp
}

// NewID returns a short random identifier with the given prefix. Randomness,
// not time, so identifiers do not leak ordering or wall-clock information.
func NewID(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}

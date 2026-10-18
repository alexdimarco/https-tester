// Package assess summarizes the security-relevant protocol posture a run has
// observed, with the risks tied to what is enabled and what is not.
//
// It is deliberately constrained by the design's rules:
//   - no A–F grade and no aggregate score;
//   - "observed accepted" is evidence a setting is enabled, but a rejected
//     single-group or single-version offer is NOT proof the server disabled it;
//   - anything not tested is reported as not tested, never as safe or unsafe.
//
// It reads only what the run already recorded; it performs no network activity.
package assess

import (
	"strings"

	"github.com/alexdimarco/https-tester/internal/evidence"
)

// Severity is a qualitative tag, never summed into a score.
const (
	SeverityInfo      = "info"      // observed and expected / healthy
	SeverityConsider  = "consider"  // worth noting; often an interoperability point
	SeverityAttention = "attention" // a problem was actually observed
)

// KnowledgeAsOf is the date the protocol-risk baseline in this file was last
// reviewed by the author against the authoritative sources in References.
// Security knowledge ages — what is "preferred" or "weak" changes — so
// judgments here are current only as of this date and must be re-reviewed. It
// is the author's baseline, not a live feed, and it is not the time the tests
// ran.
const KnowledgeAsOf = "2026-10-18"

// Reference is an authoritative source backing a risk claim. The claims in this
// file were checked against these on KnowledgeAsOf.
type Reference struct {
	Topic string `json:"topic"`
	Cite  string `json:"cite"`
	URL   string `json:"url"`
}

// References are the primary sources the risk notes were verified against.
var References = []Reference{
	{Topic: "TLS 1.0 and 1.1 are formally deprecated (weak)", Cite: "IETF RFC 8996 / BCP 195 (Mar 2021)", URL: "https://www.rfc-editor.org/rfc/rfc8996"},
	{Topic: "Secure-use TLS baseline: MUST NOT negotiate TLS 1.0/1.1, MUST support 1.2, SHOULD prefer 1.3", Cite: "IETF RFC 9325 / BCP 195 (Nov 2022, obsoletes RFC 7525)", URL: "https://www.rfc-editor.org/rfc/rfc9325"},
	{Topic: "Server-side TLS configuration profiles (Intermediate, Modern)", Cite: "docs.tlsref.org (successor to Mozilla Server-Side TLS)", URL: "https://docs.tlsref.org/"},
	{Topic: "TLS 1.3 protocol; ephemeral-only key exchange gives forward secrecy", Cite: "IETF RFC 8446 (Aug 2018)", URL: "https://www.rfc-editor.org/rfc/rfc8446"},
	{Topic: "TLS 1.2 baseline, TLS 1.3 recommended (US gov guidance)", Cite: "NIST SP 800-52 Rev. 2 (Aug 2019)", URL: "https://doi.org/10.6028/NIST.SP.800-52r2"},
	{Topic: "ML-KEM post-quantum KEM (ML-KEM-768 parameter set)", Cite: "NIST FIPS 203 (Aug 2024)", URL: "https://doi.org/10.6028/NIST.FIPS.203"},
	{Topic: "X25519MLKEM768 hybrid key exchange for TLS 1.3", Cite: "IETF draft-ietf-tls-ecdhe-mlkem (Standards Track)", URL: "https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/"},
	{Topic: "Certificate revocation status (OCSP)", Cite: "IETF RFC 6960", URL: "https://www.rfc-editor.org/rfc/rfc6960"},
	{Topic: "Go cannot select TLS 1.3 cipher suites", Cite: "Go crypto/tls Config documentation", URL: "https://pkg.go.dev/crypto/tls#Config"},
}

// Assessment is the posture summary for one run.
type Assessment struct {
	KnowledgeAsOf string      `json:"knowledge_as_of"`
	Scope         string      `json:"scope"`
	Properties    []Property  `json:"properties"`
	NotTested     []Gap       `json:"not_tested"`
	References    []Reference `json:"references"`
	Disclaimer    string      `json:"disclaimer"`
}

// Property is one observed protocol fact and its plain-language implication.
type Property struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Severity string `json:"severity"`
	Note     string `json:"note"`
}

// Gap is something this build did not test and why it still matters.
type Gap struct {
	Name string `json:"name"`
	Why  string `json:"why"`
}

// Build derives the assessment from a run's recorded observations.
func Build(run evidence.Run) Assessment {
	a := Assessment{
		KnowledgeAsOf: KnowledgeAsOf,
		Scope: "Covers only the tests actually run against " + orUnknown(run.TargetScope.Authority) +
			". “Observed accepted” is evidence a setting is enabled; a rejected single offer is not proof it is disabled; “not tested” is neither.",
		Disclaimer: "This is not a security grade or a pass/fail verdict for the server. It summarizes what these tests observed for this client against this endpoint. The protocol-risk judgments were checked against the listed sources on " + KnowledgeAsOf + " and should be re-reviewed periodically.",
		References: References,
	}

	sc := scan(run)
	a.Properties = buildProperties(sc.certState, sc.tls12, sc.tls13, sc.groups, sc.groupOrder, sc.pq)
	a.NotTested = buildGaps(sc.tls12, sc.tls13)
	return a
}

// scanResult is the observed TLS posture distilled from a run's observations.
type scanResult struct {
	tls12, tls13 *bool
	groups       map[string]bool
	groupOrder   []string
	pq           bool
	certState    string // "", "pass", or a normalized certificate error
}

func scan(run evidence.Run) scanResult {
	sc := scanResult{groups: map[string]bool{}}
	for _, o := range run.Observations {
		if o.Stage == evidence.StageCertificate && o.Outcome == evidence.OutcomePass && sc.certState == "" {
			sc.certState = "pass"
		}
		if o.Stage != evidence.StageTLS {
			continue
		}
		pass := o.Outcome == evidence.OutcomePass
		if pass && strings.Contains(o.Group, "MLKEM") {
			sc.pq = true
		}
		switch {
		case o.ProbeID == "TLS-12":
			sc.tls12 = boolPtr(pass)
		case o.ProbeID == "TLS-13":
			sc.tls13 = boolPtr(pass)
		case strings.HasPrefix(o.ProbeID, "GROUP-"):
			name := groupFriendly(o.ProbeID)
			if _, seen := sc.groups[name]; !seen {
				sc.groupOrder = append(sc.groupOrder, name)
			}
			sc.groups[name] = pass
		case o.ProbeID == "HTTPS-01" && pass:
			if o.NegotiatedVersion == "TLS 1.3" && sc.tls13 == nil {
				sc.tls13 = boolPtr(true)
			}
			if o.NegotiatedVersion == "TLS 1.2" && sc.tls12 == nil {
				sc.tls12 = boolPtr(true)
			}
		}
		if !pass && isCertError(o.NormalizedError) && sc.certState == "" {
			sc.certState = o.NormalizedError
		}
	}
	return sc
}

func buildProperties(certState string, tls12, tls13 *bool, groups map[string]bool, order []string, pq bool) []Property {
	var props []Property

	// Certificate / trust.
	switch {
	case certState == "pass":
		props = append(props, Property{
			Name: "Certificate and trust", State: "observed passing", Severity: SeverityInfo,
			Note: "The certificate verified against the chosen trust for this attempt. Revocation (OCSP/CRL) was not checked.",
		})
	case certState != "":
		props = append(props, Property{
			Name: "Certificate and trust", State: "failed", Severity: SeverityAttention,
			Note: certPlain(certState) + " A browser will likely also refuse or warn; fix the certificate before relying on this endpoint.",
		})
	}

	// TLS versions.
	if tls13 != nil {
		if *tls13 {
			props = append(props, Property{
				Name: "TLS 1.3", State: "observed working", Severity: SeverityInfo,
				Note: "The current, preferred protocol; provides forward secrecy and the modern handshake.",
			})
		} else {
			props = append(props, Property{
				Name: "TLS 1.3", State: "rejected for the tested offer", Severity: SeverityConsider,
				Note: "A TLS 1.3 offer did not complete for this attempt, so clients that require 1.3 may fail here. This is not proof 1.3 is disabled; confirm with the server configuration.",
			})
		}
	}
	if tls12 != nil {
		if *tls12 {
			props = append(props, Property{
				Name: "TLS 1.2", State: "observed working", Severity: SeverityConsider,
				Note: "Broadly compatible and still acceptable. If your policy is TLS 1.3 only, note that 1.2 is still reachable here.",
			})
		} else {
			props = append(props, Property{
				Name: "TLS 1.2", State: "rejected for the tested offer", Severity: SeverityConsider,
				Note: "A TLS 1.2 offer did not complete, so older clients without TLS 1.3 may fail to connect here.",
			})
		}
	}

	// Key-exchange groups.
	var accepted, rejected []string
	for _, name := range order {
		if groups[name] {
			accepted = append(accepted, name)
		} else {
			rejected = append(rejected, name)
		}
	}
	if len(accepted) > 0 {
		props = append(props, Property{
			Name: "Key exchange — accepted", State: "observed accepted: " + strings.Join(accepted, ", "), Severity: SeverityInfo,
			Note: "These key-exchange groups completed a handshake and provide forward secrecy.",
		})
	}
	if len(rejected) > 0 {
		props = append(props, Property{
			Name: "Key exchange — rejected for offer", State: "rejected: " + strings.Join(rejected, ", "), Severity: SeverityConsider,
			Note: "A client offering only one of these groups would fail to connect here. This is not proof the group is disabled server-side; confirm with the server configuration.",
		})
	}

	// Post-quantum readiness (only when TLS 1.3 was exercised).
	if pq {
		props = append(props, Property{
			Name: "Post-quantum readiness", State: "hybrid group observed", Severity: SeverityInfo,
			Note: "A hybrid post-quantum key exchange (ML-KEM, NIST FIPS 203; hybrid per IETF draft-ietf-tls-ecdhe-mlkem) was negotiated, which protects today's traffic against future “harvest-now, decrypt-later” decryption.",
		})
	} else if tls13 != nil && *tls13 {
		props = append(props, Property{
			Name: "Post-quantum readiness", State: "not observed", Severity: SeverityConsider,
			Note: "No hybrid post-quantum key-exchange group was observed in these tests. That is not proof the server lacks one.",
		})
	}

	return props
}

func buildGaps(tls12, tls13 *bool) []Gap {
	gaps := []Gap{
		{Name: "Legacy TLS 1.0 / 1.1", Why: "Not tested by this build. They are formally deprecated by IETF RFC 8996 (BCP 195); if a server still accepts them they are considered weak and should be disabled. Test them separately."},
		{Name: "Individual / weak cipher suites", Why: "TLS 1.3 cipher suites are not selectable in Go, so this build does not enumerate them. Use the planned OpenSSL adapter for cipher-level testing."},
		{Name: "Certificate revocation (OCSP/CRL)", Why: "Not checked. A revoked but otherwise-valid certificate would still appear to pass here."},
		{Name: "HSTS, ECH, HTTP/3, and policy/compliance", Why: "Not evaluated by this build."},
	}
	if tls13 == nil {
		gaps = append(gaps, Gap{Name: "TLS 1.3 (direct test)", Why: "Not directly tested in this run; run the TLS 1.3 test to confirm support."})
	}
	if tls12 == nil {
		gaps = append(gaps, Gap{Name: "TLS 1.2 (direct test)", Why: "Not directly tested in this run; run the TLS 1.2 test to confirm compatibility."})
	}
	return gaps
}

func groupFriendly(probeID string) string {
	switch probeID {
	case "GROUP-X25519":
		return "X25519"
	case "GROUP-P256":
		return "P-256"
	case "GROUP-P384":
		return "P-384"
	case "GROUP-P521":
		return "P-521"
	default:
		return strings.TrimPrefix(probeID, "GROUP-")
	}
}

func isCertError(normalized string) bool {
	return strings.HasPrefix(normalized, "certificate_")
}

func certPlain(normalized string) string {
	switch normalized {
	case "certificate_invalid":
		return "The certificate is expired or not yet valid."
	case "certificate_hostname_mismatch":
		return "The certificate does not cover the address requested."
	case "certificate_unknown_authority":
		return "The certificate's issuer is not trusted by this machine."
	default:
		return "The certificate did not validate."
	}
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "the target"
	}
	return s
}

func boolPtr(b bool) *bool { return &b }

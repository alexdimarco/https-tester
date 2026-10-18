package assess

import "github.com/alexdimarco/https-tester/internal/evidence"

// ProfileTarget is a named security target the observed posture is compared
// against. The names follow the current public TLS guidance (docs.tlsref.org,
// the community successor to Mozilla Server-Side TLS), which today defines
// Intermediate and Modern; the former "Old" tier has been retired as insecure,
// so the legacy target here is labelled below-baseline rather than recommended.
type ProfileTarget struct {
	Name     string         `json:"name"`
	Summary  string         `json:"summary"`
	Standing string         `json:"standing"` // recommended | high-security | below-baseline
	Source   string         `json:"source"`
	Checks   []ProfileCheck `json:"checks"`
	Note     string         `json:"note"`
}

// ProfileCheck is one expectation of a profile and whether the run met it.
type ProfileCheck struct {
	Expectation string `json:"expectation"`
	Status      string `json:"status"` // met | unmet | not_tested | consider
	Detail      string `json:"detail"`
}

const profileNote = "Compares observed TLS-version posture only. Cipher-suite strength and legacy TLS 1.0/1.1 acceptance are not fully testable by this build; use the openssl client profile and a dedicated scanner to complete a conformance check."

// CompareProfiles reports how the run's observed posture lines up with the
// legacy, Intermediate, and Modern targets.
func CompareProfiles(run evidence.Run) []ProfileTarget {
	sc := scan(run)
	return []ProfileTarget{legacyTarget(sc), intermediateTarget(sc), modernTarget(sc)}
}

func legacyTarget(sc scanResult) ProfileTarget {
	return ProfileTarget{
		Name:     "Widest compatibility (legacy)",
		Standing: "below-baseline",
		Summary:  "Serves the broadest range of clients, including obsolete ones, at the cost of security. No current standard endorses this; the former “Old” profile was retired.",
		Source:   "former Mozilla “Old” tier (retired); contrary to IETF RFC 9325",
		Note:     profileNote,
		Checks: []ProfileCheck{
			tlsCheck("Modern clients can connect (TLS 1.2 or 1.3)", eitherWorks(sc.tls12, sc.tls13)),
			{
				Expectation: "Accepts legacy TLS 1.0 / 1.1 for very old clients",
				Status:      "not_tested",
				Detail:      "This build does not test TLS 1.0/1.1. Enabling them is deprecated (RFC 8996) and fails modern baselines; confirm with a dedicated scanner only if you must support obsolete clients.",
			},
		},
	}
}

func intermediateTarget(sc scanResult) ProfileTarget {
	return ProfileTarget{
		Name:     "Good security, wide compatibility (Intermediate)",
		Standing: "recommended",
		Summary:  "TLS 1.2 and 1.3 with no weak ciphers; broad modern-browser compatibility. The recommended general-purpose baseline, suited to e.g. file-transfer sites.",
		Source:   "docs.tlsref.org “Intermediate”; IETF RFC 9325 (BCP 195); NIST SP 800-52 Rev. 2",
		Note:     profileNote,
		Checks: []ProfileCheck{
			tlsCheck("TLS 1.3 supported", statusOf(sc.tls13)),
			tlsCheck("TLS 1.2 supported (for broad compatibility)", statusOf(sc.tls12)),
			{Expectation: "No legacy TLS 1.0 / 1.1 enabled", Status: "not_tested", Detail: "legacy versions are not tested by this build; confirm with a scanner."},
			{Expectation: "No weak cipher suites", Status: "not_tested", Detail: "Go cannot enumerate TLS 1.3 cipher suites; use the openssl client profile or a scanner."},
		},
	}
}

func modernTarget(sc scanResult) ProfileTarget {
	// For Modern, TLS 1.2 being reachable is a (mild) miss: strict Modern is
	// TLS 1.3-only.
	tls12Absent := ProfileCheck{Expectation: "TLS 1.2 not offered (strict Modern is TLS 1.3-only)"}
	switch {
	case sc.tls12 == nil:
		tls12Absent.Status = "not_tested"
		tls12Absent.Detail = "run the TLS 1.2 test to confirm whether 1.2 is still reachable."
	case *sc.tls12:
		tls12Absent.Status = "consider"
		tls12Absent.Detail = "TLS 1.2 is still reachable here; a strict Modern profile offers TLS 1.3 only. This is a policy choice, not a defect."
	default:
		tls12Absent.Status = "met"
		tls12Absent.Detail = "a TLS 1.2 offer did not complete, consistent with a TLS 1.3-only posture."
	}
	return ProfileTarget{
		Name:     "High security (Modern)",
		Standing: "high-security",
		Summary:  "TLS 1.3 only, modern clients. For high-value transactions such as banking; pair with sector rules (e.g. PCI DSS for cardholder data).",
		Source:   "docs.tlsref.org “Modern”; PCI DSS for cardholder data (per widely-cited guidance, not re-verified at the PCI SSC source)",
		Note:     profileNote,
		Checks: []ProfileCheck{
			tlsCheck("TLS 1.3 supported", statusOf(sc.tls13)),
			tls12Absent,
			{Expectation: "No legacy TLS 1.0 / 1.1 enabled", Status: "not_tested", Detail: "legacy versions are not tested by this build; confirm with a scanner."},
		},
	}
}

func tlsCheck(expectation, status string) ProfileCheck {
	detail := map[string]string{
		"met":        "observed working in this run.",
		"unmet":      "a direct test of this did not complete in this run.",
		"not_tested": "not directly tested in this run; run that test to confirm.",
	}[status]
	return ProfileCheck{Expectation: expectation, Status: status, Detail: detail}
}

func statusOf(b *bool) string {
	switch {
	case b == nil:
		return "not_tested"
	case *b:
		return "met"
	default:
		return "unmet"
	}
}

func eitherWorks(a, b *bool) string {
	if (a != nil && *a) || (b != nil && *b) {
		return "met"
	}
	if a == nil && b == nil {
		return "not_tested"
	}
	return "unmet"
}

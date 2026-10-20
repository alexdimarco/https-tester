package assess

import (
	"fmt"
	"strings"

	"github.com/alexdimarco/https-tester/internal/evidence"
)

// Summary is the short, lead-with-the-answer overview for the top of a report.
// It restates, in plain words, only what the tests observed: whether a verified
// HTTPS connection was obtained, which issues (if any) were actually seen, and
// how the observed posture lines up with the named targets. It is deliberately
// NOT a security grade, a score, or a certification of the server — it carries
// the same constraints as the rest of this package (see the package doc).
type Summary struct {
	Headline       string   `json:"headline"`
	Connection     string   `json:"connection"` // verified | failed | not_tested
	ConnectionNote string   `json:"connection_note"`
	Standing       string   `json:"standing"` // high-security | recommended | below-baseline | not_tested
	StandingLabel  string   `json:"standing_label"`
	StandingNote   string   `json:"standing_note"`
	Issues         []string `json:"issues"`          // problems actually observed (needs attention)
	Watch          []string `json:"watch,omitempty"` // interoperability / policy notes worth seeing
	TestsRun       int      `json:"tests_run"`
	KnowledgeAsOf  string   `json:"knowledge_as_of"`
	Caveat         string   `json:"caveat"`
}

const summaryCaveat = "This reports what THIS client observed against this endpoint for these attempts — not a security grade and not a certification of the server. Cipher strength, legacy TLS 1.0/1.1, and certificate revocation were not tested by this build."

// standingBase is appended to every standing note so the boundary travels with
// the judgement, not just at the end of the report.
const standingBase = "Based only on the TLS-version checks run so far; cipher strength, legacy TLS 1.0/1.1, and revocation were not tested."

// Summarize distills a run into the short executive summary. It draws on the
// same scan, properties, and version evidence as the rest of the package, so
// the headline cannot drift from the detail below it.
func Summarize(run evidence.Run) Summary {
	s := Summary{
		TestsRun:      len(run.Claims),
		KnowledgeAsOf: KnowledgeAsOf,
		Caveat:        summaryCaveat,
	}

	conn, connNote := connectionState(run)
	s.Connection, s.ConnectionNote = conn, connNote

	// Issues (observed problems) and watch items (interoperability / policy
	// notes) come straight from the assessment properties, so the summary and
	// the detail below it name the same things.
	for _, p := range Build(run).Properties {
		switch p.Severity {
		case SeverityAttention:
			s.Issues = append(s.Issues, p.Name+": "+p.State+". "+p.Note)
		case SeverityConsider:
			s.Watch = append(s.Watch, p.Name+": "+p.State+".")
		}
	}

	sc := scan(run)
	s.Standing, s.StandingLabel, s.StandingNote = standing(sc, conn, len(s.Issues) > 0)
	s.Headline = headline(conn, s.Standing, len(s.Issues))
	return s
}

// connectionState reports whether a verified HTTPS response was obtained, and
// if not, how far the deepest attempt reached. A certificate failure is called
// out specifically because it is the most common fixable problem.
func connectionState(run evidence.Run) (state, note string) {
	httpPass, sawFailure, sawCertFail := false, false, false
	var failStage evidence.Stage
	failRank := -1
	var certErr string
	for _, o := range run.Observations {
		if o.Stage == evidence.StageHTTP && o.Outcome == evidence.OutcomePass {
			httpPass = true
		}
		if o.Outcome == evidence.OutcomeFail || o.Outcome == evidence.OutcomeInconclusive {
			sawFailure = true
			// Keep the deepest failing stage actually reached, not just the last
			// one in record order, so the note does not understate progress.
			if r := stageRank(o.Stage); r > failRank {
				failRank = r
				failStage = o.Stage
			}
			if isCertError(o.NormalizedError) {
				sawCertFail = true
				certErr = o.NormalizedError
			}
		}
	}
	switch {
	case httpPass:
		return "verified", "A verified HTTPS response was obtained — the certificate was trusted and an HTTP reply was read."
	case sawCertFail:
		return "failed", "The connection reached TLS but the certificate did not validate: " + strings.ToLower(certPlain(certErr))
	case sawFailure:
		return "failed", fmt.Sprintf("No verified HTTPS response; the deepest attempt stopped at the %s stage. This does not by itself prove a server defect.", strings.ToUpper(string(failStage)))
	default:
		return "not_tested", "No connection test has completed yet."
	}
}

// standing places the observed posture against the named targets, conservatively
// and only as far as the run actually tested. It never awards a tier on evidence
// it does not have.
func standing(sc scanResult, conn string, hasIssues bool) (code, label, note string) {
	v12, v13 := sc.tls12, sc.tls13
	noPosture := v12 == nil && v13 == nil

	switch {
	case conn == "not_tested" && noPosture:
		return "not_tested", "Not yet characterized",
			"Run the default verified request to produce a standing."
	case hasIssues:
		return "below-baseline", "Below the recommended baseline — issues observed",
			"One or more problems were observed (see Issues); fix those before judging the posture. " + standingBase
	case v13 != nil && !*v13:
		return "below-baseline", "Below the recommended baseline",
			"A direct TLS 1.3 test did not complete. TLS 1.3 is the current preferred protocol (IETF RFC 9325 / docs.tlsref.org). " + standingBase
	case v13 != nil && *v13 && v12 != nil && !*v12:
		return "high-security", "Consistent with High security (Modern), as far as tested",
			"TLS 1.3 works and a TLS 1.2 offer did not complete, consistent with a TLS 1.3-only posture. Legacy TLS 1.0/1.1 was not tested. " + standingBase
	case v13 != nil && *v13:
		n := "TLS 1.3 works. "
		if v12 == nil {
			n += "TLS 1.2 was not separately tested — run the TLS 1.2 test to confirm broad compatibility. "
		} else {
			n += "TLS 1.2 also works, for broad compatibility. "
		}
		return "recommended", "Consistent with Good security, wide compatibility (Intermediate), as far as tested", n + standingBase
	case v12 != nil && *v12:
		return "recommended", "Meets the TLS 1.2 baseline; TLS 1.3 not yet confirmed",
			"A verified connection used TLS 1.2; TLS 1.3 was not observed. Run the TLS 1.3 test to confirm the recommended posture. " + standingBase
	default:
		return "not_tested", "Not yet characterized",
			"The tests run so far do not establish a TLS-version posture. " + standingBase
	}
}

func headline(conn, standingCode string, issueCount int) string {
	switch {
	case conn == "not_tested" && standingCode == "not_tested":
		return "No test has completed yet — run the default verified request to produce a summary."
	case issueCount > 0 && conn == "failed":
		return fmt.Sprintf("This client could NOT complete a verified HTTPS connection, and %s.", issueClause(issueCount))
	case issueCount > 0:
		return fmt.Sprintf("A verified HTTPS connection succeeded, but %s.", issueClause(issueCount))
	case conn == "failed":
		return "This client could NOT complete a verified HTTPS connection (no server defect is proven — see the connection note)."
	case standingCode == "high-security":
		return "Verified HTTPS connection; the observed posture is consistent with a high-security (TLS 1.3-only) target, as far as tested."
	case standingCode == "recommended":
		return "Verified HTTPS connection; the observed posture is consistent with the recommended baseline, as far as tested."
	case standingCode == "below-baseline":
		return "Verified HTTPS connection, but the observed posture is below the recommended baseline (see the standing note)."
	default:
		return "Verified HTTPS connection; the posture is not yet fully characterized."
	}
}

// issueClause names the number of observed issues with a subject-agreeing verb,
// so a single issue reads "1 issue needs attention", not "1 issue need attention".
func issueClause(n int) string {
	if n == 1 {
		return "1 issue needs attention"
	}
	return fmt.Sprintf("%d issues need attention", n)
}

// stageRank orders the connection stages shallow-to-deep so connectionState can
// report how far the deepest failing attempt actually reached, independent of the
// order observations were recorded in.
func stageRank(s evidence.Stage) int {
	switch s {
	case evidence.StageInput:
		return 0
	case evidence.StageDNS:
		return 1
	case evidence.StageTCP:
		return 2
	case evidence.StageTLS:
		return 3
	case evidence.StageCertificate:
		return 4
	case evidence.StageHTTP:
		return 5
	default:
		return -1
	}
}

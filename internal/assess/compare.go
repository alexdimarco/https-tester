package assess

import (
	"fmt"

	"github.com/alexdimarco/https-tester/internal/evidence"
)

// Comparison is a side-by-side reading of two runs, dimension by dimension. It
// carries the same constraints as the rest of this package: it is NOT a grade
// and it never declares an overall "winner". It states, for each dimension,
// what each server was observed to do, whether they agree, and — crucially —
// when a dimension was tested on only one side, so it cannot be compared yet.
type Comparison struct {
	A             Side         `json:"a"`
	B             Side         `json:"b"`
	Verdict       string       `json:"verdict"`
	Rows          []CompareRow `json:"rows"`
	KnowledgeAsOf string       `json:"knowledge_as_of"`
	Caveat        string       `json:"caveat"`
}

// Side is the compact header for one server in a comparison, drawn from the
// same executive summary the single-server report leads with.
type Side struct {
	Label         string   `json:"label"`     // "A" or "B"
	Host          string   `json:"host"`      // the host (or authority) tested
	Authority     string   `json:"authority"` // host:port
	Connection    string   `json:"connection"`
	Standing      string   `json:"standing"`
	StandingLabel string   `json:"standing_label"`
	TestsRun      int      `json:"tests_run"`
	IssueCount    int      `json:"issue_count"`
	Issues        []string `json:"issues,omitempty"`
}

// CompareRow is one compared dimension. Agreement is "same", "differs", or
// "incomparable" (at least one side did not test it). Note explains a
// difference, or names which side still needs to run the test.
type CompareRow struct {
	Dimension string `json:"dimension"`
	A         string `json:"a"`
	B         string `json:"b"`
	Agreement string `json:"agreement"`
	Note      string `json:"note,omitempty"`
}

const (
	agreeSame  = "same"
	agreeDiff  = "differs"
	agreeNone  = "incomparable"
	notTested  = "not tested"
	compareCav = "Compares only what each client observed for these attempts — not a grade or a certification of either server. Cipher strength, legacy TLS 1.0/1.1, and certificate revocation were not tested by this build."
)

// Compare reads two runs and reports, dimension by dimension, how the servers
// line up. It reuses the same scan and summary the single-server views use, so
// a cell can never drift from what that server's own report would say.
func Compare(a, b evidence.Run) Comparison {
	sa, sb := scan(a), scan(b)
	sideA, sideB := side("A", a), side("B", b)

	var rows []CompareRow
	rows = append(rows, connRow(sideA, sideB))
	rows = append(rows, tierRow(sideA, sideB))
	rows = append(rows, versionRow("TLS 1.3", sa.tls13, sb.tls13))
	rows = append(rows, versionRow("TLS 1.2", sa.tls12, sb.tls12))
	rows = append(rows, groupRows(sa, sb)...)
	rows = append(rows, certRow(sa, sb))
	rows = append(rows, issuesRow(sideA, sideB))

	return Comparison{
		A:             sideA,
		B:             sideB,
		Verdict:       verdict(sideA, sideB, rows),
		Rows:          rows,
		KnowledgeAsOf: KnowledgeAsOf,
		Caveat:        compareCav,
	}
}

func side(label string, run evidence.Run) Side {
	sum := Summarize(run)
	host := run.TargetScope.Host
	if host == "" {
		host = run.TargetScope.Authority
	}
	if host == "" {
		host = "server " + label
	}
	return Side{
		Label:         label,
		Host:          host,
		Authority:     run.TargetScope.Authority,
		Connection:    sum.Connection,
		Standing:      sum.Standing,
		StandingLabel: sum.StandingLabel,
		TestsRun:      sum.TestsRun,
		IssueCount:    len(sum.Issues),
		Issues:        sum.Issues,
	}
}

func connRow(a, b Side) CompareRow {
	ca, cb := connCell(a.Connection), connCell(b.Connection)
	aTested := a.Connection != "not_tested"
	bTested := b.Connection != "not_tested"
	row := CompareRow{Dimension: "Verified connection", A: ca, B: cb,
		Agreement: agreementOf(aTested, bTested, a.Connection == b.Connection)}
	switch row.Agreement {
	case agreeDiff:
		row.Note = "One client obtained a verified HTTPS response and the other did not."
	case agreeNone:
		row.Note = missingNote(aTested, bTested)
	}
	return row
}

func tierRow(a, b Side) CompareRow {
	aTested := a.Standing != "not_tested" && a.Standing != ""
	bTested := b.Standing != "not_tested" && b.Standing != ""
	row := CompareRow{Dimension: "Security tier", A: shortTier(a.Standing), B: shortTier(b.Standing),
		Agreement: agreementOf(aTested, bTested, a.Standing == b.Standing)}
	switch row.Agreement {
	case agreeDiff:
		row.Note = fmt.Sprintf("As far as tested — %s: %s; %s: %s. Not a grade; the rows below show why.",
			a.Host, a.StandingLabel, b.Host, b.StandingLabel)
	case agreeNone:
		row.Note = "Run the default request and the TLS-version tests on both to place each on a tier."
	}
	return row
}

func versionRow(name string, a, b *bool) CompareRow {
	row := CompareRow{Dimension: name, A: versionCell(a), B: versionCell(b),
		Agreement: agreementOf(a != nil, b != nil, equalBool(a, b))}
	switch row.Agreement {
	case agreeDiff:
		row.Note = fmt.Sprintf("One client completed %s and the other did not; clients that require %s would behave differently here.", name, name)
	case agreeNone:
		row.Note = missingNote(a != nil, b != nil)
	}
	return row
}

// groupRows produces one row per key-exchange group tested on either side. If
// neither side ran a group test, it returns a single placeholder row so the
// dimension is still visible and invites running the test on both.
func groupRows(sa, sb scanResult) []CompareRow {
	order := unionGroups(sa, sb)
	if len(order) == 0 {
		return []CompareRow{{
			Dimension: "Key exchange", A: notTested, B: notTested,
			Agreement: agreeNone,
			Note:      "Run the key-exchange tests (X25519, P-256, P-384) on both to compare.",
		}}
	}
	var rows []CompareRow
	for _, name := range order {
		pa, pb := groupPtr(sa, name), groupPtr(sb, name)
		row := CompareRow{Dimension: "Key exchange — " + name, A: groupCell(pa), B: groupCell(pb),
			Agreement: agreementOf(pa != nil, pb != nil, equalBool(pa, pb))}
		switch row.Agreement {
		case agreeDiff:
			row.Note = "One server completed a handshake offering only this group and the other did not (a single rejected offer is not proof the group is disabled)."
		case agreeNone:
			row.Note = missingNote(pa != nil, pb != nil)
		}
		rows = append(rows, row)
	}
	return rows
}

func certRow(sa, sb scanResult) CompareRow {
	aTested := sa.certState != ""
	bTested := sb.certState != ""
	row := CompareRow{Dimension: "Certificate", A: certCell(sa.certState), B: certCell(sb.certState),
		Agreement: agreementOf(aTested, bTested, sa.certState == sb.certState)}
	switch row.Agreement {
	case agreeDiff:
		row.Note = "The certificate result differs between the two servers."
	case agreeNone:
		row.Note = missingNote(aTested, bTested)
	}
	return row
}

func issuesRow(a, b Side) CompareRow {
	// Issues are only meaningful once a side has run a test.
	if a.TestsRun == 0 || b.TestsRun == 0 {
		return CompareRow{Dimension: "Issues needing attention", A: issueCell(a), B: issueCell(b),
			Agreement: agreeNone, Note: "Run tests on both servers to compare observed issues."}
	}
	both0 := a.IssueCount == 0 && b.IssueCount == 0
	row := CompareRow{Dimension: "Issues needing attention", A: issueCell(a), B: issueCell(b),
		Agreement: map[bool]string{true: agreeSame, false: agreeDiff}[both0]}
	if !both0 {
		row.Note = "Each server's specific issues are listed under its name above; a count match does not mean the same issues."
	}
	return row
}

func verdict(a, b Side, rows []CompareRow) string {
	switch {
	case a.TestsRun == 0 && b.TestsRun == 0:
		return "Neither server has a completed test yet. Run the tests on both, then compare."
	case a.TestsRun == 0:
		return fmt.Sprintf("%s has no completed test yet — run its tests to compare the two.", a.Host)
	case b.TestsRun == 0:
		return fmt.Sprintf("%s has no completed test yet — run its tests to compare the two.", b.Host)
	}

	var diffs, incs int
	for _, r := range rows {
		switch r.Agreement {
		case agreeDiff:
			diffs++
		case agreeNone:
			incs++
		}
	}

	var base string
	if a.Standing == b.Standing && a.Standing != "not_tested" && a.Standing != "" {
		base = fmt.Sprintf("Both servers land in the same tier as far as tested: %s.", a.StandingLabel)
	} else {
		base = fmt.Sprintf("Different standings as far as tested — %s: %s; %s: %s. This is not a grade; see the rows for where they differ.",
			a.Host, a.StandingLabel, b.Host, b.StandingLabel)
	}
	if diffs > 0 {
		base += fmt.Sprintf(" They differ on %s below.", countNoun(diffs, "tested dimension", "tested dimensions"))
	} else {
		base += " No tested dimension differs."
	}
	if incs > 0 {
		base += fmt.Sprintf(" %s could not be compared because they were not run on both servers (marked “can’t compare”); run them on both for a complete picture.",
			countNoun(incs, "check", "checks"))
	}
	return base
}

// --- cell formatters -------------------------------------------------------

func connCell(state string) string {
	switch state {
	case "verified":
		return "verified"
	case "failed":
		return "not completed"
	default:
		return notTested
	}
}

func versionCell(b *bool) string {
	switch {
	case b == nil:
		return notTested
	case *b:
		return "works"
	default:
		return "offer did not complete"
	}
}

func groupCell(b *bool) string {
	switch {
	case b == nil:
		return notTested
	case *b:
		return "accepted"
	default:
		return "rejected (single offer)"
	}
}

func certCell(certState string) string {
	switch certState {
	case "":
		return notTested
	case "pass":
		return "valid & trusted"
	case "certificate_invalid":
		return "expired / not yet valid"
	case "certificate_hostname_mismatch":
		return "name mismatch"
	case "certificate_unknown_authority":
		return "untrusted issuer"
	default:
		return "did not validate"
	}
}

func issueCell(s Side) string {
	if s.TestsRun == 0 {
		return notTested
	}
	if s.IssueCount == 0 {
		return "none observed"
	}
	return countNoun(s.IssueCount, "issue", "issues") + " observed"
}

func shortTier(standing string) string {
	switch standing {
	case "high-security":
		return "Highest security"
	case "recommended":
		return "Good security"
	case "below-baseline":
		return "Below baseline"
	default:
		return notTested
	}
}

// --- small helpers ---------------------------------------------------------

func agreementOf(aTested, bTested, equal bool) string {
	if !aTested || !bTested {
		return agreeNone
	}
	if equal {
		return agreeSame
	}
	return agreeDiff
}

func missingNote(aTested, bTested bool) string {
	switch {
	case !aTested && !bTested:
		return "Not tested on either server — run it on both to compare."
	case !aTested:
		return "Tested on server B only — run it on server A to compare."
	default:
		return "Tested on server A only — run it on server B to compare."
	}
}

func equalBool(a, b *bool) bool {
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func groupPtr(sc scanResult, name string) *bool {
	v, ok := sc.groups[name]
	if !ok {
		return nil
	}
	return boolPtr(v)
}

// unionGroups lists every key-exchange group tested on either side, keeping A's
// observed order first and appending any groups only B tested.
func unionGroups(sa, sb scanResult) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range sa.groupOrder {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, n := range sb.groupOrder {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func countNoun(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}

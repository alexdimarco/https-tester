package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/alexdimarco/https-tester/internal/evidence"
)

func verifiedRun() evidence.Run {
	return evidence.Run{
		SchemaVersion: evidence.SchemaVersion,
		TargetScope:   evidence.TargetScope{InputURL: "https://example.test/", Authority: "example.test:443", Host: "example.test"},
		Claims:        []evidence.Claim{{Statement: "A verified HTTPS response was obtained."}},
		Observations: []evidence.Observation{
			{ProbeID: "HTTPS-01", Stage: evidence.StageTLS, Outcome: evidence.OutcomePass, NegotiatedVersion: "TLS 1.3"},
			{ProbeID: "HTTPS-01", Stage: evidence.StageCertificate, Outcome: evidence.OutcomePass},
			{ProbeID: "HTTPS-01", Stage: evidence.StageHTTP, Outcome: evidence.OutcomePass, HTTPStatus: 200},
		},
	}
}

func TestTextLeadsWithExecutiveSummary(t *testing.T) {
	out := Text(verifiedRun())
	idxSummary := strings.Index(out, "EXECUTIVE SUMMARY")
	idxFound := strings.Index(out, "WHAT WE FOUND")
	if idxSummary < 0 {
		t.Fatalf("report has no EXECUTIVE SUMMARY section:\n%s", out)
	}
	if idxFound >= 0 && idxSummary > idxFound {
		t.Errorf("EXECUTIVE SUMMARY should come before WHAT WE FOUND (%d vs %d)", idxSummary, idxFound)
	}
	if !strings.Contains(out, "Bottom line:") || !strings.Contains(out, "Standing:") {
		t.Errorf("summary is missing the bottom line or standing:\n%s", out)
	}
}

func TestTextIncludesTierPlacement(t *testing.T) {
	out := Text(verifiedRun())
	if !strings.Contains(out, "WHERE THIS LANDS") {
		t.Fatalf("report is missing the tier placement section:\n%s", out)
	}
	// A verified TLS 1.3 run with no separate 1.2 test lands on Intermediate.
	if !strings.Contains(out, "Intermediate") {
		t.Errorf("expected the Intermediate target to be named:\n%s", out)
	}
	if !strings.Contains(out, "server lands here") {
		t.Errorf("tier placement should mark the matched tier:\n%s", out)
	}
	if !strings.Contains(out, "How it matches") || !strings.Contains(out, "What's missing") {
		t.Errorf("tier placement should show how it matches and what is missing:\n%s", out)
	}
	// The tier section should sit after the executive summary and before details.
	if strings.Index(out, "WHERE THIS LANDS") < strings.Index(out, "EXECUTIVE SUMMARY") {
		t.Errorf("tier placement should come after the executive summary")
	}
}

func secondRun() evidence.Run {
	r := verifiedRun()
	r.TargetScope = evidence.TargetScope{InputURL: "https://other.test/", Authority: "other.test:443", Host: "other.test"}
	return r
}

func TestCompareTextIsSideBySideAndUngraded(t *testing.T) {
	a := verifiedRun()
	a.TargetScope.Host = "example.test"
	out := CompareText(a, secondRun())
	for _, want := range []string{"two-server comparison", "SIDE BY SIDE", "Server A", "Server B", "example.test", "other.test", "Bottom line:"} {
		if !strings.Contains(out, want) {
			t.Errorf("comparison text is missing %q:\n%s", want, out)
		}
	}
	// It must not invent a grade or a winner.
	for _, banned := range []string{"better", "winner", "grade A", "score"} {
		if strings.Contains(strings.ToLower(out), strings.ToLower(banned)) {
			t.Errorf("comparison text should not contain %q:\n%s", banned, out)
		}
	}
}

func TestCompareJSONDocumentHasComparisonAndBothSides(t *testing.T) {
	b, err := CompareJSONDocument(verifiedRun(), secondRun())
	if err != nil {
		t.Fatalf("CompareJSONDocument: %v", err)
	}
	var doc struct {
		Comparison struct {
			Verdict string          `json:"verdict"`
			Rows    json.RawMessage `json:"rows"`
		} `json:"comparison"`
		A json.RawMessage `json:"a"`
		B json.RawMessage `json:"b"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("comparison document is not valid JSON: %v", err)
	}
	if doc.Comparison.Verdict == "" || len(doc.Comparison.Rows) == 0 {
		t.Errorf("comparison document is missing the verdict or rows")
	}
	if len(doc.A) == 0 || len(doc.B) == 0 {
		t.Errorf("comparison document is missing one of the per-server documents")
	}
	// The comparison must be serialized before the bulky per-server runs.
	if strings.Index(string(b), "\"comparison\"") > strings.Index(string(b), "\"run\"") {
		t.Errorf("comparison should be serialized before the runs")
	}
}

func TestJSONDocumentLeadsWithSummary(t *testing.T) {
	b, err := JSONDocument(verifiedRun())
	if err != nil {
		t.Fatalf("JSONDocument: %v", err)
	}
	var doc struct {
		Summary struct {
			Headline string `json:"headline"`
			Standing string `json:"standing"`
		} `json:"summary"`
		Run        json.RawMessage `json:"run"`
		Assessment json.RawMessage `json:"assessment"`
		Profiles   json.RawMessage `json:"profiles"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("export document is not valid JSON: %v", err)
	}
	if doc.Summary.Headline == "" {
		t.Errorf("export document has no summary headline")
	}
	if len(doc.Run) == 0 || len(doc.Assessment) == 0 || len(doc.Profiles) == 0 {
		t.Errorf("export document is missing run/assessment/profiles sections")
	}
	// The summary must appear before the raw run in the serialized bytes.
	if strings.Index(string(b), "\"summary\"") > strings.Index(string(b), "\"run\"") {
		t.Errorf("summary should be serialized before the run")
	}
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafe(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "keeps hostname chars", in: "web-01.prod_local", want: "web-01.prod_local"},
		{name: "drops path separators", in: "../web/01", want: "..web01"},
		{name: "falls back", in: "///", want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safe(tt.in); got != tt.want {
				t.Fatalf("safe(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDecodeChecks(t *testing.T) {
	checks := map[string]any{
		"system": base64.StdEncoding.EncodeToString([]byte("uname -a")),
		"bad":    "%%%not-base64%%%",
		"number": 42,
	}

	got := decodeChecks(checks)
	if got["system"] != "uname -a" {
		t.Fatalf("decoded system = %q", got["system"])
	}
	if got["bad"] != "<decode error>" {
		t.Fatalf("bad decode = %q", got["bad"])
	}
	if got["number"] != "<decode error>" {
		t.Fatalf("number decode = %q", got["number"])
	}
}

func TestReceiveReportRequiresToken(t *testing.T) {
	a := testApp(t)
	req := httptest.NewRequest(http.MethodPost, "/report", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()

	a.receiveReport(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestReceiveReportStoresDecodedReport(t *testing.T) {
	a := testApp(t)
	payload := `{
		"hostname":"web/../01",
		"timestamp":"2026-07-04T00:00:00Z",
		"collected_as":"root",
		"checks":{
			"system":"` + base64.StdEncoding.EncodeToString([]byte("kernel info")) + `",
			"bad":"%%%not-base64%%%"
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/report", strings.NewReader(payload))
	req.Header.Set("X-Auth-Token", defaultSharedSecret)
	rr := httptest.NewRecorder()

	a.receiveReport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}

	data, err := os.ReadFile(filepath.Join(a.dataDir, "web..01.json"))
	if err != nil {
		t.Fatalf("read stored report: %v", err)
	}
	var stored map[string]any
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("unmarshal stored report: %v", err)
	}
	if _, ok := stored["checks"]; ok {
		t.Fatal("stored report still has encoded checks")
	}
	decoded := decodedMap(stored["_decoded"])
	if decoded["system"] != "kernel info" {
		t.Fatalf("decoded system = %q", decoded["system"])
	}
	if decoded["bad"] != "<decode error>" {
		t.Fatalf("decoded bad = %q", decoded["bad"])
	}
}

func TestFormatStamp(t *testing.T) {
	if got := formatStamp("20260717T205948.482136Z"); got != "2026-07-17 20:59:48 UTC" {
		t.Fatalf("formatStamp = %q", got)
	}
	if got := formatStamp("not-a-stamp"); got != "not-a-stamp" {
		t.Fatalf("formatStamp fallback = %q", got)
	}
}

func TestFormatReceived(t *testing.T) {
	if got := formatReceived("2026-07-17T20:59:48.482136Z"); got != "2026-07-17 20:59:48 UTC" {
		t.Fatalf("formatReceived = %q", got)
	}
	if got := formatReceived("?"); got != "?" {
		t.Fatalf("formatReceived fallback = %q", got)
	}
}

func TestCountReportLines(t *testing.T) {
	payload := map[string]any{
		"_decoded": map[string]any{"system": "line one\nline two"},
	}
	// formatDecodedReport renders "===== SYSTEM =====\nline one\nline two\n\n" -> 3 lines
	if got := countReportLines(payload); got != 3 {
		t.Fatalf("countReportLines = %d, want 3", got)
	}
	if got := countReportLines(map[string]any{}); got != 0 {
		t.Fatalf("countReportLines empty = %d, want 0", got)
	}
}

func writeReportFile(t *testing.T, a *app, host string, payload map[string]any) {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if err := os.WriteFile(a.reportPath(host), data, 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}
}

func writeHistoryFile(t *testing.T, a *app, host, stamp string, payload map[string]any) {
	t.Helper()
	path := a.historyReportPath(host, stamp)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir history: %v", err)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write history: %v", err)
	}
}

func TestReportPageHTMLAndRaw(t *testing.T) {
	a := testApp(t)
	writeReportFile(t, a, "web01", map[string]any{
		"hostname":  "web01",
		"_received": "2026-07-17T20:59:48.482136Z",
		"_decoded":  map[string]any{"system": "kernel info"},
	})

	req := httptest.NewRequest(http.MethodGet, "/report/web01", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	a.getReport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `<pre class="report-pre">`) {
		t.Fatal("html view missing report-pre block")
	}
	if !strings.Contains(body, "2026-07-17 20:59:48 UTC") {
		t.Fatal("html view missing readable date")
	}

	req = httptest.NewRequest(http.MethodGet, "/report/web01?raw=1", nil)
	req.Header.Set("Accept", "text/html")
	rr = httptest.NewRecorder()
	a.getReport(rr, req)
	if got := rr.Body.String(); !strings.HasPrefix(got, "===== SYSTEM =====") {
		t.Fatalf("raw view = %q", got)
	}
}

func TestHistoryEntryHTMLAndRaw(t *testing.T) {
	a := testApp(t)
	stamp := "20260717T205948.482136Z"
	writeHistoryFile(t, a, "web01", stamp, map[string]any{
		"hostname": "web01",
		"_decoded": map[string]any{"system": "old kernel info"},
	})

	req := httptest.NewRequest(http.MethodGet, "/history/web01/"+stamp, nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	a.getHistory(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `<pre class="report-pre">`) {
		t.Fatal("entry html missing report-pre block")
	}
	if !strings.Contains(body, "2026-07-17 20:59:48 UTC") {
		t.Fatal("entry html missing formatted stamp")
	}

	req = httptest.NewRequest(http.MethodGet, "/history/web01/"+stamp+"?raw=1", nil)
	req.Header.Set("Accept", "text/html")
	rr = httptest.NewRecorder()
	a.getHistory(rr, req)
	if got := rr.Body.String(); !strings.HasPrefix(got, "===== SYSTEM =====") {
		t.Fatalf("entry raw = %q", got)
	}
}

func TestReportPlainTextWithoutAcceptHeader(t *testing.T) {
	a := testApp(t)
	writeReportFile(t, a, "web01", map[string]any{
		"hostname": "web01",
		"_decoded": map[string]any{"system": "kernel info"},
	})
	req := httptest.NewRequest(http.MethodGet, "/report/web01", nil)
	rr := httptest.NewRecorder()
	a.getReport(rr, req)
	if got := rr.Body.String(); !strings.HasPrefix(got, "===== SYSTEM =====") {
		t.Fatalf("plain view = %q", got)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type = %q", ct)
	}
}

func TestCorruptReportLegibleMessage(t *testing.T) {
	a := testApp(t)
	if err := os.WriteFile(a.reportPath("web01"), []byte("{not json"), 0644); err != nil {
		t.Fatalf("write corrupt report: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/report/web01", nil)
	rr := httptest.NewRecorder()
	a.getReport(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "not valid JSON") {
		t.Fatalf("plain corrupt = %d %q", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/report/web01", nil)
	req.Header.Set("Accept", "text/html")
	rr = httptest.NewRecorder()
	a.getReport(rr, req)
	if !strings.Contains(rr.Body.String(), "Report unreadable") {
		t.Fatalf("html corrupt missing message page: %q", rr.Body.String())
	}
}

func TestCorruptHistoryEntryLegibleMessage(t *testing.T) {
	a := testApp(t)
	stamp := "20260717T205948.482136Z"
	path := a.historyReportPath("web01", stamp)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir history: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0644); err != nil {
		t.Fatalf("write corrupt entry: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/history/web01/"+stamp, nil)
	rr := httptest.NewRecorder()
	a.getHistory(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "not valid JSON") {
		t.Fatalf("plain corrupt = %d %q", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/history/web01/"+stamp, nil)
	req.Header.Set("Accept", "text/html")
	rr = httptest.NewRecorder()
	a.getHistory(rr, req)
	if !strings.Contains(rr.Body.String(), "Snapshot unreadable") {
		t.Fatalf("html corrupt missing message page: %q", rr.Body.String())
	}
}

func TestHistorySummaryPage(t *testing.T) {
	a := testApp(t)
	writeReportFile(t, a, "web01", map[string]any{
		"hostname":  "web01",
		"_received": "2026-07-17T21:10:00.000000Z",
		"_decoded":  map[string]any{"system": "one\ntwo"},
	})
	writeHistoryFile(t, a, "web01", "20260717T205948.482136Z", map[string]any{
		"hostname": "web01",
		"_decoded": map[string]any{"system": "one"},
	})

	req := httptest.NewRequest(http.MethodGet, "/history/web01", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	a.getHistory(rr, req)
	body := rr.Body.String()

	if !strings.Contains(body, "Current") {
		t.Fatal("summary missing Current badge")
	}
	if !strings.Contains(body, "2026-07-17 20:59:48 UTC") {
		t.Fatal("summary missing snapshot date")
	}
	if !strings.Contains(body, "/history/web01/20260717T205948.482136Z") {
		t.Fatal("summary missing snapshot link")
	}
	// current report: "===== SYSTEM =====\none\ntwo" -> 3 lines
	if !strings.Contains(body, "<td>3</td>") {
		t.Fatal("summary missing current line count")
	}
	// snapshot: "===== SYSTEM =====\none" -> 2 lines
	if !strings.Contains(body, "<td>2</td>") {
		t.Fatal("summary missing snapshot line count")
	}
}

func TestHistoryPlainTextListsStamps(t *testing.T) {
	a := testApp(t)
	writeHistoryFile(t, a, "web01", "20260717T205948.482136Z", map[string]any{
		"_decoded": map[string]any{},
	})
	req := httptest.NewRequest(http.MethodGet, "/history/web01", nil)
	rr := httptest.NewRecorder()
	a.getHistory(rr, req)
	if got := strings.TrimSpace(rr.Body.String()); got != "20260717T205948.482136Z" {
		t.Fatalf("plain list = %q", got)
	}
}

func TestEmptyHistoryPage(t *testing.T) {
	a := testApp(t)
	req := httptest.NewRequest(http.MethodGet, "/history/ghost", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	a.getHistory(rr, req)
	body := rr.Body.String()
	if strings.Contains(body, "Analysis pending") {
		t.Fatal("empty history still renders the analysis-pending page")
	}
	if !strings.Contains(body, "No history for ghost") {
		t.Fatal("empty history missing its own message")
	}
}

func testApp(t *testing.T) *app {
	t.Helper()
	a, err := newApp(t.TempDir(), defaultSharedSecret)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	a.analyzer = func([]byte) (string, error) {
		return "1. HARDENING SCORE: 80/100 - test", nil
	}
	return a
}

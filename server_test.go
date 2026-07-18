package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSafe(t *testing.T) {
	if got := safe("web-01.prod_local"); got != "web-01.prod_local" {
		t.Fatalf("safe hostname = %q, want unchanged", got)
	}

	inputs := []string{
		"web-01.prod_local",
		"../web/01",
		"///",
		".",
		"..",
		strings.Repeat("a", 100),
	}
	for _, input := range inputs {
		t.Run("idempotent_"+input, func(t *testing.T) {
			got := safe(input)
			if second := safe(got); second != got {
				t.Fatalf("safe is not idempotent: safe(%q) = %q, safe(%q) = %q", input, got, got, second)
			}
			if got == "." || got == ".." {
				t.Fatalf("safe(%q) returned reserved path %q", input, got)
			}
			if strings.Contains(got, "/") || strings.Contains(got, `\`) {
				t.Fatalf("safe(%q) retained a path separator in %q", input, got)
			}
		})
	}

	for _, pair := range [][2]string{
		{"web/01", "web01"},
		{"///", "???"},
	} {
		if left, right := safe(pair[0]), safe(pair[1]); left == right {
			t.Fatalf("safe aliases distinct names %q and %q as %q", pair[0], pair[1], left)
		}
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

func TestReadPayloadRejectsInvalidStoredShape(t *testing.T) {
	for _, content := range []string{"null", `{}`, `{"_decoded":null}`} {
		path := filepath.Join(t.TempDir(), "report.json")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("write report: %v", err)
		}
		if _, err := readPayload(path); !errors.Is(err, errInvalidReport) {
			t.Fatalf("readPayload(%s) error = %v, want errInvalidReport", content, err)
		}
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

func TestReceiveReportRejectsInvalidPayloads(t *testing.T) {
	valid := `{"hostname":"web01","checks":{"system":"a2VybmVs"}}`
	tests := []struct {
		name string
		body string
	}{
		{name: "null document", body: `null`},
		{name: "trailing JSON", body: valid + ` {}`},
		{name: "invalid hostname", body: `{"hostname":"   ","checks":{"system":"a2VybmVs"}}`},
		{name: "empty checks", body: `{"hostname":"web01","checks":{}}`},
		{name: "invalid timestamp", body: `{"hostname":"web01","timestamp":"yesterday","checks":{"system":"a2VybmVs"}}`},
		{name: "oversized collected as", body: `{"hostname":"web01","collected_as":"` + strings.Repeat("a", maxCollectedAsBytes+1) + `","checks":{"system":"a2VybmVs"}}`},
		{name: "oversized check name", body: `{"hostname":"web01","checks":{"` + strings.Repeat("a", maxCheckNameBytes+1) + `":"a2VybmVs"}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testApp(t)
			req := httptest.NewRequest(http.MethodPost, "/report", strings.NewReader(tt.body))
			req.Header.Set("X-Auth-Token", defaultSharedSecret)
			rr := httptest.NewRecorder()

			a.receiveReport(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
			}
		})
	}
}

func TestReceiveReportRejectsOversizedBodyWith413(t *testing.T) {
	a := testApp(t)
	req := httptest.NewRequest(http.MethodPost, "/report", strings.NewReader(`{"hostname":"web01","checks":{"system":"a2VybmVs"}}`))
	req.ContentLength = maxReportBytes + 1
	req.Header.Set("X-Auth-Token", defaultSharedSecret)
	rr := httptest.NewRecorder()

	a.receiveReport(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 body=%s", rr.Code, rr.Body.String())
	}
}

func TestReceiveReportStoresDecodedReport(t *testing.T) {
	a := testApp(t)
	receivedAt := time.Date(2026, time.July, 17, 20, 59, 48, 482136000, time.UTC)
	a.now = func() time.Time { return receivedAt }
	host := "web/../01"
	payload := `{
		"agent_version":"1.4.0",
		"hostname":"` + host + `",
		"timestamp":"2026-07-04T00:00:00Z",
		"collected_as":"root",
		"is_root":true,
		"untrusted_extension":{"large":"value"},
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

	reportPath := a.reportPath(host)
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read stored report: %v", err)
	}
	historyPath := a.historyReportPath(host, receivedAt.Format(historyStampLayout))
	historyData, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatalf("read stored history snapshot: %v", err)
	}
	if string(historyData) != string(data) {
		t.Fatal("history snapshot differs from current report")
	}
	for _, path := range []string{reportPath, historyPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("permissions for %s = %04o, want 0600", path, got)
		}
	}

	var stored map[string]any
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("unmarshal stored report: %v", err)
	}
	if _, ok := stored["checks"]; ok {
		t.Fatal("stored report still has encoded checks")
	}
	if _, ok := stored["untrusted_extension"]; ok {
		t.Fatal("stored report retained an unknown top-level field")
	}
	if got := stringValue(stored["agent_version"], ""); got != "1.4.0" {
		t.Fatalf("stored agent version = %q", got)
	}
	if got, ok := stored["is_root"].(bool); !ok || !got {
		t.Fatalf("stored is_root = %#v", stored["is_root"])
	}
	decoded := decodedMap(stored["_decoded"])
	if decoded["system"] != "kernel info" {
		t.Fatalf("decoded system = %q", decoded["system"])
	}
	if decoded["bad"] != "<decode error>" {
		t.Fatalf("decoded bad = %q", decoded["bad"])
	}
	if got := stringValue(stored["_received"], ""); got != receivedAt.Format(receivedLayout) {
		t.Fatalf("received timestamp = %q, want %q", got, receivedAt.Format(receivedLayout))
	}
}

func TestConcurrentReportsKeepUniqueHistoryAndLatestSnapshot(t *testing.T) {
	a := testApp(t)
	fixed := time.Date(2026, time.July, 17, 21, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return fixed }
	const submissions = 20

	var wg sync.WaitGroup
	errors := make(chan string, submissions)
	for index := 0; index < submissions; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"hostname":"web01","checks":{"system":"%s"}}`, base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("report-%d", index))))
			req := httptest.NewRequest(http.MethodPost, "/report", strings.NewReader(body))
			req.Header.Set("X-Auth-Token", defaultSharedSecret)
			rr := httptest.NewRecorder()
			a.receiveReport(rr, req)
			if rr.Code != http.StatusOK {
				errors <- fmt.Sprintf("submission %d: status=%d body=%s", index, rr.Code, rr.Body.String())
			}
		}(index)
	}
	wg.Wait()
	close(errors)
	for message := range errors {
		t.Error(message)
	}

	stamps, err := a.listHistoryStamps("web01")
	if err != nil {
		t.Fatalf("list history: %v", err)
	}
	if len(stamps) != submissions {
		t.Fatalf("history entries = %d, want %d", len(stamps), submissions)
	}
	latest, err := os.ReadFile(a.reportPath("web01"))
	if err != nil {
		t.Fatalf("read latest report: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(latest, &payload); err != nil {
		t.Fatalf("latest report is invalid JSON: %v", err)
	}
	received, ok := parseReceived(stringValue(payload["_received"], ""))
	if !ok {
		t.Fatalf("latest report has invalid received timestamp: %v", payload["_received"])
	}
	latestSnapshot, err := os.ReadFile(a.historyReportPath("web01", received.Format(historyStampLayout)))
	if err != nil {
		t.Fatalf("read matching latest snapshot: %v", err)
	}
	if string(latestSnapshot) != string(latest) {
		t.Fatal("latest report does not match its immutable history snapshot")
	}
}

func TestRoutesExposeHealthAndSecurityHeaders(t *testing.T) {
	a := testApp(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	a.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"status":"ok"`) {
		t.Fatalf("health response = %d %q", rr.Code, rr.Body.String())
	}
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	} {
		if got := rr.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/report/web01/extra", nil)
	req.Header.Set("X-Auth-Token", defaultSharedSecret)
	rr = httptest.NewRecorder()
	a.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("nested report path status = %d, want 404", rr.Code)
	}
}

func TestRoutesRequireAuthenticationExceptHealth(t *testing.T) {
	a := testApp(t)
	handler := a.routes()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized || rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("unauthenticated dashboard = %d, want Basic challenge", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("operator", defaultSharedSecret)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Fleet posture") {
		t.Fatalf("authenticated dashboard = %d %q", rr.Code, rr.Body.String())
	}
}

func TestSeparateUITokenAndBasicAuthCSRFProtection(t *testing.T) {
	a := testApp(t)
	a.uiToken = "operator-secret"
	handler := a.routes()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Auth-Token", defaultSharedSecret)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("collector token opened dashboard: status=%d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/report", strings.NewReader(`{"hostname":"web01","checks":{"system":"a2VybmVs"}}`))
	req.Header.Set("X-Auth-Token", defaultSharedSecret)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("collector token could not ingest report: status=%d body=%s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/analyze/ghost", nil)
	req.SetBasicAuth("operator", "operator-secret")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("Basic cross-origin mutation status=%d, want 403", rr.Code)
	}

	form := url.Values{"csrf_token": {a.csrfToken()}}
	req = httptest.NewRequest(http.MethodPost, "/analyze/ghost", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("operator", "operator-secret")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("Basic mutation with UI CSRF token status=%d, want handler 404", rr.Code)
	}
	if markup := a.analysisForm("ghost", "Refresh analysis", ""); !strings.Contains(markup, `name='csrf_token' value='`+a.csrfToken()+`'`) {
		t.Fatalf("analysis form does not carry CSRF token: %s", markup)
	}

	req = httptest.NewRequest(http.MethodPost, "/analyze/ghost", nil)
	req.SetBasicAuth("operator", "operator-secret")
	req.Header.Set("Origin", "http://example.com")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("same-origin Basic mutation status=%d, want handler 404", rr.Code)
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

func TestReportChangeStats(t *testing.T) {
	before := map[string]any{
		"_decoded": map[string]any{
			"system": "shared\nold kernel",
			"users":  "legacy account",
			"ssh":    "PermitRootLogin yes",
		},
	}
	after := map[string]any{
		"_decoded": map[string]any{
			"system":  "shared\nnew kernel",
			"network": "tcp 22",
			"ssh":     "PermitRootLogin yes",
		},
	}

	changed, added, removed := reportChangeStats(before, after)
	wantChanged := []string{"system", "users", "network"}
	if strings.Join(changed, ",") != strings.Join(wantChanged, ",") {
		t.Fatalf("changed sections = %v, want %v", changed, wantChanged)
	}
	if added != 2 || removed != 2 {
		t.Fatalf("line delta = +%d/-%d, want +2/-2", added, removed)
	}

	changed, added, removed = reportChangeStats(after, after)
	if len(changed) != 0 || added != 0 || removed != 0 {
		t.Fatalf("unchanged report delta = %v +%d/-%d, want no changes", changed, added, removed)
	}
}

func TestResponseNegotiation(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/report/web01", nil)
	req.Header.Set("Accept", "application/json, text/html;q=0")
	if wantsHTML(req) {
		t.Fatal("wantsHTML accepted text/html;q=0")
	}

	req.Header.Set("Accept", "TEXT/HTML;Q=0.8")
	if !wantsHTML(req) {
		t.Fatal("wantsHTML rejected an acceptable HTML media type")
	}

	req = httptest.NewRequest(http.MethodGet, "/report/web01?raw=0", nil)
	if wantsRaw(req) {
		t.Fatal("wantsRaw treated raw=0 as enabled")
	}
	req = httptest.NewRequest(http.MethodGet, "/report/web01?raw=1", nil)
	if !wantsRaw(req) {
		t.Fatal("wantsRaw rejected raw=1")
	}
}

func TestAnalysisState(t *testing.T) {
	base := time.Date(2026, time.July, 17, 21, 0, 0, 0, time.UTC)
	tests := []struct {
		name          string
		content       string
		analysisMod   time.Time
		reportMod     time.Time
		want          string
		writeAnalysis bool
	}{
		{name: "pending", want: "pending"},
		{name: "ready", content: "1. HARDENING SCORE: 80/100", analysisMod: base.Add(time.Minute), reportMod: base, want: "ready", writeAnalysis: true},
		{name: "stale", content: "1. HARDENING SCORE: 80/100", analysisMod: base, reportMod: base.Add(time.Minute), want: "stale", writeAnalysis: true},
		{name: "failed", content: "[analyzer] Python analyzer failed: timeout", analysisMod: base.Add(time.Minute), reportMod: base, want: "failed", writeAnalysis: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testApp(t)
			if tt.writeAnalysis {
				path := a.analysisPath("web01")
				if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
					t.Fatalf("write analysis: %v", err)
				}
				if err := os.Chtimes(path, tt.analysisMod, tt.analysisMod); err != nil {
					t.Fatalf("set analysis time: %v", err)
				}
			}
			if got := a.analysisState("web01", tt.reportMod); got != tt.want {
				t.Fatalf("analysisState = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMissingAnalysisReturns404InPlainAndHTML(t *testing.T) {
	a := testApp(t)
	for _, accept := range []string{"", "text/html"} {
		req := httptest.NewRequest(http.MethodGet, "/analysis/web01", nil)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		rr := httptest.NewRecorder()
		a.getAnalysis(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("accept %q: status=%d, want 404 body=%s", accept, rr.Code, rr.Body.String())
		}
	}
}

func TestStaleAnalysisRefreshFormCarriesCSRFToken(t *testing.T) {
	a := testApp(t)
	writeReportFile(t, a, "web01", map[string]any{
		"hostname":  "web01",
		"_received": "2026-07-17T20:59:48Z",
		"_decoded":  map[string]any{"system": "kernel"},
	})
	analysisPath := a.analysisPath("web01")
	if err := os.WriteFile(analysisPath, []byte("1. HARDENING SCORE: 80/100"), 0600); err != nil {
		t.Fatalf("write analysis: %v", err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(analysisPath, old, old); err != nil {
		t.Fatalf("age analysis: %v", err)
	}

	body := renderAnalysisPage(a, "web01", "1. HARDENING SCORE: 80/100")
	if !strings.Contains(body, "Refresh analysis") || !strings.Contains(body, `name='csrf_token' value='`+a.csrfToken()+`'`) {
		t.Fatalf("stale analysis page missing protected refresh form")
	}
	if strings.Contains(body, "%!") {
		t.Fatalf("stale analysis page contains a formatting artifact")
	}
}

func TestDashboardOnlyRunsPendingAnalysis(t *testing.T) {
	tests := []struct {
		name            string
		analysisContent string
		stale           bool
		wantRun         bool
	}{
		{name: "pending", wantRun: true},
		{name: "current", analysisContent: "1. HARDENING SCORE: 80/100"},
		{name: "stale", analysisContent: "1. HARDENING SCORE: 70/100", stale: true},
		{name: "failed", analysisContent: "[analyzer] provider unavailable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testApp(t)
			writeReportFile(t, a, "web01", map[string]any{
				"hostname":     "web01",
				"timestamp":    "2026-07-18T12:00:00Z",
				"collected_as": "root",
				"_received":    "2026-07-18T12:00:00Z",
				"_decoded":     map[string]any{"system": "kernel"},
			})
			if tt.analysisContent != "" {
				path := a.analysisPath("web01")
				if err := os.WriteFile(path, []byte(tt.analysisContent), 0600); err != nil {
					t.Fatalf("write analysis: %v", err)
				}
				if tt.stale {
					old := time.Now().Add(-time.Hour)
					if err := os.Chtimes(path, old, old); err != nil {
						t.Fatalf("age analysis: %v", err)
					}
				}
			}

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rr := httptest.NewRecorder()
			a.dashboard(rr, req)
			body := rr.Body.String()

			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 body=%s", rr.Code, body)
			}
			if strings.Contains(body, "Refresh analysis") || strings.Contains(body, "Retry analysis") {
				t.Fatalf("dashboard offers rerun action for %s analysis", tt.name)
			}
			if tt.wantRun {
				if !strings.Contains(body, "Run analysis") || !strings.Contains(body, "action='/analyze/web01'") {
					t.Fatal("pending analysis is missing its run action")
				}
				return
			}
			if !strings.Contains(body, "Open analysis") || strings.Contains(body, "action='/analyze/web01'") {
				t.Fatalf("dashboard does not open the existing %s analysis", tt.name)
			}
		})
	}
}

func TestAnalyzeDiscardsResultWhenReportChanges(t *testing.T) {
	a := testApp(t)
	writeReportFile(t, a, "web01", map[string]any{
		"hostname": "web01",
		"_decoded": map[string]any{"system": "old kernel"},
	})
	a.analyzer = func([]byte) (string, error) {
		writeReportFile(t, a, "web01", map[string]any{
			"hostname": "web01",
			"_decoded": map[string]any{"system": "new kernel"},
		})
		return "1. HARDENING SCORE: 80/100", nil
	}

	req := httptest.NewRequest(http.MethodPost, "/analyze/web01", nil)
	rr := httptest.NewRecorder()
	a.analyze(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 body=%s", rr.Code, rr.Body.String())
	}
	if fileExists(a.analysisPath("web01")) {
		t.Fatal("stale analysis result was stored after the report changed")
	}
}

func TestAnalyzeFailureReturnsGatewayErrorAndRecordsFailedState(t *testing.T) {
	a := testApp(t)
	writeReportFile(t, a, "web01", map[string]any{
		"hostname": "web01",
		"_decoded": map[string]any{"system": "kernel"},
	})
	a.analyzer = func([]byte) (string, error) {
		return "", errors.New("provider unavailable")
	}

	req := httptest.NewRequest(http.MethodPost, "/analyze/web01", nil)
	rr := httptest.NewRecorder()
	a.analyze(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 body=%s", rr.Code, rr.Body.String())
	}
	if got := a.analysisState("web01", time.Time{}); got != "failed" {
		t.Fatalf("analysis state = %q, want failed", got)
	}
}

func TestAnalyzeRejectsOversizedStoredReport(t *testing.T) {
	a := testApp(t)
	path := a.reportPath("web01")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if err := os.Truncate(path, maxStoredReportSize+1); err != nil {
		t.Fatalf("expand report: %v", err)
	}
	called := false
	a.analyzer = func([]byte) (string, error) {
		called = true
		return "", nil
	}

	req := httptest.NewRequest(http.MethodPost, "/analyze/web01", nil)
	rr := httptest.NewRecorder()
	a.analyze(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 body=%s", rr.Code, rr.Body.String())
	}
	if called {
		t.Fatal("analyzer ran for an oversized stored report")
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
	payload := map[string]any{
		"hostname":  "web01",
		"_received": "2026-07-17T20:59:48.482136Z",
		"_decoded": map[string]any{
			"system": "kernel info",
			"ssh":    "PermitRootLogin no",
		},
	}
	writeReportFile(t, a, "web01", payload)
	wantRaw := formatDecodedReport(payload)

	req := httptest.NewRequest(http.MethodGet, "/report/web01", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	a.getReport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `class="report-section"`) || !strings.Contains(body, `class="section-output"`) {
		t.Fatal("html view missing structured report sections")
	}
	if strings.Contains(body, `class="report-pre"`) {
		t.Fatal("html view still renders the legacy report-pre block")
	}
	if !strings.Contains(body, `id="report-search"`) {
		t.Fatal("html view missing report search")
	}
	for _, title := range []string{"System &amp; kernel", "SSH"} {
		if !strings.Contains(body, title) {
			t.Fatalf("html view missing section title %q", title)
		}
	}
	if !strings.Contains(body, "2026-07-17 20:59:48 UTC") {
		t.Fatal("html view missing readable date")
	}

	req = httptest.NewRequest(http.MethodGet, "/report/web01?raw=1", nil)
	req.Header.Set("Accept", "text/html")
	rr = httptest.NewRecorder()
	a.getReport(rr, req)
	if got := rr.Body.String(); got != wantRaw {
		t.Fatalf("raw view changed\ngot:  %q\nwant: %q", got, wantRaw)
	}
}

func TestHistoryEntryHTMLAndRaw(t *testing.T) {
	a := testApp(t)
	stamp := "20260717T205948.482136Z"
	payload := map[string]any{
		"hostname": "web01",
		"_decoded": map[string]any{
			"system":  "old kernel info",
			"network": "tcp 22",
		},
	}
	writeHistoryFile(t, a, "web01", stamp, payload)
	wantRaw := formatDecodedReport(payload)

	req := httptest.NewRequest(http.MethodGet, "/history/web01/"+stamp, nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	a.getHistory(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `class="report-section"`) || !strings.Contains(body, `class="section-output"`) {
		t.Fatal("entry html missing structured report sections")
	}
	if strings.Contains(body, `class="report-pre"`) {
		t.Fatal("entry html still renders the legacy report-pre block")
	}
	if !strings.Contains(body, `id="report-search"`) {
		t.Fatal("entry html missing report search")
	}
	for _, title := range []string{"System &amp; kernel", "Network exposure"} {
		if !strings.Contains(body, title) {
			t.Fatalf("entry html missing section title %q", title)
		}
	}
	if !strings.Contains(body, "2026-07-17 20:59:48 UTC") {
		t.Fatal("entry html missing formatted stamp")
	}

	req = httptest.NewRequest(http.MethodGet, "/history/web01/"+stamp+"?raw=1", nil)
	req.Header.Set("Accept", "text/html")
	rr = httptest.NewRecorder()
	a.getHistory(rr, req)
	if got := rr.Body.String(); got != wantRaw {
		t.Fatalf("entry raw changed\ngot:  %q\nwant: %q", got, wantRaw)
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
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "cannot be decoded") {
		t.Fatalf("plain corrupt = %d %q", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/report/web01", nil)
	req.Header.Set("Accept", "text/html")
	rr = httptest.NewRecorder()
	a.getReport(rr, req)
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "Report unreadable") {
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
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "cannot be decoded") {
		t.Fatalf("plain corrupt = %d %q", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/history/web01/"+stamp, nil)
	req.Header.Set("Accept", "text/html")
	rr = httptest.NewRecorder()
	a.getHistory(rr, req)
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "Snapshot unreadable") {
		t.Fatalf("html corrupt missing message page: %q", rr.Body.String())
	}
}

func TestHistorySummaryPage(t *testing.T) {
	a := testApp(t)
	a.now = func() time.Time {
		return time.Date(2026, time.July, 17, 21, 15, 0, 0, time.UTC)
	}
	oldStamp := "20260717T205948.482136Z"
	currentStamp := "20260717T211000.000000Z"
	oldPayload := map[string]any{
		"hostname":     "web01",
		"collected_as": "root",
		"_decoded": map[string]any{
			"system": "shared\nold kernel",
			"ssh":    "PermitRootLogin yes",
		},
	}
	currentPayload := map[string]any{
		"hostname":     "web01",
		"_received":    "2026-07-17T21:10:00.000000Z",
		"collected_as": "root",
		"_decoded": map[string]any{
			"system":  "shared\nnew kernel",
			"network": "tcp 22",
			"ssh":     "PermitRootLogin no",
		},
	}
	writeReportFile(t, a, "web01", currentPayload)
	writeHistoryFile(t, a, "web01", oldStamp, oldPayload)
	writeHistoryFile(t, a, "web01", currentStamp, currentPayload)

	req := httptest.NewRequest(http.MethodGet, "/history/web01", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	a.getHistory(rr, req)
	body := rr.Body.String()

	if !strings.Contains(body, `<ol class="history-timeline">`) {
		t.Fatal("history page missing timeline")
	}
	if got := strings.Count(body, `class="history-card `); got != 2 {
		t.Fatalf("timeline has %d cards, want 2 after current/snapshot deduplication", got)
	}
	if !strings.Contains(body, `<span class="badge ok">Current</span>`) {
		t.Fatal("timeline missing Current badge")
	}
	if strings.Contains(body, "/history/web01/"+currentStamp) {
		t.Fatal("timeline kept a duplicate link for the current snapshot")
	}
	if !strings.Contains(body, "2026-07-17 20:59:48 UTC") {
		t.Fatal("timeline missing older snapshot date")
	}
	if !strings.Contains(body, "/history/web01/"+oldStamp) {
		t.Fatal("timeline missing older snapshot link")
	}
	for _, metric := range []string{
		"3/11 sections",
		"9 lines",
		"2/11 sections",
		"6 lines",
		"Visible captures</span><strong>2</strong>",
		"Archived on page</span><strong>1</strong>",
	} {
		if !strings.Contains(body, metric) {
			t.Fatalf("timeline missing metric %q", metric)
		}
	}
	for _, change := range []string{
		"3 sections changed",
		"System &amp; kernel, Network exposure, SSH",
		"<span class='delta plus'>+3</span>",
		"<span class='delta minus'>-2 lines</span>",
	} {
		if !strings.Contains(body, change) {
			t.Fatalf("timeline missing change summary %q", change)
		}
	}
}

func TestHistoryPagination(t *testing.T) {
	a := testApp(t)
	base := time.Date(2026, time.July, 17, 20, 0, 0, 0, time.UTC)
	for index := 0; index < historyPageSize+1; index++ {
		stamp := base.Add(time.Duration(index) * time.Second).Format(historyStampLayout)
		writeHistoryFile(t, a, "web01", stamp, map[string]any{
			"hostname": "web01",
			"_decoded": map[string]any{"system": "kernel info"},
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/history/web01?page=1", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	a.getHistory(rr, req)
	firstPage := rr.Body.String()
	if !strings.Contains(firstPage, "Page 1 of 2") || !strings.Contains(firstPage, "/history/web01?page=2") {
		t.Fatalf("first page missing pagination controls: %q", firstPage)
	}
	if got := strings.Count(firstPage, `class="history-card `); got != historyPageSize {
		t.Fatalf("first page has %d captures, want %d", got, historyPageSize)
	}

	req = httptest.NewRequest(http.MethodGet, "/history/web01?page=2", nil)
	req.Header.Set("Accept", "text/html")
	rr = httptest.NewRecorder()
	a.getHistory(rr, req)
	secondPage := rr.Body.String()
	if !strings.Contains(secondPage, "Page 2 of 2") || !strings.Contains(secondPage, "/history/web01?page=1") {
		t.Fatalf("second page missing pagination controls: %q", secondPage)
	}
	if got := strings.Count(secondPage, `class="history-card `); got != 1 {
		t.Fatalf("second page has %d captures, want 1", got)
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
	a.protectUI = true
	a.uiToken = defaultSharedSecret
	return a
}

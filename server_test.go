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

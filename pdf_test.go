package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var pdfTestTime = time.Date(2026, time.July, 17, 22, 47, 0, 0, time.UTC)

func representativePDFData() analysisPDFData {
	return analysisPDFData{
		title:       "CCDC Hardening Analysis: web-01.prod_local",
		host:        "web-01.prod_local",
		body:        representativePDFBody(),
		generatedAt: pdfTestTime,
		analyzedAt:  pdfTestTime.Add(-7 * time.Minute),
		status:      "Current",
		provider:    "openai",
		model:       "gpt-4o-test",
		collectedAs: "root",
		collectedAt: "2026-07-17T22:30:00Z",
	}
}

func representativePDFBody() string {
	return strings.Join([]string{
		"1. HARDENING SCORE: 42/100 - Immediate remediation is required.",
		"",
		"2. PROBABLE COMPROMISE / RED-TEAM ARTIFACTS",
		"- Evidence: /opt/red-team/agent is listening on an unexpected port.",
		"- Remediation: isolate the host and preserve volatile evidence.",
		"",
		"3. HARDENING GAPS",
		"### Authentication",
		"configuración crítica con contraseña inválida y acción rápida.",
		"",
		"probe)Tj(foo\\bar",
		"",
		"```bash",
		"sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config",
		"systemctl restart sshd",
		"```",
		"",
		"4. SUSPICIOUS PROCESSES / SERVICES / TASKS",
		"| Item | Evidence | Action |",
		"| --- | --- | --- |",
		"| bluehood.daemon | python -m bluehood.daemon | stop and investigate |",
		"| cron-backdoor | /etc/cron.d/update | remove after collection |",
		"",
		"5. DO-NOW CHECKLIST",
		"1. Isolate the affected host.",
		"2. Disable password authentication for SSH.",
		"3. Apply the firewall default-deny policy.",
	}, "\n")
}

func TestGenerateAnalysisPDFDocumentContract(t *testing.T) {
	pdf := generateAnalysisPDF(representativePDFData())
	raw := string(pdf)

	if !bytes.HasPrefix(pdf, []byte("%PDF-1.4\n")) {
		t.Fatalf("PDF signature = %q", firstPDFBytes(pdf, 12))
	}
	if !bytes.HasSuffix(pdf, []byte("%%EOF\n")) {
		t.Fatal("PDF does not end with the EOF marker")
	}
	for _, fragment := range []string{
		"/MediaBox [0 0 612 792]",
		"/BaseFont /Helvetica /Encoding /WinAnsiEncoding",
		"/BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding",
		"/BaseFont /Courier /Encoding /WinAnsiEncoding",
		"/Title (CCDC Hardening Analysis: web-01.prod_local)",
		"/Creator (CCDC Hardening Tracker)",
		"/CreationDate (D:20260717224700Z)",
	} {
		if !strings.Contains(raw, fragment) {
			t.Errorf("PDF is missing structural fragment %q", fragment)
		}
	}
	assertPDFStartXref(t, pdf)
}

func TestGenerateAnalysisPDFIsDeterministicWithFixedTimes(t *testing.T) {
	data := representativePDFData()
	first := generateAnalysisPDF(data)
	second := generateAnalysisPDF(data)
	if !bytes.Equal(first, second) {
		t.Fatal("same PDF data and fixed timestamps produced different bytes")
	}
}

func TestGenerateAnalysisPDFUsesVisualPaletteAndStructuredContent(t *testing.T) {
	raw := string(generateAnalysisPDF(representativePDFData()))

	for name, fragment := range map[string]string{
		"paper":   "0.969 0.976 0.984 rg",
		"navy":    "0.031 0.043 0.063 rg",
		"accent":  "0.345 0.784 0.961 rg",
		"purple":  "0.655 0.545 0.980 rg",
		"success": "0.384 0.831 0.612 rg",
		"warning": "0.961 0.741 0.337 rg",
		"danger":  "1.000 0.455 0.498 rg",
	} {
		if !strings.Contains(raw, fragment) {
			t.Errorf("PDF is missing %s palette color %q", name, fragment)
		}
	}

	for _, text := range []string{
		"SECURITY POSTURE",
		"HARDENING SCORE",
		"EXECUTIVE SUMMARY",
		"(42) Tj",
		"Probable Compromise",
		"Hardening Gaps",
		"Suspicious Tasks",
		"Do-Now Checklist",
		"COLLECTED AS",
		"ANALYZED",
	} {
		if !strings.Contains(raw, text) {
			t.Errorf("PDF is missing visual/content marker %q", text)
		}
	}
	if !strings.Contains(raw, "/F3 8.10 Tf") {
		t.Error("PDF does not render the command block with the monospace font")
	}
	if !strings.Contains(raw, "bluehood.daemon") || !strings.Contains(raw, "cron-backdoor") {
		t.Error("PDF did not retain representative table rows")
	}
}

func TestGenerateAnalysisPDFMultipageFooters(t *testing.T) {
	data := representativePDFData()
	var extra strings.Builder
	for index := 1; index <= 120; index++ {
		fmt.Fprintf(&extra, "\n%d. Validate repeated control %03d and retain its evidence.", index+3, index)
	}
	data.body += extra.String()

	pdf := generateAnalysisPDF(data)
	raw := string(pdf)
	pageCount := declaredPDFPageCount(t, raw)
	if pageCount < 3 {
		t.Fatalf("page count = %d, want at least 3", pageCount)
	}
	if got := strings.Count(raw, "/Type /Page "); got != pageCount {
		t.Errorf("page objects = %d, declared pages = %d", got, pageCount)
	}
	for page := 1; page <= pageCount; page++ {
		footer := fmt.Sprintf("(PAGE %d OF %d) Tj", page, pageCount)
		if count := strings.Count(raw, footer); count != 1 {
			t.Errorf("footer %q appears %d times", footer, count)
		}
	}
	if count := strings.Count(raw, "CCDC HARDENING TRACKER"); count != pageCount {
		t.Errorf("page header count = %d, want %d", count, pageCount)
	}
}

func TestGenerateAnalysisPDFEscapesHostileAndLatin1Text(t *testing.T) {
	data := representativePDFData()
	data.host = "blue)Tj(foo\\ops"
	data.title = "Analysis (urgent) for blue\\ops"
	pdf := generateAnalysisPDF(data)
	raw := string(pdf)

	for _, escaped := range []string{
		"blue\\)Tj\\(foo\\\\ops",
		"Analysis \\(urgent\\) for blue\\\\ops",
		"probe\\)Tj\\(foo\\\\bar",
		"configuraci\\363n cr\\355tica con contrase\\361a inv\\341lida y acci\\363n r\\341pida.",
	} {
		if !strings.Contains(raw, escaped) {
			t.Errorf("PDF is missing safely encoded text %q", escaped)
		}
	}
	for _, unsafe := range []string{
		"blue)Tj(foo\\ops",
		"probe)Tj(foo\\bar",
		"configuración",
	} {
		if strings.Contains(raw, unsafe) {
			t.Errorf("PDF retained unsafe/unencoded text %q", unsafe)
		}
	}
}

func TestPDFDownloadEndpoint(t *testing.T) {
	t.Setenv("HARDEN_UI_TOKEN", "operator-test-token")
	t.Setenv("HARDEN_LLM_PROVIDER", "openai")
	t.Setenv("HARDEN_MODEL", "gpt-4o-test")
	a, err := newApp(t.TempDir(), "collector-test-token")
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	a.now = func() time.Time { return pdfTestTime }

	host := "web-01.prod_local"
	report := `{"hostname":"web-01.prod_local","timestamp":"2026-07-17T22:30:00Z","collected_as":"root","_decoded":{"system":"kernel"}}`
	if err := os.WriteFile(a.reportPath(host), []byte(report), 0600); err != nil {
		t.Fatalf("write report fixture: %v", err)
	}
	if err := os.WriteFile(a.analysisPath(host), []byte(representativePDFBody()), 0600); err != nil {
		t.Fatalf("write analysis fixture: %v", err)
	}
	reportTime := pdfTestTime.Add(-10 * time.Minute)
	analysisTime := pdfTestTime.Add(-7 * time.Minute)
	if err := os.Chtimes(a.reportPath(host), reportTime, reportTime); err != nil {
		t.Fatalf("set report time: %v", err)
	}
	if err := os.Chtimes(a.analysisPath(host), analysisTime, analysisTime); err != nil {
		t.Fatalf("set analysis time: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/analysis/"+host+"?format=pdf", nil)
	req.Header.Set("X-Auth-Token", "operator-test-token")
	rr := httptest.NewRecorder()
	a.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/pdf" {
		t.Errorf("Content-Type = %q, want application/pdf", got)
	}
	if got := rr.Header().Get("Content-Disposition"); got != `attachment; filename="web-01.prod_local-analysis.pdf"` {
		t.Errorf("Content-Disposition = %q", got)
	}
	if got := rr.Header().Get("Content-Length"); got != strconv.Itoa(rr.Body.Len()) {
		t.Errorf("Content-Length = %q, body length = %d", got, rr.Body.Len())
	}
	if !bytes.HasPrefix(rr.Body.Bytes(), []byte("%PDF-1.4\n")) || !bytes.HasSuffix(rr.Body.Bytes(), []byte("%%EOF\n")) {
		t.Fatal("endpoint body is not a complete PDF")
	}
	if raw := rr.Body.String(); !strings.Contains(raw, "(CURRENT) Tj") || !strings.Contains(raw, "(web-01.prod_local) Tj") {
		t.Error("endpoint PDF is missing report-derived host/status metadata")
	}
}

func TestGenerateAnalysisPDFQAOutput(t *testing.T) {
	output := strings.TrimSpace(os.Getenv("PDF_QA_OUTPUT"))
	if output == "" {
		t.Skip("set PDF_QA_OUTPUT to write the visual QA fixture")
	}
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		t.Fatalf("create PDF QA directory: %v", err)
	}
	pdf := generateAnalysisPDF(representativePDFData())
	if err := os.WriteFile(output, pdf, 0644); err != nil {
		t.Fatalf("write PDF QA fixture: %v", err)
	}
	t.Logf("wrote %d-byte PDF QA fixture to %s", len(pdf), output)
}

func declaredPDFPageCount(t *testing.T, raw string) int {
	t.Helper()
	match := regexp.MustCompile(`/Type /Pages /Kids \[[^]]*\] /Count ([0-9]+)`).FindStringSubmatch(raw)
	if len(match) != 2 {
		t.Fatal("PDF pages object does not declare a page count")
	}
	count, err := strconv.Atoi(match[1])
	if err != nil || count < 1 {
		t.Fatalf("invalid PDF page count %q", match[1])
	}
	return count
}

func assertPDFStartXref(t *testing.T, pdf []byte) {
	t.Helper()
	match := regexp.MustCompile(`startxref\n([0-9]+)\n%%EOF\n$`).FindSubmatch(pdf)
	if len(match) != 2 {
		t.Fatal("PDF does not contain a valid startxref trailer")
	}
	offset, err := strconv.Atoi(string(match[1]))
	if err != nil || offset < 0 || offset >= len(pdf) {
		t.Fatalf("invalid startxref offset %q", match[1])
	}
	if !bytes.HasPrefix(pdf[offset:], []byte("xref\n")) {
		t.Fatalf("startxref offset %d does not point to the xref table", offset)
	}
}

func firstPDFBytes(pdf []byte, limit int) []byte {
	if len(pdf) < limit {
		return pdf
	}
	return pdf[:limit]
}

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	defaultSharedSecret = "ccdcagent2026"
	defaultDataDir      = "./reports"
	defaultListenAddr   = ":8000"
	maxReportBytes      = 64 << 20
)

var checkOrder = []string{
	"system",
	"users",
	"processes",
	"network",
	"services",
	"scheduled",
	"permissions",
	"ssh",
	"firewall",
	"persistence",
}

var analysisSectionTitles = []string{
	"HARDENING SCORE",
	"PROBABLE COMPROMISE / RED-TEAM ARTIFACTS",
	"HARDENING GAPS",
	"SUSPICIOUS PROCESSES / SERVICES / TASKS",
	"DO-NOW CHECKLIST",
}

var analysisSectionLabels = map[string]string{
	"HARDENING SCORE":                          "Hardening Score",
	"PROBABLE COMPROMISE / RED-TEAM ARTIFACTS": "Probable Compromise",
	"HARDENING GAPS":                           "Hardening Gaps",
	"SUSPICIOUS PROCESSES / SERVICES / TASKS":  "Suspicious Tasks",
	"DO-NOW CHECKLIST":                         "Do-Now Checklist",
}

var defaultModels = map[string]string{
	"anthropic": "claude-sonnet-4-5",
	"openai":    "gpt-4o",
}

var (
	headingPrefixRE      = regexp.MustCompile(`^#+\s*`)
	numberedPrefixRE     = regexp.MustCompile(`^\d+[\.)]\s*`)
	inlineCodeRE         = regexp.MustCompile("`([^`]+)`")
	inlineStrongRE       = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	sectionSlugRE        = regexp.MustCompile(`[^a-z0-9]+`)
	scoreRE              = regexp.MustCompile(`(?:^|[^\d])(100|[1-9]?\d)\s*/\s*100`)
	bulletRE             = regexp.MustCompile(`^\s*[-*]\s+(.*)$`)
	numberedItemRE       = regexp.MustCompile(`^\s*\d+[\.)]\s+(.*)$`)
	tableSeparatorCellRE = regexp.MustCompile(`^:?-{3,}:?$`)
)

const dashboardCSS = `
:root {
  color-scheme: dark;
  --bg: #05070d;
  --panel: #0d1420;
  --panel-soft: #121d2b;
  --panel-hot: #161328;
  --ink: #ecfff8;
  --muted: #91a7ad;
  --line: #233f4b;
  --accent: #00f5d4;
  --accent-strong: #ff2bd6;
  --warn: #ffd166;
  --danger: #ff5f6d;
  --ok-bg: #092923;
  --warn-bg: #30240b;
  --danger-bg: #321219;
  --info-bg: #0b2535;
  --glow: rgba(0, 245, 212, 0.24);
  --hot-glow: rgba(255, 43, 214, 0.20);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background:
    linear-gradient(180deg, rgba(5, 7, 13, 0.90), rgba(5, 7, 13, 1)),
    repeating-linear-gradient(90deg, rgba(0, 245, 212, 0.045) 0 1px, transparent 1px 76px),
    repeating-linear-gradient(0deg, rgba(255, 43, 214, 0.035) 0 1px, transparent 1px 76px),
    var(--bg);
  color: var(--ink);
  font: 14px/1.45 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
.shell {
  width: min(1180px, calc(100% - 32px));
  margin: 0 auto;
  padding: 28px 0 36px;
}
.topbar {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 22px;
}
.eyebrow {
  margin: 0 0 5px;
  color: var(--accent);
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0;
  text-transform: uppercase;
  text-shadow: 0 0 16px var(--glow);
}
h1 {
  margin: 0;
  font-size: clamp(30px, 5vw, 48px);
  line-height: 1;
  letter-spacing: 0;
  color: var(--ink);
  text-shadow: 0 0 24px rgba(0, 245, 212, 0.16);
}
.runtime {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
  color: var(--muted);
  font-size: 12px;
}
.runtime span,
.badge {
  display: inline-flex;
  align-items: center;
  min-height: 26px;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--panel);
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.02);
  padding: 3px 9px;
  white-space: nowrap;
}
.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 18px;
}
.metric {
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
  box-shadow: 0 0 26px rgba(0, 0, 0, 0.24), inset 0 1px 0 rgba(255, 255, 255, 0.03);
  padding: 14px 16px;
}
.metric span {
  display: block;
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
}
.metric strong {
  display: block;
  margin-top: 6px;
  font-size: 30px;
  line-height: 1;
  color: var(--accent);
  text-shadow: 0 0 18px var(--glow);
}
.table-panel {
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
  box-shadow: 0 22px 52px rgba(0, 0, 0, 0.28), 0 0 0 1px rgba(0, 245, 212, 0.04);
}
.table-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  border-bottom: 1px solid var(--line);
  background: var(--panel-soft);
  padding: 13px 16px;
}
.table-heading h2 {
  margin: 0;
  font-size: 16px;
  letter-spacing: 0;
}
.table-heading span {
  color: var(--muted);
  font-size: 12px;
}
.table-scroll {
  overflow-x: auto;
}
table {
  width: 100%;
  min-width: 820px;
  border-collapse: collapse;
}
th,
td {
  border-bottom: 1px solid var(--line);
  padding: 12px 14px;
  text-align: left;
  vertical-align: middle;
}
th {
  background: #0a101a;
  color: #95fff0;
  font-size: 12px;
  font-weight: 800;
  text-transform: uppercase;
}
tr:last-child td {
  border-bottom: 0;
}
tbody tr:hover {
  background: rgba(0, 245, 212, 0.06);
}
.host strong {
  display: block;
  font-size: 15px;
}
.host span {
  display: block;
  color: var(--muted);
  font-size: 12px;
  margin-top: 2px;
}
.badge.ok {
  border-color: rgba(0, 245, 212, 0.56);
  background: var(--ok-bg);
  color: #66ffe8;
}
.badge.pending {
  border-color: rgba(255, 209, 102, 0.62);
  background: var(--warn-bg);
  color: var(--warn);
}
.badge.root {
  border-color: rgba(0, 245, 212, 0.56);
  background: var(--ok-bg);
  color: var(--accent);
}
.badge.limited {
  border-color: rgba(255, 95, 109, 0.62);
  background: var(--danger-bg);
  color: var(--danger);
}
.actions {
  display: flex;
  align-items: center;
  gap: 7px;
  flex-wrap: wrap;
}
.history-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  list-style: none;
  margin: 16px 0 0;
  padding: 0;
}
.button,
button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 32px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #0a121d;
  color: var(--ink);
  padding: 5px 10px;
  font: inherit;
  font-weight: 700;
  text-decoration: none;
  cursor: pointer;
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.02);
}
button.primary {
  border-color: var(--accent);
  background: linear-gradient(135deg, rgba(0, 245, 212, 0.95), rgba(255, 43, 214, 0.78));
  color: #041013;
  box-shadow: 0 0 20px var(--glow);
}
.button:hover,
button:hover {
  border-color: var(--accent);
  box-shadow: 0 0 18px var(--glow);
}
.empty {
  padding: 34px 16px;
  color: var(--muted);
  text-align: center;
}
.analysis-top {
  align-items: flex-start;
  margin-bottom: 16px;
}
.back-link {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  margin-bottom: 10px;
  color: var(--accent);
  font-weight: 800;
  text-decoration: none;
}
.back-link:hover {
  color: var(--accent-strong);
  text-shadow: 0 0 14px var(--hot-glow);
}
.analysis-summary {
  display: grid;
  grid-template-columns: minmax(240px, 330px) minmax(0, 1fr);
  gap: 14px;
  margin-bottom: 18px;
}
.score-panel,
.summary-panel,
.analysis-card,
.side-panel {
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
  box-shadow: 0 20px 46px rgba(0, 0, 0, 0.28), 0 0 0 1px rgba(255, 43, 214, 0.035);
}
.score-panel {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: center;
  gap: 14px;
  padding: 16px;
}
.score-ring {
  display: grid;
  place-items: center;
  width: 96px;
  height: 96px;
  border: 9px solid var(--line);
  border-radius: 50%;
  background: radial-gradient(circle at 50% 45%, #132538 0, #07111c 66%, #04070d 100%);
  box-shadow: inset 0 0 18px rgba(0, 0, 0, 0.55), 0 0 22px rgba(0, 245, 212, 0.12);
}
.score-ring.ok {
  border-color: var(--accent);
}
.score-ring.warn {
  border-color: var(--warn);
}
.score-ring.danger {
  border-color: var(--danger);
}
.score-ring.neutral {
  border-color: #6f8490;
}
.score-ring strong {
  font-size: 28px;
  line-height: 1;
}
.score-ring span {
  color: var(--muted);
  font-size: 11px;
  font-weight: 800;
}
.score-copy span,
.summary-panel span,
.side-panel span {
  color: var(--muted);
  font-size: 12px;
  font-weight: 800;
  text-transform: uppercase;
}
.score-copy strong {
  display: block;
  margin-top: 5px;
  font-size: 18px;
}
.score-copy p,
.summary-panel p {
  margin: 7px 0 0;
  color: var(--muted);
}
.summary-panel {
  padding: 16px;
}
.section-pills {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 13px;
}
.section-pills a {
  display: inline-flex;
  align-items: center;
  min-height: 28px;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--panel-soft);
  color: var(--ink);
  padding: 3px 10px;
  font-size: 12px;
  font-weight: 800;
  text-decoration: none;
}
.section-pills a:hover {
  border-color: var(--accent);
  color: var(--accent);
  box-shadow: 0 0 16px var(--glow);
}
.analysis-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 280px;
  align-items: start;
  gap: 16px;
}
.analysis-stack {
  display: grid;
  gap: 12px;
}
.analysis-card {
  overflow: hidden;
}
.analysis-card header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  border-bottom: 1px solid var(--line);
  background: var(--panel-soft);
  padding: 12px 15px;
}
.analysis-card h2 {
  margin: 0;
  font-size: 16px;
  letter-spacing: 0;
}
.analysis-card .count {
  color: var(--muted);
  font-size: 12px;
  white-space: nowrap;
}
.analysis-content {
  padding: 14px 15px 16px;
}
.analysis-content p {
  margin: 0 0 10px;
}
.analysis-content p:last-child,
.analysis-content ul:last-child,
.analysis-content ol:last-child,
.analysis-content table:last-child {
  margin-bottom: 0;
}
.analysis-content ul,
.analysis-content ol {
  margin: 0 0 12px;
  padding-left: 22px;
}
.analysis-content li {
  margin: 5px 0;
}
.analysis-content code {
  border: 1px solid var(--line);
  border-radius: 5px;
  background: #08111a;
  color: #9dffef;
  padding: 1px 5px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}
.analysis-content strong {
  color: #ffffff;
}
.analysis-content .table-scroll {
  margin: 2px 0 13px;
  border: 1px solid var(--line);
  border-radius: 8px;
}
.analysis-content table {
  min-width: 640px;
  font-size: 13px;
}
.analysis-content th,
.analysis-content td {
  padding: 10px 12px;
}
.side-panel {
  position: sticky;
  top: 16px;
  padding: 14px;
}
.side-panel h2 {
  margin: 3px 0 12px;
  font-size: 16px;
}
.side-panel dl {
  margin: 0;
}
.side-panel dt {
  margin-top: 12px;
  color: var(--muted);
  font-size: 12px;
  font-weight: 800;
  text-transform: uppercase;
}
.side-panel dd {
  margin: 3px 0 0;
  overflow-wrap: anywhere;
}
.side-actions {
  display: grid;
  gap: 8px;
  margin-top: 14px;
}
.side-actions .button,
.side-actions button {
  width: 100%;
}
.empty-panel {
  border: 1px dashed var(--line);
  border-radius: 8px;
  background: var(--panel);
  padding: 28px 18px;
  text-align: center;
}
.empty-panel h2 {
  margin: 0 0 8px;
}
.empty-panel p {
  margin: 0 auto 16px;
  max-width: 560px;
  color: var(--muted);
}
@media (max-width: 760px) {
  .shell {
    width: min(100% - 20px, 1180px);
    padding-top: 18px;
  }
  .topbar {
    align-items: flex-start;
    flex-direction: column;
  }
  .runtime {
    justify-content: flex-start;
  }
  .metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .analysis-summary,
  .analysis-layout {
    grid-template-columns: 1fr;
  }
  .score-panel {
    grid-template-columns: 1fr;
  }
  .side-panel {
    position: static;
  }
}
`

type app struct {
	dataDir   string
	authToken string
	analyzer  func([]byte) (string, error)
}

type analysisSection struct {
	title string
	lines []string
}

type reportSummary struct {
	host        string
	hostID      string
	collectedAs string
	received    string
	timestamp   string
	sections    int
	analyzed    bool
}

func main() {
	dataDir := getenv("HARDEN_DATA", defaultDataDir)
	authToken := getenv("HARDEN_TOKEN", defaultSharedSecret)
	listenAddr := getenv("HARDEN_ADDR", defaultListenAddr)

	a, err := newApp(dataDir, authToken)
	if err != nil {
		log.Fatalf("server init failed: %v", err)
	}

	provider := selectProvider()
	log.Printf("server starting addr=%s data_dir=%s auth_token_set=%t", listenAddr, dataDir, authToken != "")
	log.Printf(
		"llm provider=%s model=%s anthropic_key_set=%t openai_key_set=%t",
		provider,
		modelFor(provider),
		os.Getenv("ANTHROPIC_API_KEY") != "",
		os.Getenv("OPENAI_API_KEY") != "",
	)

	if err := http.ListenAndServe(listenAddr, a.routes()); err != nil {
		log.Fatal(err)
	}
}

func newApp(dataDir, authToken string) (*app, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}
	return &app{
		dataDir:   dataDir,
		authToken: authToken,
		analyzer:  runPythonAnalyzer,
	}, nil
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.dashboard)
	mux.HandleFunc("/report", a.receiveReport)
	mux.HandleFunc("/report/", a.getReport)
	mux.HandleFunc("/analyze/", a.analyze)
	mux.HandleFunc("/analysis/", a.getAnalysis)
	mux.HandleFunc("/history/", a.getHistory)
	return mux
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func safe(name string) string {
	var b strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '.' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func (a *app) reportPath(host string) string {
	return filepath.Join(a.dataDir, safe(host)+".json")
}

func (a *app) analysisPath(host string) string {
	return filepath.Join(a.dataDir, safe(host)+".analysis.txt")
}

func (a *app) historyDir(host string) string {
	return filepath.Join(a.dataDir, "history", safe(host))
}

func (a *app) historyReportPath(host, stamp string) string {
	return filepath.Join(a.historyDir(host), safe(stamp)+".json")
}

func wantsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/html") || strings.Contains(accept, "application/xhtml+xml")
}

func routeHost(pathValue, prefix string) string {
	return safe(strings.TrimPrefix(pathValue, prefix))
}

func (a *app) receiveReport(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/report" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Auth-Token") != a.authToken {
		log.Printf("rejected report from=%s bad token header_present=%t", r.RemoteAddr, r.Header.Get("X-Auth-Token") != "")
		http.Error(w, "bad token", http.StatusUnauthorized)
		return
	}

	body := http.MaxBytesReader(w, r.Body, maxReportBytes)
	defer body.Close()

	var payload map[string]any
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(&payload); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	receivedAt := time.Now().UTC()
	payload["_decoded"] = decodeChecks(payload["checks"])
	payload["_received"] = receivedAt.Format("2006-01-02T15:04:05.999999Z")
	delete(payload, "checks")

	host := stringValue(payload["hostname"], "unknown")
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		http.Error(w, "could not encode report", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(a.reportPath(host), data, 0644); err != nil {
		log.Printf("could not write report host=%s err=%v", host, err)
		http.Error(w, "could not write report", http.StatusInternalServerError)
		return
	}

	historyStamp := receivedAt.Format("20060102T150405.000000Z")
	historyPath := a.historyReportPath(host, historyStamp)
	if err := os.MkdirAll(filepath.Dir(historyPath), 0755); err != nil {
		log.Printf("could not create history dir host=%s err=%v", host, err)
	} else if err := os.WriteFile(historyPath, data, 0644); err != nil {
		log.Printf("could not write history report host=%s err=%v", host, err)
	}

	decoded := decodedMap(payload["_decoded"])
	log.Printf(
		"received report host=%s from=%s collected_as=%s sections=%s path=%s",
		host,
		r.RemoteAddr,
		stringValue(payload["collected_as"], "?"),
		strings.Join(orderedKeys(decoded), ","),
		a.reportPath(host),
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"host":   payload["hostname"],
	})
}

func decodeChecks(raw any) map[string]string {
	out := make(map[string]string)
	checks, ok := raw.(map[string]any)
	if !ok {
		return out
	}
	for key, value := range checks {
		encoded, ok := value.(string)
		if !ok {
			out[key] = "<decode error>"
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			out[key] = "<decode error>"
			continue
		}
		out[key] = string(decoded)
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writePlain(w http.ResponseWriter, status int, value string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, value)
}

func (a *app) analyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	host := routeHost(r.URL.Path, "/analyze/")
	log.Printf("analysis requested host=%s", host)

	reportData, err := os.ReadFile(a.reportPath(host))
	if err != nil {
		log.Printf("analysis failed host=%s reason=report_not_found path=%s", host, a.reportPath(host))
		http.Error(w, "no report for that host", http.StatusNotFound)
		return
	}

	provider := selectProvider()
	log.Printf("analysis starting host=%s provider=%s model=%s report_path=%s", host, provider, modelFor(provider), a.reportPath(host))
	result, err := a.analyzer(reportData)
	if err != nil {
		result = fmt.Sprintf("[analyzer] Python analyzer failed: %v", err)
	}
	if err := os.WriteFile(a.analysisPath(host), []byte(result), 0644); err != nil {
		log.Printf("could not write analysis host=%s err=%v", host, err)
		http.Error(w, "could not write analysis", http.StatusInternalServerError)
		return
	}

	if strings.HasPrefix(result, "[analyzer]") {
		firstLine := strings.SplitN(result, "\n", 2)[0]
		log.Printf("analysis returned analyzer error host=%s message=%s", host, firstLine)
	} else {
		log.Printf("analysis completed host=%s bytes=%d path=%s", host, len(result), a.analysisPath(host))
	}

	if wantsHTML(r) {
		http.Redirect(w, r, "/analysis/"+safe(host), http.StatusSeeOther)
		return
	}
	writePlain(w, http.StatusOK, result)
}

func (a *app) getAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	host := routeHost(r.URL.Path, "/analysis/")
	path := a.analysisPath(host)
	text, err := os.ReadFile(path)
	raw := r.URL.Query().Has("raw")
	format := r.URL.Query().Get("format")
	if err == nil {
		log.Printf("served analysis host=%s path=%s", host, path)
		switch format {
		case "md":
			writeMarkdownDownload(w, host, string(text))
			return
		case "pdf":
			writePDFDownload(w, host, string(text))
			return
		}
		if raw || !wantsHTML(r) {
			writePlain(w, http.StatusOK, string(text))
			return
		}
		writeHTML(w, renderAnalysisPage(a, host, string(text)))
		return
	}

	log.Printf("analysis not found host=%s path=%s", host, path)
	message := fmt.Sprintf("no analysis yet - POST /analyze/%s", safe(host))
	if raw || !wantsHTML(r) {
		writePlain(w, http.StatusOK, message)
		return
	}
	writeHTML(w, renderMissingAnalysisPage(a, host))
}

func writeMarkdownDownload(w http.ResponseWriter, host, text string) {
	filename := safe(host) + "-analysis.md"
	body := fmt.Sprintf(
		"# CCDC Hardening Analysis: %s\n\n_Generated %s_\n\n%s\n",
		host,
		time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		text,
	)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body)
}

func writePDFDownload(w http.ResponseWriter, host, text string) {
	filename := safe(host) + "-analysis.pdf"
	title := fmt.Sprintf("CCDC Hardening Analysis: %s", host)
	pdfBytes := generateAnalysisPDF(title, text)
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdfBytes)
}

// generateAnalysisPDF renders plain text into a minimal multi-page PDF using
// only the standard library: a monospace Courier font, word-wrapped lines,
// and a hand-built PDF object/xref table. No third-party PDF library needed.
func generateAnalysisPDF(title string, body string) []byte {
	const pageWidth = 612.0
	const pageHeight = 792.0
	const marginX = 50.0
	const marginTop = 56.0
	const marginBottom = 50.0
	const fontSize = 10.0
	const leading = 14.0

	charWidth := fontSize * 0.6
	maxChars := int((pageWidth - 2*marginX) / charWidth)
	if maxChars < 20 {
		maxChars = 20
	}

	lines := buildPDFLines(title, body, maxChars)

	linesPerPage := int((pageHeight - marginTop - marginBottom) / leading)
	if linesPerPage < 1 {
		linesPerPage = 1
	}

	var pages [][]string
	for len(lines) > 0 {
		n := linesPerPage
		if n > len(lines) {
			n = len(lines)
		}
		pages = append(pages, lines[:n])
		lines = lines[n:]
	}
	if len(pages) == 0 {
		pages = [][]string{{}}
	}

	totalObjects := 3 + len(pages)*2
	pageObjNums := make([]int, len(pages))
	contentObjNums := make([]int, len(pages))
	for i := range pages {
		pageObjNums[i] = 4 + i*2
		contentObjNums[i] = 5 + i*2
	}

	var buf bytes.Buffer
	offsets := make([]int, totalObjects+1)
	record := func(objNum int) {
		offsets[objNum] = buf.Len()
	}

	buf.WriteString("%PDF-1.4\n")

	record(1)
	buf.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	record(2)
	buf.WriteString("2 0 obj\n<< /Type /Pages /Kids [")
	for i, n := range pageObjNums {
		if i > 0 {
			buf.WriteString(" ")
		}
		fmt.Fprintf(&buf, "%d 0 R", n)
	}
	fmt.Fprintf(&buf, "] /Count %d >>\nendobj\n", len(pages))

	record(3)
	buf.WriteString("3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n")

	for i, pageLines := range pages {
		pageObj := pageObjNums[i]
		contentObj := contentObjNums[i]

		var content bytes.Buffer
		content.WriteString("BT\n")
		fmt.Fprintf(&content, "/F1 %.1f Tf\n", fontSize)
		fmt.Fprintf(&content, "%.1f TL\n", leading)
		fmt.Fprintf(&content, "%.1f %.1f Td\n", marginX, pageHeight-marginTop)
		for _, line := range pageLines {
			fmt.Fprintf(&content, "(%s) Tj T*\n", pdfEscape(line))
		}
		content.WriteString("ET\n")

		record(pageObj)
		fmt.Fprintf(&buf,
			"%d 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>\nendobj\n",
			pageObj, pageWidth, pageHeight, contentObj)

		record(contentObj)
		fmt.Fprintf(&buf, "%d 0 obj\n<< /Length %d >>\nstream\n", contentObj, content.Len())
		buf.Write(content.Bytes())
		buf.WriteString("\nendstream\nendobj\n")
	}

	xrefStart := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", totalObjects+1)
	buf.WriteString("0000000000 65535 f \n")
	for n := 1; n <= totalObjects; n++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[n])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", totalObjects+1, xrefStart)

	return buf.Bytes()
}

func buildPDFLines(title string, body string, width int) []string {
	lines := []string{
		title,
		"Generated: " + time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		"",
	}
	for _, raw := range strings.Split(body, "\n") {
		lines = append(lines, wrapPlainText(raw, width)...)
	}
	return lines
}

func wrapPlainText(line string, width int) []string {
	if width <= 0 {
		width = 80
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return []string{""}
	}
	var out []string
	current := ""
	currentLen := 0
	for _, word := range fields {
		wr := []rune(word)
		for len(wr) > width {
			if current != "" {
				out = append(out, current)
				current = ""
				currentLen = 0
			}
			out = append(out, string(wr[:width]))
			wr = wr[width:]
		}
		wLen := len(wr)
		switch {
		case current == "":
			current = string(wr)
			currentLen = wLen
		case currentLen+1+wLen <= width:
			current += " " + string(wr)
			currentLen += 1 + wLen
		default:
			out = append(out, current)
			current = string(wr)
			currentLen = wLen
		}
	}
	if current != "" {
		out = append(out, current)
	}
	return out
}

// pdfEscape encodes a line for a PDF literal string: backslash/paren
// escaping plus a best-effort Latin-1 fallback since standard PDF fonts
// like Courier only cover WinAnsiEncoding, not full UTF-8.
func pdfEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\\' || r == '(' || r == ')':
			b.WriteByte('\\')
			b.WriteByte(byte(r))
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20:
			// drop other control characters
		case r < 0x100:
			b.WriteByte(byte(r))
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

func (a *app) getReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	host := routeHost(r.URL.Path, "/report/")
	path := a.reportPath(host)
	payload, err := readPayload(path)
	if err != nil {
		log.Printf("report not found host=%s path=%s", host, path)
		http.Error(w, "no report", http.StatusNotFound)
		return
	}
	log.Printf("served report host=%s path=%s", host, path)
	writePlain(w, http.StatusOK, formatDecodedReport(payload))
}

func formatDecodedReport(payload map[string]any) string {
	decoded := decodedMap(payload["_decoded"])
	var b strings.Builder
	for _, key := range orderedKeys(decoded) {
		b.WriteString("===== ")
		b.WriteString(strings.ToUpper(key))
		b.WriteString(" =====\n")
		b.WriteString(decoded[key])
		b.WriteString("\n\n")
	}
	return b.String()
}

// getHistory serves the archive of every report a host has ever submitted.
// /history/<host> lists timestamps; /history/<host>/<timestamp> replays one.
func (a *app) getHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/history/")
	parts := strings.SplitN(rest, "/", 2)
	host := safe(parts[0])

	if len(parts) == 2 && parts[1] != "" {
		stamp := safe(parts[1])
		payload, err := readPayload(a.historyReportPath(host, stamp))
		if err != nil {
			log.Printf("history entry not found host=%s stamp=%s", host, stamp)
			http.Error(w, "no history entry", http.StatusNotFound)
			return
		}
		log.Printf("served history entry host=%s stamp=%s", host, stamp)
		writePlain(w, http.StatusOK, formatDecodedReport(payload))
		return
	}

	stamps, err := a.listHistoryStamps(host)
	if err != nil || len(stamps) == 0 {
		message := fmt.Sprintf("no report history yet for %s", host)
		if !wantsHTML(r) {
			writePlain(w, http.StatusOK, message)
			return
		}
		writeHTML(w, renderMissingAnalysisPage(a, host))
		return
	}

	if !wantsHTML(r) {
		writePlain(w, http.StatusOK, strings.Join(stamps, "\n"))
		return
	}

	hostID := html.EscapeString(host)
	var rows strings.Builder
	for i := len(stamps) - 1; i >= 0; i-- {
		stamp := html.EscapeString(stamps[i])
		rows.WriteString(fmt.Sprintf(
			"<li><a class='button' href='/history/%s/%s'>%s</a></li>",
			hostID, stamp, stamp,
		))
	}
	page := fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>History - %s</title>
  <style>%s</style>
</head>
<body>
  <main class="shell">
    <a class="back-link" href="/">Back to dashboard</a>
    <h1>Report history: %s</h1>
    <p>%d stored report%s, most recent first.</p>
    <ul class="history-list">%s</ul>
  </main>
</body>
</html>`,
		hostID, dashboardCSS, hostID, len(stamps), pluralSuffix(len(stamps)), rows.String())
	writeHTML(w, page)
}

func pluralSuffix(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func (a *app) listHistoryStamps(host string) ([]string, error) {
	entries, err := os.ReadDir(a.historyDir(host))
	if err != nil {
		return nil, err
	}
	var stamps []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".json") {
			stamps = append(stamps, strings.TrimSuffix(name, ".json"))
		}
	}
	sort.Strings(stamps)
	return stamps, nil
}

func (a *app) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reports := a.loadDashboardReports()
	total := len(reports)
	analyzedCount := 0
	rootCount := 0
	for _, report := range reports {
		if report.analyzed {
			analyzedCount++
		}
		if report.collectedAs == "root" {
			rootCount++
		}
	}
	pendingCount := total - analyzedCount
	provider := selectProvider()

	var rows strings.Builder
	for _, report := range reports {
		host := html.EscapeString(report.host)
		hostID := html.EscapeString(report.hostID)
		who := html.EscapeString(report.collectedAs)
		received := html.EscapeString(report.received)
		timestamp := html.EscapeString(report.timestamp)
		statusClass := "pending"
		statusText := "Pending"
		if report.analyzed {
			statusClass = "ok"
			statusText = "Analyzed"
		}
		identityClass := "limited"
		identityText := "Limited"
		if report.collectedAs == "root" {
			identityClass = "root"
			identityText = "Root"
		}
		rows.WriteString("<tr>")
		rows.WriteString(fmt.Sprintf("<td class='host'><strong>%s</strong><span>Collected: %s</span></td>", host, timestamp))
		rows.WriteString(fmt.Sprintf("<td><span class='badge %s'>%s</span> <span>%s</span></td>", identityClass, identityText, who))
		rows.WriteString(fmt.Sprintf("<td>%s</td>", received))
		rows.WriteString(fmt.Sprintf("<td><span class='badge %s'>%s</span></td>", statusClass, statusText))
		rows.WriteString(fmt.Sprintf("<td>%d</td>", report.sections))
		rows.WriteString("<td><div class='actions'>")
		rows.WriteString(fmt.Sprintf("<a class='button' href='/report/%s'>Report</a>", hostID))
		rows.WriteString(fmt.Sprintf("<a class='button' href='/history/%s'>History</a>", hostID))
		rows.WriteString(fmt.Sprintf("<a class='button' href='/analysis/%s'>Analysis</a>", hostID))
		rows.WriteString(fmt.Sprintf("<form method='post' action='/analyze/%s'>", hostID))
		rows.WriteString("<button class='primary' type='submit'>Run</button></form>")
		rows.WriteString("</div></td>")
		rows.WriteString("</tr>")
	}
	if rows.Len() == 0 {
		rows.WriteString("<tr><td class='empty' colspan='6'>No host reports yet</td></tr>")
	}

	model := html.EscapeString(modelFor(provider))
	if model == "" {
		model = "not configured"
	}
	page := fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CCDC Hardening Tracker</title>
  <style>%s</style>
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div>
        <p class="eyebrow">Blue Team Operations</p>
        <h1>CCDC Hardening Tracker</h1>
      </div>
      <div class="runtime" aria-label="Runtime configuration">
        <span>Provider: %s</span>
        <span>Model: %s</span>
        <span>Data: %s</span>
      </div>
    </header>

    <section class="metrics" aria-label="Report summary">
      <div class="metric"><span>Hosts</span><strong>%d</strong></div>
      <div class="metric"><span>Analyzed</span><strong>%d</strong></div>
      <div class="metric"><span>Pending</span><strong>%d</strong></div>
      <div class="metric"><span>Root Reports</span><strong>%d</strong></div>
    </section>

    <section class="table-panel" aria-label="Host reports">
      <div class="table-heading">
        <h2>Host Reports</h2>
        <span>%d total</span>
      </div>
      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>Identity</th>
              <th>Received UTC</th>
              <th>Status</th>
              <th>Sections</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>%s</tbody>
        </table>
      </div>
    </section>
  </main>
</body>
</html>`,
		dashboardCSS,
		html.EscapeString(provider),
		model,
		html.EscapeString(a.dataDir),
		total,
		analyzedCount,
		pendingCount,
		rootCount,
		total,
		rows.String(),
	)
	writeHTML(w, page)
}

func writeHTML(w http.ResponseWriter, value string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, value)
}

func readPayload(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func decodedMap(raw any) map[string]string {
	out := make(map[string]string)
	values, ok := raw.(map[string]any)
	if !ok {
		if typed, ok := raw.(map[string]string); ok {
			return typed
		}
		return out
	}
	for key, value := range values {
		out[key] = stringValue(value, "")
	}
	return out
}

func orderedKeys(values map[string]string) []string {
	seen := make(map[string]bool, len(values))
	keys := make([]string, 0, len(values))
	for _, key := range checkOrder {
		if _, ok := values[key]; ok {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	var rest []string
	for key := range values {
		if !seen[key] {
			rest = append(rest, key)
		}
	}
	sort.Strings(rest)
	return append(keys, rest...)
}

func stringValue(raw any, fallback string) string {
	value, ok := raw.(string)
	if !ok || value == "" {
		return fallback
	}
	return value
}

func (a *app) loadDashboardReports() []reportSummary {
	entries, err := os.ReadDir(a.dataDir)
	if err != nil {
		log.Printf("could not read data dir=%s err=%v", a.dataDir, err)
		return nil
	}

	var reports []reportSummary
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(a.dataDir, entry.Name())
		payload, err := readPayload(path)
		if err != nil {
			log.Printf("skipping unreadable report path=%s err=%v", path, err)
			continue
		}
		host := stringValue(payload["hostname"], strings.TrimSuffix(entry.Name(), ".json"))
		decoded := decodedMap(payload["_decoded"])
		reports = append(reports, reportSummary{
			host:        host,
			hostID:      safe(host),
			collectedAs: stringValue(payload["collected_as"], "?"),
			received:    stringValue(payload["_received"], "?"),
			timestamp:   stringValue(payload["timestamp"], "?"),
			sections:    len(decoded),
			analyzed:    fileExists(a.analysisPath(host)),
		})
	}
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].received > reports[j].received
	})
	return reports
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func runPythonAnalyzer(payload []byte) (string, error) {
	code := strings.Join([]string{
		"import json, sys",
		"from analyzer import analyze_report",
		"payload = json.load(sys.stdin)",
		"sys.stdout.write(analyze_report(payload))",
	}, "\n")
	cmd := exec.Command(getenv("HARDEN_PYTHON", "python3"), "-c", code)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Env = os.Environ()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return "", fmt.Errorf("%w: %s", err, message)
		}
		return "", err
	}
	return stdout.String(), nil
}

func selectProvider() string {
	configured := strings.ToLower(strings.TrimSpace(os.Getenv("HARDEN_LLM_PROVIDER")))
	if configured != "" {
		return configured
	}
	if os.Getenv("OPENAI_API_KEY") != "" && os.Getenv("ANTHROPIC_API_KEY") == "" {
		return "openai"
	}
	return "anthropic"
}

func modelFor(provider string) string {
	if configured := strings.TrimSpace(os.Getenv("HARDEN_MODEL")); configured != "" {
		return configured
	}
	return defaultModels[provider]
}

func stripAnalysisMarkup(value string) string {
	text := strings.TrimSpace(value)
	text = headingPrefixRE.ReplaceAllString(text, "")
	text = numberedPrefixRE.ReplaceAllString(text, "")
	text = strings.ReplaceAll(text, "**", "")
	text = strings.ReplaceAll(text, "__", "")
	text = strings.ReplaceAll(text, "`", "")
	return strings.TrimSpace(text)
}

func inlineMarkup(value string) string {
	escaped := html.EscapeString(strings.TrimSpace(value))
	escaped = inlineCodeRE.ReplaceAllString(escaped, "<code>$1</code>")
	escaped = inlineStrongRE.ReplaceAllString(escaped, "<strong>$1</strong>")
	return escaped
}

func matchAnalysisSection(line string) (string, string, bool) {
	cleaned := stripAnalysisMarkup(line)
	upper := strings.ToUpper(cleaned)
	for _, title := range analysisSectionTitles {
		if strings.HasPrefix(upper, title) {
			detail := strings.TrimLeft(cleaned[len(title):], " :-")
			return title, detail, true
		}
	}
	return "", "", false
}

func slugFor(value string) string {
	slug := sectionSlugRE.ReplaceAllString(strings.ToLower(value), "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		return "section"
	}
	return slug
}

func splitAnalysisSections(text string) []analysisSection {
	var sections []analysisSection
	var current *analysisSection
	var intro []string

	for _, line := range strings.Split(text, "\n") {
		title, detail, ok := matchAnalysisSection(line)
		if ok {
			if current != nil {
				sections = append(sections, *current)
			}
			current = &analysisSection{title: title}
			if detail != "" {
				current.lines = append(current.lines, detail)
			}
			continue
		}
		if current != nil {
			current.lines = append(current.lines, line)
		} else if strings.TrimSpace(line) != "" {
			intro = append(intro, line)
		}
	}

	if current != nil {
		sections = append(sections, *current)
	}
	if len(intro) > 0 {
		sections = append([]analysisSection{{title: "ANALYSIS SUMMARY", lines: intro}}, sections...)
	}
	if len(sections) == 0 {
		sections = append(sections, analysisSection{title: "ANALYSIS OUTPUT", lines: strings.Split(text, "\n")})
	}
	return sections
}

func extractScore(text string) *int {
	match := scoreRE.FindStringSubmatch(text)
	if len(match) < 2 {
		return nil
	}
	value, err := strconv.Atoi(match[1])
	if err != nil {
		return nil
	}
	if value < 0 {
		value = 0
	}
	if value > 100 {
		value = 100
	}
	return &value
}

func scoreStatus(score *int, text string) (string, string) {
	if strings.HasPrefix(text, "[analyzer]") {
		return "danger", "Analyzer error"
	}
	if score == nil {
		return "neutral", "Unscored"
	}
	switch {
	case *score >= 80:
		return "ok", "Strong"
	case *score >= 60:
		return "warn", "Needs work"
	default:
		return "danger", "Critical"
	}
}

func scoreSummary(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if scoreRE.MatchString(line) {
			summary := stripAnalysisMarkup(line)
			summary = regexp.MustCompile(`(?i)^HARDENING SCORE\s*[:\-]?\s*`).ReplaceAllString(summary, "")
			if summary != "" {
				return summary
			}
			return "Score found in analysis output."
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			return stripAnalysisMarkup(line)
		}
	}
	return "No analysis text was saved."
}

func sectionItemCount(lines []string) int {
	count := 0
	for _, line := range lines {
		if bulletRE.MatchString(line) || numberedItemRE.MatchString(line) || strings.Contains(line, "|") {
			count++
		}
	}
	return count
}

func tableCells(line string) []string {
	stripped := strings.Trim(strings.TrimSpace(line), "|")
	parts := strings.Split(stripped, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) == 1 && parts[0] == "" {
		return nil
	}
	return parts
}

func isTableSeparator(line string) bool {
	cells := tableCells(line)
	if len(cells) == 0 {
		return false
	}
	for _, cell := range cells {
		if !tableSeparatorCellRE.MatchString(strings.TrimSpace(cell)) {
			return false
		}
	}
	return true
}

func isTableLine(line string) bool {
	return strings.Contains(line, "|") && len(tableCells(line)) >= 3
}

func renderTable(lines []string) string {
	var rows [][]string
	for _, line := range lines {
		if !isTableSeparator(line) {
			rows = append(rows, tableCells(line))
		}
	}
	if len(rows) == 0 {
		return ""
	}

	header := rows[0]
	body := rows[1:]
	var b strings.Builder
	b.WriteString("<div class='table-scroll'><table><thead><tr>")
	for _, cell := range header {
		b.WriteString("<th>")
		b.WriteString(inlineMarkup(cell))
		b.WriteString("</th>")
	}
	b.WriteString("</tr></thead><tbody>")
	if len(body) == 0 {
		b.WriteString(fmt.Sprintf("<tr><td colspan='%d'>No rows</td></tr>", max(1, len(header))))
	} else {
		for _, row := range body {
			b.WriteString("<tr>")
			for _, cell := range row {
				b.WriteString("<td>")
				b.WriteString(inlineMarkup(cell))
				b.WriteString("</td>")
			}
			b.WriteString("</tr>")
		}
	}
	b.WriteString("</tbody></table></div>")
	return b.String()
}

func renderList(tag string, items []string) string {
	var b strings.Builder
	b.WriteString("<")
	b.WriteString(tag)
	b.WriteString(">")
	for _, item := range items {
		b.WriteString("<li>")
		b.WriteString(inlineMarkup(item))
		b.WriteString("</li>")
	}
	b.WriteString("</")
	b.WriteString(tag)
	b.WriteString(">")
	return b.String()
}

func renderAnalysisBlocks(lines []string) string {
	var parts strings.Builder
	index := 0
	for index < len(lines) {
		line := lines[index]
		stripped := strings.TrimSpace(line)
		if stripped == "" {
			index++
			continue
		}

		if isTableLine(line) {
			var tableLines []string
			for index < len(lines) && (isTableLine(lines[index]) || isTableSeparator(lines[index])) {
				tableLines = append(tableLines, lines[index])
				index++
			}
			parts.WriteString(renderTable(tableLines))
			continue
		}

		if match := bulletRE.FindStringSubmatch(line); len(match) == 2 {
			var items []string
			for index < len(lines) {
				match := bulletRE.FindStringSubmatch(lines[index])
				if len(match) != 2 {
					break
				}
				items = append(items, match[1])
				index++
			}
			parts.WriteString(renderList("ul", items))
			continue
		}

		if match := numberedItemRE.FindStringSubmatch(line); len(match) == 2 {
			var items []string
			for index < len(lines) {
				match := numberedItemRE.FindStringSubmatch(lines[index])
				if len(match) != 2 {
					break
				}
				items = append(items, match[1])
				index++
			}
			parts.WriteString(renderList("ol", items))
			continue
		}

		parts.WriteString("<p>")
		parts.WriteString(inlineMarkup(stripped))
		parts.WriteString("</p>")
		index++
	}

	if parts.Len() == 0 {
		return "<p>No detail was returned for this section.</p>"
	}
	return parts.String()
}

func loadReportMetadata(a *app, host string) map[string]string {
	payload, err := readPayload(a.reportPath(host))
	if err != nil {
		log.Printf("could not read report metadata host=%s path=%s err=%v", host, a.reportPath(host), err)
		return map[string]string{}
	}
	decoded := decodedMap(payload["_decoded"])
	return map[string]string{
		"host":         stringValue(payload["hostname"], host),
		"collected_as": stringValue(payload["collected_as"], "?"),
		"timestamp":    stringValue(payload["timestamp"], "?"),
		"received":     stringValue(payload["_received"], "?"),
		"sections":     strconv.Itoa(len(decoded)),
	}
}

func renderMissingAnalysisPage(a *app, host string) string {
	hostID := html.EscapeString(safe(host))
	reportExists := fileExists(a.reportPath(host))
	action := "<a class='button' href='/'>Back to Dashboard</a>"
	message := "No report is stored for this host yet."
	if reportExists {
		action = fmt.Sprintf("<form method='post' action='/analyze/%s'><button class='primary' type='submit'>Run Analysis</button></form>", hostID)
		message = "The report exists, but the LLM analysis has not been run for this host."
	}
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Analysis Pending - %s</title>
  <style>%s</style>
</head>
<body>
  <main class="shell">
    <a class="back-link" href="/">Back to dashboard</a>
    <section class="empty-panel">
      <h2>Analysis pending for %s</h2>
      <p>%s</p>
      <div class="actions" style="justify-content:center">%s</div>
    </section>
  </main>
</body>
</html>`, hostID, dashboardCSS, hostID, html.EscapeString(message), action)
}

func renderAnalysisPage(a *app, host string, text string) string {
	metadata := loadReportMetadata(a, host)
	displayHost := html.EscapeString(valueOr(metadata["host"], host))
	hostID := html.EscapeString(safe(host))
	score := extractScore(text)
	scoreClass, scoreLabel := scoreStatus(score, text)
	scoreValue := "--"
	if score != nil {
		scoreValue = strconv.Itoa(*score)
	}
	summary := html.EscapeString(scoreSummary(text))
	sections := splitAnalysisSections(text)
	var contentSections []analysisSection
	for _, section := range sections {
		if section.title != "HARDENING SCORE" {
			contentSections = append(contentSections, section)
		}
	}
	if len(contentSections) == 0 {
		contentSections = sections
	}

	var pills strings.Builder
	var cards strings.Builder
	for _, section := range contentSections {
		title := analysisSectionLabels[section.title]
		if title == "" {
			title = strings.Title(strings.ToLower(section.title))
		}
		sectionID := slugFor(title)
		count := sectionItemCount(section.lines)
		countText := "details"
		if count > 0 {
			countText = fmt.Sprintf("%d item", count)
			if count != 1 {
				countText += "s"
			}
		}
		pills.WriteString(fmt.Sprintf("<a href='#%s'>%s</a>", html.EscapeString(sectionID), html.EscapeString(title)))
		cards.WriteString(fmt.Sprintf(
			"<section class='analysis-card' id='%s'><header><h2>%s</h2><span class='count'>%s</span></header><div class='analysis-content'>%s</div></section>",
			html.EscapeString(sectionID),
			html.EscapeString(title),
			html.EscapeString(countText),
			renderAnalysisBlocks(section.lines),
		))
	}

	provider := selectProvider()
	model := modelFor(provider)
	if model == "" {
		model = "not configured"
	}
	sideValues := [][2]string{
		{"Collected As", valueOr(metadata["collected_as"], "?")},
		{"Collected", valueOr(metadata["timestamp"], "?")},
		{"Received UTC", valueOr(metadata["received"], "?")},
		{"Sections", valueOr(metadata["sections"], "?")},
		{"Provider", provider},
		{"Model", model},
	}
	var sideRows strings.Builder
	for _, pair := range sideValues {
		sideRows.WriteString(fmt.Sprintf("<dt>%s</dt><dd>%s</dd>", html.EscapeString(pair[0]), html.EscapeString(pair[1])))
	}

	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Analysis - %s</title>
  <style>%s</style>
</head>
<body>
  <main class="shell">
    <header class="topbar analysis-top">
      <div>
        <a class="back-link" href="/">Back to dashboard</a>
        <p class="eyebrow">LLM Diagnosis</p>
        <h1>Analysis: %s</h1>
      </div>
      <div class="runtime" aria-label="Analysis links">
        <a class="button" href="/report/%s">Report</a>
        <a class="button" href="/history/%s">History</a>
        <a class="button" href="/analysis/%s?raw=1">Raw Text</a>
        <a class="button" href="/analysis/%s?format=pdf">Download PDF</a>
        <a class="button" href="/analysis/%s?format=md">Download .md</a>
      </div>
    </header>

    <section class="analysis-summary" aria-label="Analysis summary">
      <div class="score-panel">
        <div class="score-ring %s">
          <div><strong>%s</strong><span>/100</span></div>
        </div>
        <div class="score-copy">
          <span>Status</span>
          <strong>%s</strong>
          <p>%s</p>
        </div>
      </div>
      <div class="summary-panel">
        <span>Sections</span>
        <p>Use this view to scan the saved LLM findings, then open the raw report only when you need source collection detail.</p>
        <nav class="section-pills" aria-label="Analysis sections">%s</nav>
      </div>
    </section>

    <section class="analysis-layout">
      <div class="analysis-stack">%s</div>
      <aside class="side-panel">
        <span>Host Context</span>
        <h2>%s</h2>
        <dl>%s</dl>
        <div class="side-actions">
          <form method="post" action="/analyze/%s">
            <button class="primary" type="submit">Run Again</button>
          </form>
          <a class="button" href="/analysis/%s?raw=1">View Raw Analysis</a>
          <a class="button" href="/analysis/%s?format=pdf">Download PDF</a>
          <a class="button" href="/analysis/%s?format=md">Download .md</a>
        </div>
      </aside>
    </section>
  </main>
</body>
</html>`,
		displayHost,
		dashboardCSS,
		displayHost,
		hostID,
		hostID,
		hostID,
		hostID,
		hostID,
		html.EscapeString(scoreClass),
		html.EscapeString(scoreValue),
		html.EscapeString(scoreLabel),
		summary,
		pills.String(),
		cards.String(),
		displayHost,
		sideRows.String(),
		hostID,
		hostID,
		hostID,
		hostID,
	)
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

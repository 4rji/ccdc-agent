package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	defaultSharedSecret = "ccdcagent2026"
	defaultDataDir      = "./reports"
	defaultListenAddr   = ":8000"
	maxReportBytes      = 24 << 20
	maxDecodedBytes     = 16 << 20
	maxStoredReportSize = 32 << 20
	maxHostnameBytes    = 253
	maxTimestampBytes   = 64
	maxCollectedAsBytes = 128
	maxAgentVersion     = 64
	maxCheckNameBytes   = 64
	maxReportChecks     = 64
	historyPageSize     = 25
	historyStampLayout  = "20060102T150405.000000Z"
	receivedLayout      = "2006-01-02T15:04:05.999999Z"
	displayTimeLayout   = "2006-01-02 15:04:05 UTC"
	defaultStaleAfter   = 15 * time.Minute
	defaultAnalyzeLimit = 2
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
	"integrity",
}

var checkLabels = map[string]string{
	"system":      "System & kernel",
	"users":       "Accounts & privilege",
	"processes":   "Processes",
	"network":     "Network exposure",
	"services":    "Services",
	"scheduled":   "Scheduled tasks",
	"permissions": "File permissions",
	"ssh":         "SSH",
	"firewall":    "Firewall",
	"persistence": "Persistence",
	"integrity":   "Package integrity",
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
	errAnalyzerTimeout    = errors.New("analyzer timeout")
	errStoredReportTooBig = errors.New("stored report exceeds safety limit")
	errInvalidReport      = errors.New("stored report has an invalid shape")
	headingPrefixRE       = regexp.MustCompile(`^#+\s*`)
	numberedPrefixRE      = regexp.MustCompile(`^\d+[\.)]\s*`)
	inlineCodeRE          = regexp.MustCompile("`([^`]+)`")
	inlineStrongRE        = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	sectionSlugRE         = regexp.MustCompile(`[^a-z0-9]+`)
	scoreRE               = regexp.MustCompile(`(?:^|[^\d])(100|[1-9]?\d)\s*/\s*100`)
	bulletRE              = regexp.MustCompile(`^\s*[-*]\s+(.*)$`)
	numberedItemRE        = regexp.MustCompile(`^\s*\d+[\.)]\s+(.*)$`)
	tableSeparatorCellRE  = regexp.MustCompile(`^:?-{3,}:?$`)
	hashedSafeIDRE        = regexp.MustCompile(`^@[A-Za-z0-9][A-Za-z0-9._-]*-[0-9a-f]{64}$`)
)

//go:embed dashboard.css
var dashboardCSS string

type app struct {
	dataDir       string
	authToken     string
	uiToken       string
	analyzer      func([]byte) (string, error)
	now           func() time.Time
	staleAfter    time.Duration
	storageMu     sync.Mutex
	lastReceived  time.Time
	analysisSlots chan struct{}
	protectUI     bool
}

type incomingReport struct {
	AgentVersion string         `json:"agent_version"`
	Hostname     string         `json:"hostname"`
	Timestamp    string         `json:"timestamp"`
	CollectedAs  string         `json:"collected_as"`
	IsRoot       *bool          `json:"is_root"`
	Checks       map[string]any `json:"checks"`
}

type analysisSection struct {
	title string
	lines []string
}

type reportSummary struct {
	host           string
	hostID         string
	collectedAs    string
	received       string
	receivedISO    string
	receivedAt     time.Time
	relativeAge    string
	timestamp      string
	sections       int
	lines          int
	historyCount   int
	analysisStatus string
	freshness      string
}

type reportSectionView struct {
	key   string
	id    string
	label string
	text  string
	lines int
	bytes int
	empty bool
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
	log.Printf("server starting addr=%s data_dir=%s auth_token_set=%t ui_auth=%t ui_token_separate=%t", listenAddr, dataDir, authToken != "", a.protectUI, a.uiToken != a.authToken)
	if a.protectUI && a.uiToken == a.authToken {
		log.Printf("security warning: UI shares HARDEN_TOKEN; set HARDEN_UI_TOKEN to isolate operator access")
	}
	log.Printf(
		"llm provider=%s model=%s anthropic_key_set=%t openai_key_set=%t",
		provider,
		modelFor(provider),
		os.Getenv("ANTHROPIC_API_KEY") != "",
		os.Getenv("OPENAI_API_KEY") != "",
	)

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           a.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func newApp(dataDir, authToken string) (*app, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dataDir, 0700); err != nil {
		return nil, err
	}
	uiToken := strings.TrimSpace(os.Getenv("HARDEN_UI_TOKEN"))
	if uiToken == "" {
		uiToken = authToken
	}
	return &app{
		dataDir:       dataDir,
		authToken:     authToken,
		uiToken:       uiToken,
		analyzer:      runPythonAnalyzer,
		now:           time.Now,
		staleAfter:    durationEnv("HARDEN_STALE_AFTER", defaultStaleAfter),
		analysisSlots: make(chan struct{}, intEnv("HARDEN_ANALYZE_LIMIT", defaultAnalyzeLimit)),
		protectUI:     boolEnv("HARDEN_PROTECT_UI", true),
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
	mux.HandleFunc("/healthz", a.healthz)
	return secureHeaders(a.requireAuth(mux))
}

func (a *app) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Report ingestion has its own collector-token check. Keeping it out of
		// UI auth lets operators use a separate token without changing agents.
		if !a.protectUI || r.URL.Path == "/healthz" || r.URL.Path == "/report" {
			next.ServeHTTP(w, r)
			return
		}
		if tokenMatches(r.Header.Get("X-Auth-Token"), a.uiToken) {
			next.ServeHTTP(w, r)
			return
		}
		_, password, basicOK := r.BasicAuth()
		if basicOK && tokenMatches(password, a.uiToken) {
			if isMutation(r.Method) && !sameOriginRequest(r) && !a.validCSRF(w, r) {
				writePlain(w, http.StatusForbidden, "cross-origin mutation rejected; use the UI or X-Auth-Token")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="CCDC Hardening Tracker", charset="UTF-8"`)
		writePlain(w, http.StatusUnauthorized, "authentication required")
	})
}

func isMutation(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func sameOriginRequest(r *http.Request) bool {
	source := strings.TrimSpace(r.Header.Get("Origin"))
	if source == "" {
		source = strings.TrimSpace(r.Header.Get("Referer"))
	}
	if source == "" {
		return strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "same-origin")
	}
	parsed, err := url.Parse(source)
	if err != nil || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func (a *app) csrfToken() string {
	mac := hmac.New(sha256.New, []byte(a.uiToken))
	_, _ = mac.Write([]byte("ccdc-hardening-ui-csrf-v1"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *app) validCSRF(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		return false
	}
	return tokenMatches(r.PostForm.Get("csrf_token"), a.csrfToken())
}

func (a *app) analysisForm(host, label, attributes string) string {
	return fmt.Sprintf(
		"<form method='post' action='/analyze/%s' %s><input type='hidden' name='csrf_token' value='%s'><button class='primary' type='submit'>%s</button></form>",
		html.EscapeString(safe(host)),
		attributes,
		html.EscapeString(a.csrfToken()),
		html.EscapeString(label),
	)
}

func (a *app) healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	info, err := os.Stat(a.dataDir)
	if err != nil || !info.IsDir() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	probe, err := os.CreateTemp(a.dataDir, ".health-*")
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	probePath := probe.Name()
	if closeErr := probe.Close(); closeErr != nil {
		_ = os.Remove(probePath)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	_ = os.Remove(probePath)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		log.Printf("invalid %s=%q; using %s", key, value, fallback)
		return fallback
	}
	return parsed
}

func intEnv(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		log.Printf("invalid %s=%q; using %d", key, value, fallback)
		return fallback
	}
	return parsed
}

func boolEnv(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		log.Printf("invalid %s=%q; using %t", key, value, fallback)
		return fallback
	}
	return parsed
}

func validMetadata(value string, limit int) bool {
	return len(value) <= limit && strings.IndexFunc(value, unicode.IsControl) < 0
}

func safe(name string) string {
	original := strings.TrimSpace(name)
	if hashedSafeIDRE.MatchString(original) {
		return original
	}
	var b strings.Builder
	lastDash := false
	for _, r := range original {
		asciiLetter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		if asciiLetter || unicode.IsDigit(r) && r <= unicode.MaxASCII || r == '-' || r == '.' || r == '_' {
			b.WriteRune(r)
			lastDash = r == '-'
		} else if b.Len() > 0 && !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	base := strings.Trim(b.String(), ".-_")
	changed := base != original
	if len(base) > 120 {
		base = strings.TrimRight(base[:120], ".-_")
		changed = true
	}
	if base == "" {
		base = "host"
		changed = true
	}
	if changed {
		digest := sha256.Sum256([]byte(original))
		base = fmt.Sprintf("@%s-%x", base, digest[:])
	}
	return base
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
	for _, part := range strings.Split(strings.ToLower(r.Header.Get("Accept")), ",") {
		mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		quality := 1.0
		if rawQuality := params["q"]; rawQuality != "" {
			if parsed, err := strconv.ParseFloat(rawQuality, 64); err == nil {
				quality = parsed
			}
		}
		if quality > 0 && (mediaType == "text/html" || mediaType == "application/xhtml+xml") {
			return true
		}
	}
	return false
}

func wantsRaw(r *http.Request) bool {
	values, ok := r.URL.Query()["raw"]
	if !ok {
		return false
	}
	if len(values) == 0 {
		return true
	}
	value := strings.ToLower(strings.TrimSpace(values[len(values)-1]))
	return value == "" || value == "1" || value == "true" || value == "yes"
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func tokenMatches(got, want string) bool {
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func routeHost(pathValue, prefix string) string {
	rest := strings.TrimPrefix(pathValue, prefix)
	if rest == "" || strings.Contains(rest, "/") {
		return ""
	}
	return safe(rest)
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
	if !tokenMatches(r.Header.Get("X-Auth-Token"), a.authToken) {
		log.Printf("rejected report from=%s bad token header_present=%t", r.RemoteAddr, r.Header.Get("X-Auth-Token") != "")
		http.Error(w, "bad token", http.StatusUnauthorized)
		return
	}

	body := http.MaxBytesReader(w, r.Body, maxReportBytes)
	defer body.Close()
	if r.ContentLength > maxReportBytes {
		http.Error(w, "report body is too large", http.StatusRequestEntityTooLarge)
		return
	}

	var incoming incomingReport
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(&incoming); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "report body is too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "report body is too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid trailing json", http.StatusBadRequest)
		return
	}

	host := strings.TrimSpace(incoming.Hostname)
	if host == "" || len(host) > maxHostnameBytes || strings.IndexFunc(host, unicode.IsControl) >= 0 || hashedSafeIDRE.MatchString(host) {
		http.Error(w, "invalid hostname", http.StatusBadRequest)
		return
	}
	timestamp := strings.TrimSpace(incoming.Timestamp)
	if !validMetadata(timestamp, maxTimestampBytes) {
		http.Error(w, "invalid timestamp", http.StatusBadRequest)
		return
	}
	if timestamp != "" {
		if _, err := time.Parse(time.RFC3339, timestamp); err != nil {
			http.Error(w, "timestamp must use RFC3339", http.StatusBadRequest)
			return
		}
	}
	collectedAs := strings.TrimSpace(incoming.CollectedAs)
	if !validMetadata(collectedAs, maxCollectedAsBytes) {
		http.Error(w, "invalid collected_as", http.StatusBadRequest)
		return
	}
	agentVersion := strings.TrimSpace(incoming.AgentVersion)
	if !validMetadata(agentVersion, maxAgentVersion) {
		http.Error(w, "invalid agent_version", http.StatusBadRequest)
		return
	}
	checks := incoming.Checks
	if len(checks) == 0 || len(checks) > maxReportChecks {
		http.Error(w, "checks must be a non-empty JSON object", http.StatusBadRequest)
		return
	}
	for key := range checks {
		if key == "" || strings.TrimSpace(key) != key || !validMetadata(key, maxCheckNameBytes) {
			http.Error(w, "invalid check name", http.StatusBadRequest)
			return
		}
	}
	estimatedDecoded := 0
	for _, raw := range checks {
		if encoded, ok := raw.(string); ok {
			estimatedDecoded += base64.StdEncoding.DecodedLen(len(encoded))
			if estimatedDecoded > maxDecodedBytes {
				http.Error(w, "decoded report is too large", http.StatusRequestEntityTooLarge)
				return
			}
		}
	}
	decodedChecks := decodeChecks(checks)
	decodedBytes := 0
	for _, value := range decodedChecks {
		decodedBytes += len(value)
	}
	if decodedBytes > maxDecodedBytes {
		http.Error(w, "decoded report is too large", http.StatusRequestEntityTooLarge)
		return
	}
	payload := map[string]any{
		"hostname": host,
		"_decoded": decodedChecks,
	}
	if timestamp != "" {
		payload["timestamp"] = timestamp
	}
	if collectedAs != "" {
		payload["collected_as"] = collectedAs
	}
	if agentVersion != "" {
		payload["agent_version"] = agentVersion
	}
	if incoming.IsRoot != nil {
		payload["is_root"] = *incoming.IsRoot
	}

	a.storageMu.Lock()
	defer a.storageMu.Unlock()
	receivedAt := a.now().UTC()
	if !receivedAt.After(a.lastReceived) {
		receivedAt = a.lastReceived.Add(time.Microsecond)
	}
	a.lastReceived = receivedAt
	payload["_received"] = receivedAt.Format(receivedLayout)

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		http.Error(w, "could not encode report", http.StatusInternalServerError)
		return
	}
	if len(data) > maxStoredReportSize {
		http.Error(w, "stored report representation is too large", http.StatusRequestEntityTooLarge)
		return
	}
	historyStamp := receivedAt.Format(historyStampLayout)
	historyPath := a.historyReportPath(host, historyStamp)
	if err := os.MkdirAll(filepath.Dir(historyPath), 0700); err != nil {
		log.Printf("could not create history dir host=%s err=%v", host, err)
		http.Error(w, "could not archive report", http.StatusInternalServerError)
		return
	}
	if err := writeFileAtomic(historyPath, data, 0600); err != nil {
		log.Printf("could not write history report host=%s err=%v", host, err)
		http.Error(w, "could not archive report", http.StatusInternalServerError)
		return
	}
	if err := writeFileAtomic(a.reportPath(host), data, 0600); err != nil {
		log.Printf("could not write report host=%s err=%v", host, err)
		http.Error(w, "could not write report", http.StatusInternalServerError)
		return
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

func writeFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func (a *app) analyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	host := routeHost(r.URL.Path, "/analyze/")
	if host == "" {
		http.NotFound(w, r)
		return
	}
	log.Printf("analysis requested host=%s", host)
	select {
	case a.analysisSlots <- struct{}{}:
		defer func() { <-a.analysisSlots }()
	default:
		w.Header().Set("Retry-After", "5")
		http.Error(w, "analysis capacity reached; try again shortly", http.StatusTooManyRequests)
		return
	}

	reportData, err := readStoredReport(a.reportPath(host))
	if err != nil {
		if errors.Is(err, errStoredReportTooBig) {
			log.Printf("analysis rejected host=%s reason=report_too_large path=%s", host, a.reportPath(host))
			http.Error(w, "stored report exceeds the analysis safety limit", http.StatusRequestEntityTooLarge)
			return
		}
		if os.IsNotExist(err) {
			log.Printf("analysis failed host=%s reason=report_not_found path=%s", host, a.reportPath(host))
			http.Error(w, "no report for that host", http.StatusNotFound)
			return
		}
		log.Printf("analysis failed host=%s reason=report_unreadable path=%s err=%v", host, a.reportPath(host), err)
		http.Error(w, "could not read report", http.StatusInternalServerError)
		return
	}

	provider := selectProvider()
	log.Printf("analysis starting host=%s provider=%s model=%s report_path=%s", host, provider, modelFor(provider), a.reportPath(host))
	result, analyzerErr := a.analyzer(reportData)
	if analyzerErr != nil {
		result = fmt.Sprintf("[analyzer] Python analyzer failed: %v", analyzerErr)
	}

	// The analyzer can run for minutes. Do not let a result based on an older
	// report overwrite the analysis for a report that arrived meanwhile.
	a.storageMu.Lock()
	currentReport, readErr := readStoredReport(a.reportPath(host))
	if readErr != nil || sha256.Sum256(currentReport) != sha256.Sum256(reportData) {
		a.storageMu.Unlock()
		log.Printf("analysis discarded host=%s reason=report_changed", host)
		http.Error(w, "report changed during analysis; run it again", http.StatusConflict)
		return
	}
	if err := writeFileAtomic(a.analysisPath(host), []byte(result), 0600); err != nil {
		a.storageMu.Unlock()
		log.Printf("could not write analysis host=%s err=%v", host, err)
		http.Error(w, "could not write analysis", http.StatusInternalServerError)
		return
	}
	a.storageMu.Unlock()

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
	if analyzerErr != nil {
		status := http.StatusBadGateway
		if errors.Is(analyzerErr, errAnalyzerTimeout) {
			status = http.StatusGatewayTimeout
		}
		writePlain(w, status, result)
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
	if host == "" {
		http.NotFound(w, r)
		return
	}
	path := a.analysisPath(host)
	text, err := os.ReadFile(path)
	raw := wantsRaw(r)
	format := r.URL.Query().Get("format")
	if err == nil {
		log.Printf("served analysis host=%s path=%s", host, path)
		switch format {
		case "md":
			writeMarkdownDownload(w, host, string(text))
			return
		case "pdf":
			a.writePDFDownload(w, host, string(text))
			return
		}
		if raw || !wantsHTML(r) {
			writePlain(w, http.StatusOK, string(text))
			return
		}
		writeHTML(w, renderAnalysisPage(a, host, string(text)))
		return
	}
	if !os.IsNotExist(err) {
		log.Printf("analysis unreadable host=%s path=%s err=%v", host, path, err)
		http.Error(w, "could not read analysis", http.StatusInternalServerError)
		return
	}

	log.Printf("analysis not found host=%s path=%s", host, path)
	message := fmt.Sprintf("no analysis yet - POST /analyze/%s", safe(host))
	if raw || !wantsHTML(r) {
		writePlain(w, http.StatusNotFound, message)
		return
	}
	writeHTMLStatus(w, http.StatusNotFound, renderMissingAnalysisPage(a, host))
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

func (a *app) getReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	host := routeHost(r.URL.Path, "/report/")
	if host == "" {
		http.NotFound(w, r)
		return
	}
	path := a.reportPath(host)
	raw := wantsRaw(r)
	payload, err := readPayload(path)
	if err != nil {
		if fileExists(path) {
			log.Printf("report unreadable host=%s path=%s err=%v", host, path, err)
			if wantsHTML(r) && !raw {
				writeHTMLStatus(w, http.StatusUnprocessableEntity, renderMessagePage(
					"Report unreadable: "+host,
					"The stored report exists but cannot be safely decoded as report JSON.",
					"<a class='button' href='/'>Back to Dashboard</a>",
				))
				return
			}
			writePlain(w, http.StatusUnprocessableEntity, "report exists but cannot be decoded as report JSON")
			return
		}
		log.Printf("report not found host=%s path=%s", host, path)
		http.Error(w, "no report", http.StatusNotFound)
		return
	}
	log.Printf("served report host=%s path=%s", host, path)
	text := formatDecodedReport(payload)
	if raw || !wantsHTML(r) {
		writePlain(w, http.StatusOK, text)
		return
	}
	dateLabel := "Current report - " + formatReceived(stringValue(payload["_received"], "?"))
	writeHTML(w, renderReportPage(host, dateLabel, payload, "/report/"+safe(host)+"?raw=1", true))
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

func buildReportSections(payload map[string]any) []reportSectionView {
	decoded := decodedMap(payload["_decoded"])
	keys := orderedKeys(decoded)
	sections := make([]reportSectionView, 0, len(keys))
	for _, key := range keys {
		label := checkLabels[key]
		if label == "" {
			label = strings.Title(strings.ReplaceAll(key, "_", " "))
		}
		text := decoded[key]
		sections = append(sections, reportSectionView{
			key:   key,
			id:    "check-" + slugFor(key),
			label: label,
			text:  text,
			lines: countLines(text),
			bytes: len(text),
			empty: strings.TrimSpace(text) == "",
		})
	}
	return sections
}

func parseReceived(value string) (time.Time, bool) {
	parsed, err := time.Parse(receivedLayout, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

func relativeTime(now, value time.Time) string {
	if value.IsZero() {
		return "time unknown"
	}
	age := now.Sub(value)
	if age < 0 {
		age = 0
	}
	switch {
	case age < time.Minute:
		return "just now"
	case age < time.Hour:
		minutes := int(age / time.Minute)
		return fmt.Sprintf("%d min ago", minutes)
	case age < 24*time.Hour:
		hours := int(age / time.Hour)
		return fmt.Sprintf("%d hr%s ago", hours, pluralSuffix(hours))
	default:
		days := int(age / (24 * time.Hour))
		return fmt.Sprintf("%d day%s ago", days, pluralSuffix(days))
	}
}

func formatBytes(size int) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
}

// formatStamp turns a history filename stamp into a readable date; on parse
// failure the raw stamp is still usable as a label.
func formatStamp(stamp string) string {
	t, err := time.Parse(historyStampLayout, stamp)
	if err != nil {
		return stamp
	}
	return t.Format(displayTimeLayout)
}

func formatReceived(value string) string {
	t, err := time.Parse(receivedLayout, value)
	if err != nil {
		return value
	}
	return t.Format(displayTimeLayout)
}

func countLines(text string) int {
	trimmed := strings.TrimRight(text, "\n")
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, "\n") + 1
}

func countReportLines(payload map[string]any) int {
	return countLines(formatDecodedReport(payload))
}

type historyEntry struct {
	hostname        string
	date            string
	dateISO         string
	relativeAge     string
	badge           string
	href            string
	stamp           string
	collectedAs     string
	lines           int
	sections        int
	bytes           int
	changedSections []string
	addedLines      int
	removedLines    int
	readable        bool
	hasDelta        bool
	current         bool
}

func (a *app) buildHistoryEntries(host string, stamps []string) []historyEntry {
	return a.buildHistoryEntriesPage(host, stamps, true)
}

// buildHistoryEntriesPage deduplicates the latest snapshot from the current
// report and calculates changes while retaining at most two report payloads.
func (a *app) buildHistoryEntriesPage(host string, stamps []string, includeCurrent bool) []historyEntry {
	hostID := safe(host)
	ordered := append([]string(nil), stamps...)
	sort.Strings(ordered)
	chronological := make([]historyEntry, 0, len(ordered)+1)
	var previousPayload map[string]any
	for _, stamp := range ordered {
		view := historyEntry{
			date:  formatStamp(stamp),
			href:  fmt.Sprintf("/history/%s/%s", hostID, stamp),
			stamp: stamp,
		}
		if parsed, err := time.Parse(historyStampLayout, stamp); err == nil {
			view.dateISO = parsed.Format(time.RFC3339Nano)
			view.relativeAge = relativeTime(a.now().UTC(), parsed)
		}
		if payload, err := readPayload(a.historyReportPath(host, stamp)); err == nil {
			populateHistoryEntry(&view, payload)
			if previousPayload != nil {
				view.changedSections, view.addedLines, view.removedLines = reportChangeStats(previousPayload, payload)
				view.hasDelta = true
			}
			previousPayload = payload
		} else {
			previousPayload = nil
		}
		chronological = append(chronological, view)
	}

	if includeCurrent {
		currentPath := a.reportPath(host)
		currentPayload, err := readPayload(currentPath)
		if err == nil {
			currentReceived := stringValue(currentPayload["_received"], "")
			currentStamp := ""
			if parsed, ok := parseReceived(currentReceived); ok {
				currentStamp = parsed.Format(historyStampLayout)
			}
			matched := false
			for index := range chronological {
				if currentStamp != "" && chronological[index].stamp == currentStamp {
					chronological[index].current = true
					chronological[index].badge = "Current"
					chronological[index].href = "/report/" + hostID
					matched = true
					break
				}
			}
			if !matched {
				view := historyEntry{
					date:    formatReceived(currentReceived),
					dateISO: currentReceived,
					badge:   "Current",
					href:    "/report/" + hostID,
					stamp:   currentStamp,
					current: true,
				}
				if parsed, ok := parseReceived(currentReceived); ok {
					view.relativeAge = relativeTime(a.now().UTC(), parsed)
				}
				populateHistoryEntry(&view, currentPayload)
				if previousPayload != nil {
					view.changedSections, view.addedLines, view.removedLines = reportChangeStats(previousPayload, currentPayload)
					view.hasDelta = true
				}
				chronological = append(chronological, view)
			}
		} else if fileExists(currentPath) && len(chronological) == 0 {
			chronological = append(chronological, historyEntry{
				date:    "current report",
				badge:   "Current",
				href:    "/report/" + hostID,
				current: true,
			})
		}
	}

	entries := make([]historyEntry, 0, len(chronological))
	for index := len(chronological) - 1; index >= 0; index-- {
		entries = append(entries, chronological[index])
	}
	return entries
}

func populateHistoryEntry(entry *historyEntry, payload map[string]any) {
	decoded := decodedMap(payload["_decoded"])
	entry.hostname = stringValue(payload["hostname"], "")
	entry.lines = countReportLines(payload)
	entry.sections = coveredCheckCount(decoded)
	entry.collectedAs = stringValue(payload["collected_as"], "?")
	entry.readable = true
	for _, text := range decoded {
		entry.bytes += len(text)
	}
}

func reportChangeStats(before, after map[string]any) ([]string, int, int) {
	oldSections := decodedMap(before["_decoded"])
	newSections := decodedMap(after["_decoded"])
	keys := make(map[string]struct{}, len(oldSections)+len(newSections))
	for key := range oldSections {
		keys[key] = struct{}{}
	}
	for key := range newSections {
		keys[key] = struct{}{}
	}
	var changed []string
	added := 0
	removed := 0
	for key := range keys {
		if oldSections[key] == newSections[key] {
			continue
		}
		changed = append(changed, key)
		sectionAdded, sectionRemoved := lineChangeStats(oldSections[key], newSections[key])
		added += sectionAdded
		removed += sectionRemoved
	}
	sort.Slice(changed, func(i, j int) bool {
		left := indexOf(checkOrder, changed[i])
		right := indexOf(checkOrder, changed[j])
		if left == right {
			return changed[i] < changed[j]
		}
		return left < right
	})
	return changed, added, removed
}

func lineChangeStats(before, after string) (int, int) {
	counts := make(map[string]int)
	for _, line := range contentLines(before) {
		counts[line]++
	}
	added := 0
	for _, line := range contentLines(after) {
		if counts[line] > 0 {
			counts[line]--
		} else {
			added++
		}
	}
	removed := 0
	for _, count := range counts {
		removed += count
	}
	return added, removed
}

func contentLines(value string) []string {
	trimmed := strings.TrimRight(value, "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func indexOf(values []string, target string) int {
	for index, value := range values {
		if value == target {
			return index
		}
	}
	return len(values)
}

type historyPagination struct {
	page       int
	totalPages int
	newerHref  string
	olderHref  string
}

func renderHistoryPage(host string, entries []historyEntry) string {
	return renderHistoryPageWithPagination(host, entries, historyPagination{page: 1, totalPages: 1})
}

func renderHistoryPageWithPagination(host string, entries []historyEntry, pagination historyPagination) string {
	displayName := host
	for _, entry := range entries {
		if entry.hostname != "" {
			displayName = entry.hostname
			break
		}
	}
	displayHost := html.EscapeString(displayName)
	hostID := html.EscapeString(safe(host))
	var cards strings.Builder
	archiveCount := 0
	for _, entry := range entries {
		if !entry.current {
			archiveCount++
		}
		statusClass := "neutral"
		statusLabel := "Snapshot"
		if entry.current {
			statusClass = "ok"
			statusLabel = "Current"
		}
		if !entry.readable {
			statusClass = "danger"
			statusLabel = "Unreadable"
		}

		changeClass := "baseline"
		changeTitle := "Baseline capture"
		changeDetail := "No earlier readable capture is available on this page."
		if entry.hasDelta {
			if len(entry.changedSections) == 0 {
				changeClass = "stable"
				changeTitle = "No collection changes"
				changeDetail = "All decoded sections match the previous capture."
			} else {
				changeClass = "changed"
				changeTitle = fmt.Sprintf("%d section%s changed", len(entry.changedSections), pluralSuffix(len(entry.changedSections)))
				labels := make([]string, 0, len(entry.changedSections))
				for _, key := range entry.changedSections {
					label := checkLabels[key]
					if label == "" {
						label = key
					}
					labels = append(labels, label)
				}
				changeDetail = strings.Join(labels, ", ")
			}
		}
		if !entry.readable {
			changeClass = "error"
			changeTitle = "Capture cannot be read"
			changeDetail = "The stored file cannot be safely decoded as report JSON."
		}

		action := "<span class='button disabled' aria-disabled='true'>Unavailable</span>"
		if entry.readable {
			label := "Open snapshot"
			if entry.current {
				label = "Open current report"
			}
			action = fmt.Sprintf("<a class='button primary-link' href='%s'>%s</a>", html.EscapeString(entry.href), label)
		}
		dateMarkup := html.EscapeString(entry.date)
		if entry.dateISO != "" {
			dateMarkup = fmt.Sprintf("<time datetime='%s'>%s</time>", html.EscapeString(entry.dateISO), dateMarkup)
		}
		metrics := "<span>Metadata unavailable</span>"
		if entry.readable {
			metrics = fmt.Sprintf(
				"<span>%d/%d sections</span><span>%d lines</span><span>%s</span><span>Collected as %s</span>",
				entry.sections,
				len(checkOrder),
				entry.lines,
				html.EscapeString(formatBytes(entry.bytes)),
				html.EscapeString(entry.collectedAs),
			)
		}
		delta := ""
		if entry.hasDelta && entry.readable {
			delta = fmt.Sprintf("<span class='delta plus'>+%d</span><span class='delta minus'>-%d lines</span>", entry.addedLines, entry.removedLines)
		}
		cards.WriteString(fmt.Sprintf(`
        <li class="history-card %s">
          <div class="history-marker" aria-hidden="true"></div>
          <article>
            <div class="history-card-head">
              <div><span class="badge %s">%s</span><h2>%s</h2><p>%s</p></div>
              %s
            </div>
            <div class="history-meta">%s</div>
            <div class="change-summary %s">
              <div><strong>%s</strong><p>%s</p></div>
              <div class="delta-group">%s</div>
            </div>
          </article>
        </li>`,
			statusClass,
			statusClass,
			html.EscapeString(statusLabel),
			dateMarkup,
			html.EscapeString(valueOr(entry.relativeAge, "time unknown")),
			action,
			metrics,
			changeClass,
			html.EscapeString(changeTitle),
			html.EscapeString(changeDetail),
			delta,
		))
	}

	pageNav := ""
	if pagination.totalPages > 1 {
		newer := "<span class='button disabled'>Newer</span>"
		older := "<span class='button disabled'>Older</span>"
		if pagination.newerHref != "" {
			newer = fmt.Sprintf("<a class='button' href='%s'>Newer</a>", html.EscapeString(pagination.newerHref))
		}
		if pagination.olderHref != "" {
			older = fmt.Sprintf("<a class='button' href='%s'>Older</a>", html.EscapeString(pagination.olderHref))
		}
		pageNav = fmt.Sprintf("<nav class='pagination' aria-label='History pages'>%s<span>Page %d of %d</span>%s</nav>", newer, pagination.page, pagination.totalPages, older)
	}
	currentAction := ""
	for _, entry := range entries {
		if entry.current && entry.readable {
			currentAction = fmt.Sprintf("<a class='button primary-link' href='/report/%s'>Open Current Report</a>", hostID)
			break
		}
	}

	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>History - %s</title>
  <style>%s</style>
</head>
<body>
  <main class="shell">
    <nav class="breadcrumb" aria-label="Breadcrumb"><a href="/">Fleet</a><span>/</span><span>%s</span><span>/</span><strong>History</strong></nav>
    <header class="topbar page-header">
      <div>
        <p class="eyebrow">Capture timeline</p>
        <h1>%s</h1>
        <p class="lede">See what changed between collections instead of opening timestamps blindly.</p>
      </div>
      <div class="actions" aria-label="History links">
        %s
        <a class="button" href="/analysis/%s">Current Analysis</a>
      </div>
    </header>
    <section class="history-overview" aria-label="History overview">
      <div><span>Visible captures</span><strong>%d</strong></div>
      <div><span>Archived on page</span><strong>%d</strong></div>
      <div><span>Page</span><strong>%d / %d</strong></div>
    </section>
    <ol class="history-timeline">%s</ol>
    %s
  </main>
</body>
</html>`,
		displayHost,
		dashboardCSS,
		displayHost,
		displayHost,
		currentAction,
		hostID,
		len(entries),
		archiveCount,
		max(1, pagination.page),
		max(1, pagination.totalPages),
		cards.String(),
		pageNav,
	)
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
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	host := safe(parts[0])

	if len(parts) == 2 && parts[1] != "" {
		if strings.Contains(parts[1], "/") {
			http.NotFound(w, r)
			return
		}
		stamp := safe(parts[1])
		path := a.historyReportPath(host, stamp)
		raw := wantsRaw(r)
		payload, err := readPayload(path)
		if err != nil {
			if fileExists(path) {
				log.Printf("history entry unreadable host=%s stamp=%s err=%v", host, stamp, err)
				if wantsHTML(r) && !raw {
					writeHTMLStatus(w, http.StatusUnprocessableEntity, renderMessagePage(
						"Snapshot unreadable",
						"This history snapshot exists but cannot be safely decoded as report JSON.",
						fmt.Sprintf("<a class='button' href='/history/%s'>Back to History</a>", html.EscapeString(host)),
					))
					return
				}
				writePlain(w, http.StatusUnprocessableEntity, "history entry exists but cannot be decoded as report JSON")
				return
			}
			log.Printf("history entry not found host=%s stamp=%s", host, stamp)
			http.Error(w, "no history entry", http.StatusNotFound)
			return
		}
		log.Printf("served history entry host=%s stamp=%s", host, stamp)
		text := formatDecodedReport(payload)
		if raw || !wantsHTML(r) {
			writePlain(w, http.StatusOK, text)
			return
		}
		dateLabel := "Snapshot - " + formatStamp(stamp)
		writeHTML(w, renderReportPage(host, dateLabel, payload, fmt.Sprintf("/history/%s/%s?raw=1", safe(host), stamp), false))
		return
	}

	stamps, err := a.listHistoryStamps(host)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("could not list history host=%s err=%v", host, err)
		http.Error(w, "could not read report history", http.StatusInternalServerError)
		return
	}
	if !wantsHTML(r) {
		if len(stamps) == 0 {
			writePlain(w, http.StatusOK, fmt.Sprintf("no report history yet for %s", host))
			return
		}
		writePlain(w, http.StatusOK, strings.Join(stamps, "\n"))
		return
	}

	page := 1
	if rawPage := r.URL.Query().Get("page"); rawPage != "" {
		if parsed, err := strconv.Atoi(rawPage); err == nil && parsed > 0 {
			page = parsed
		}
	}
	totalPages := max(1, (len(stamps)+historyPageSize-1)/historyPageSize)
	if page > totalPages {
		page = totalPages
	}
	end := len(stamps) - (page-1)*historyPageSize
	if end < 0 {
		end = 0
	}
	start := max(0, end-historyPageSize)
	pageStamps := stamps[start:end]
	entries := a.buildHistoryEntriesPage(host, pageStamps, page == 1)
	if len(entries) == 0 {
		actions := "<a class='button' href='/'>Back to Dashboard</a>"
		writeHTML(w, renderMessagePage(
			"No history for "+host,
			"No current report or archived captures are available for this host.",
			actions,
		))
		return
	}
	pagination := historyPagination{page: page, totalPages: totalPages}
	if page > 1 {
		pagination.newerHref = fmt.Sprintf("/history/%s?page=%d", safe(host), page-1)
	}
	if page < totalPages {
		pagination.olderHref = fmt.Sprintf("/history/%s?page=%d", safe(host), page+1)
	}
	writeHTML(w, renderHistoryPageWithPagination(host, entries, pagination))
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
			stamp := strings.TrimSuffix(name, ".json")
			if _, err := time.Parse(historyStampLayout, stamp); err == nil {
				stamps = append(stamps, stamp)
			}
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
	freshCount := 0
	needsAnalysisCount := 0
	limitedCount := 0
	attentionCount := 0
	for _, report := range reports {
		if report.freshness == "fresh" {
			freshCount++
		}
		if report.analysisStatus != "ready" {
			needsAnalysisCount++
		}
		if report.collectedAs != "root" {
			limitedCount++
		}
		if report.freshness != "fresh" || report.analysisStatus != "ready" || report.collectedAs != "root" {
			attentionCount++
		}
	}
	provider := selectProvider()
	model := modelFor(provider)
	if model == "" {
		model = "not configured"
	}

	var cards strings.Builder
	for _, report := range reports {
		host := html.EscapeString(report.host)
		hostID := html.EscapeString(report.hostID)
		analysisClass := report.analysisStatus
		analysisLabel := map[string]string{
			"ready":   "Analysis current",
			"stale":   "Analysis stale",
			"failed":  "Analysis failed",
			"pending": "Needs analysis",
		}[report.analysisStatus]
		if analysisLabel == "" {
			analysisLabel = "Analysis unknown"
			analysisClass = "neutral"
		}
		identityClass := "limited"
		identityLabel := "Limited"
		if report.collectedAs == "root" {
			identityClass = "ok"
			identityLabel = "Root"
		}
		freshnessClass := report.freshness
		freshnessLabel := strings.Title(report.freshness)
		if report.freshness == "unknown" {
			freshnessClass = "neutral"
			freshnessLabel = "Time unknown"
		}
		analysisAction := fmt.Sprintf("<a class='button primary-link' href='/analysis/%s'>Open analysis</a>", hostID)
		if report.analysisStatus != "ready" {
			label := "Run analysis"
			if report.analysisStatus == "stale" {
				label = "Refresh analysis"
			} else if report.analysisStatus == "failed" {
				label = "Retry analysis"
			}
			analysisAction = a.analysisForm(report.host, label, "data-analysis-form")
		}
		states := []string{report.freshness, report.analysisStatus}
		if report.analysisStatus != "ready" || report.freshness != "fresh" || report.collectedAs != "root" {
			states = append(states, "attention")
		}
		if report.collectedAs != "root" {
			states = append(states, "limited")
		}
		coverage := float64(report.sections) / float64(max(1, len(checkOrder))) * 100
		if coverage > 100 {
			coverage = 100
		}
		cards.WriteString(fmt.Sprintf(`
      <article class="host-card" data-host-card data-search="%s" data-state="%s">
        <header>
          <div class="host-title">
            <span class="host-indicator %s" aria-hidden="true"></span>
            <div><h2><a href="/report/%s">%s</a></h2><p>Agent collected <code>%s</code></p></div>
          </div>
          <div class="host-badges"><span class="badge %s">%s</span><span class="badge %s">%s</span></div>
        </header>
        <div class="host-grid">
          <div><span>Last received</span><strong>%s</strong><small><time datetime="%s">%s</time></small></div>
          <div><span>Coverage</span><strong>%d / %d sections</strong><div class="coverage-track"><i style="width: %.0f%%"></i></div></div>
          <div><span>Analysis</span><strong class="state-%s">%s</strong><small>%d report lines</small></div>
          <div><span>History</span><strong>%d capture%s</strong><small>Stored snapshots</small></div>
        </div>
        <footer>
          <div class="actions"><a class="button primary-link" href="/report/%s">Open report</a><a class="button" href="/history/%s">History</a></div>
          %s
        </footer>
      </article>`,
			html.EscapeString(strings.ToLower(report.host+" "+report.collectedAs)),
			html.EscapeString(strings.Join(states, " ")),
			freshnessClass,
			hostID,
			host,
			html.EscapeString(report.timestamp),
			freshnessClass,
			html.EscapeString(freshnessLabel),
			identityClass,
			html.EscapeString(identityLabel),
			html.EscapeString(report.relativeAge),
			html.EscapeString(report.receivedISO),
			html.EscapeString(report.received),
			report.sections,
			len(checkOrder),
			coverage,
			analysisClass,
			html.EscapeString(analysisLabel),
			report.lines,
			report.historyCount,
			pluralSuffix(report.historyCount),
			hostID,
			hostID,
			analysisAction,
		))
	}
	if cards.Len() == 0 {
		cards.WriteString("<section class='empty-panel'><h2>No reports yet</h2><p>Send a collector report and the host will appear here with coverage, freshness, history, and analysis status.</p></section>")
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
  <main class="shell" data-fleet-dashboard>
    <header class="topbar fleet-header">
      <div>
        <p class="eyebrow">Blue team operations</p>
        <h1>Fleet posture</h1>
        <p class="lede">Prioritize stale collections, incomplete visibility, and reports that still need analysis.</p>
      </div>
      <div class="fleet-pulse">
        <span class="pulse-dot" aria-hidden="true"></span>
        <div><strong>%d host%s reporting</strong><small>%d need%s attention</small></div>
      </div>
    </header>

    <section class="metrics fleet-metrics" aria-label="Fleet summary">
      <div class="metric"><span>Hosts</span><strong>%d</strong></div>
      <div class="metric good"><span>Fresh reports</span><strong>%d</strong></div>
      <div class="metric urgent"><span>Needs analysis</span><strong>%d</strong></div>
      <div class="metric warn"><span>Limited collection</span><strong>%d</strong></div>
    </section>

    <section class="fleet-controls" aria-label="Fleet filters">
      <label class="search-box"><span>Find a host</span><input type="search" id="host-search" placeholder="Hostname…" autocomplete="off"></label>
      <div class="filter-chips" role="group" aria-label="Filter hosts">
        <button type="button" class="active" data-filter="all">All</button>
        <button type="button" data-filter="attention">Needs attention</button>
        <button type="button" data-filter="stale">Stale reports</button>
        <button type="button" data-filter="limited">Limited</button>
      </div>
    </section>

    <div class="fleet-list" id="fleet-list">%s</div>
    <p class="filter-empty" id="filter-empty" hidden>No hosts match this filter.</p>

    <details class="runtime-details">
      <summary>Analysis runtime</summary>
      <div><span>Provider</span><strong>%s</strong><span>Model</span><strong>%s</strong></div>
    </details>
  </main>
  <script>
  (() => {
    const root = document.querySelector('[data-fleet-dashboard]');
    if (!root) return;
    const cards = [...root.querySelectorAll('[data-host-card]')];
    const search = root.querySelector('#host-search');
    const empty = root.querySelector('#filter-empty');
    let filter = 'all';
    const apply = () => {
      const query = search.value.trim().toLowerCase();
      let visible = 0;
      cards.forEach(card => {
        const matchesText = !query || card.dataset.search.includes(query);
        const matchesFilter = filter === 'all' || card.dataset.state.split(' ').includes(filter);
        card.hidden = !(matchesText && matchesFilter);
        if (!card.hidden) visible += 1;
      });
      empty.hidden = visible !== 0 || cards.length === 0;
    };
    search?.addEventListener('input', apply);
    root.querySelectorAll('[data-filter]').forEach(button => button.addEventListener('click', () => {
      filter = button.dataset.filter;
      root.querySelectorAll('[data-filter]').forEach(item => item.classList.toggle('active', item === button));
      apply();
    }));
    root.querySelectorAll('[data-analysis-form]').forEach(form => form.addEventListener('submit', () => {
      const button = form.querySelector('button');
      button.disabled = true;
      button.textContent = 'Analyzing…';
    }));
  })();
  </script>
</body>
</html>`,
		dashboardCSS,
		total,
		pluralSuffix(total),
		attentionCount,
		map[bool]string{true: "s", false: ""}[attentionCount == 1],
		total,
		freshCount,
		needsAnalysisCount,
		limitedCount,
		cards.String(),
		html.EscapeString(provider),
		html.EscapeString(model),
	)
	writeHTML(w, page)
}

func writeHTML(w http.ResponseWriter, value string) {
	writeHTMLStatus(w, http.StatusOK, value)
}

func writeHTMLStatus(w http.ResponseWriter, status int, value string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, value)
}

func readPayload(path string) (map[string]any, error) {
	data, err := readStoredReport(path)
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return nil, errInvalidReport
	}
	if _, ok := payload["_decoded"].(map[string]any); !ok {
		return nil, errInvalidReport
	}
	return payload, nil
}

func readStoredReport(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxStoredReportSize {
		return nil, errStoredReportTooBig
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
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

func coveredCheckCount(values map[string]string) int {
	count := 0
	for _, key := range checkOrder {
		value, ok := values[key]
		if ok && value != "<decode error>" {
			count++
		}
	}
	return count
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
		receivedISO := stringValue(payload["_received"], "")
		receivedAt, parsedReceived := parseReceived(receivedISO)
		received := formatReceived(receivedISO)
		relativeAge := "time unknown"
		freshness := "unknown"
		if parsedReceived {
			relativeAge = relativeTime(a.now().UTC(), receivedAt)
			freshness = "fresh"
			if a.now().UTC().Sub(receivedAt) > a.staleAfter {
				freshness = "stale"
			}
		}
		reportInfo, _ := entry.Info()
		reportModTime := time.Time{}
		if reportInfo != nil {
			reportModTime = reportInfo.ModTime()
		}
		historyCount := 0
		if stamps, err := a.listHistoryStamps(host); err == nil {
			historyCount = len(stamps)
		}
		reports = append(reports, reportSummary{
			host:           host,
			hostID:         safe(host),
			collectedAs:    stringValue(payload["collected_as"], "?"),
			received:       received,
			receivedISO:    receivedISO,
			receivedAt:     receivedAt,
			relativeAge:    relativeAge,
			timestamp:      stringValue(payload["timestamp"], "?"),
			sections:       coveredCheckCount(decoded),
			lines:          countReportLines(payload),
			historyCount:   historyCount,
			analysisStatus: a.analysisState(host, reportModTime),
			freshness:      freshness,
		})
	}
	sort.Slice(reports, func(i, j int) bool {
		if reports[i].receivedAt.Equal(reports[j].receivedAt) {
			return reports[i].host < reports[j].host
		}
		return reports[i].receivedAt.After(reports[j].receivedAt)
	})
	return reports
}

func (a *app) analysisState(host string, reportModTime time.Time) string {
	path := a.analysisPath(host)
	info, err := os.Stat(path)
	if err != nil {
		return "pending"
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.HasPrefix(strings.TrimSpace(string(data)), "[analyzer]") {
		return "failed"
	}
	if !reportModTime.IsZero() && info.ModTime().Before(reportModTime) {
		return "stale"
	}
	return "ready"
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
	timeout := durationEnv("HARDEN_ANALYZE_TIMEOUT", 3*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, getenv("HARDEN_PYTHON", "python3"), "-c", code)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Env = os.Environ()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("%w after %s", errAnalyzerTimeout, timeout)
		}
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
		"sections":     strconv.Itoa(coveredCheckCount(decoded)),
	}
}

func renderMissingAnalysisPage(a *app, host string) string {
	hostID := html.EscapeString(safe(host))
	reportExists := fileExists(a.reportPath(host))
	action := "<a class='button' href='/'>Back to Dashboard</a>"
	message := "No report is stored for this host yet."
	if reportExists {
		action = a.analysisForm(host, "Run Analysis", "")
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

// renderMessagePage is the chrome for states with nothing to show: empty
// history, corrupt files. actionsHTML is trusted pre-built markup.
func renderMessagePage(title, message, actionsHTML string) string {
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>%s</title>
  <style>%s</style>
</head>
<body>
  <main class="shell">
    <a class="back-link" href="/">Back to dashboard</a>
    <section class="empty-panel">
      <h2>%s</h2>
      <p>%s</p>
      <div class="actions" style="justify-content:center">%s</div>
    </section>
  </main>
</body>
</html>`,
		html.EscapeString(title),
		dashboardCSS,
		html.EscapeString(title),
		html.EscapeString(message),
		actionsHTML,
	)
}

// renderReportPage turns decoded checks into a searchable, collapsible report
// while rawHref preserves the exact plain-text interface used by scripts.
func renderReportPage(host, dateLabel string, payload map[string]any, rawHref string, current bool) string {
	hostID := html.EscapeString(safe(host))
	displayHost := html.EscapeString(stringValue(payload["hostname"], host))
	sections := buildReportSections(payload)
	var nav strings.Builder
	var cards strings.Builder
	totalBytes := 0
	for index, section := range sections {
		totalBytes += section.bytes
		nav.WriteString(fmt.Sprintf(
			"<a href='#%s'><span>%02d</span><strong>%s</strong><small>%d lines</small></a>",
			html.EscapeString(section.id),
			index+1,
			html.EscapeString(section.label),
			section.lines,
		))
		emptyBadge := ""
		output := section.text
		if section.empty {
			emptyBadge = "<span class='badge neutral'>No output</span>"
			output = "(No output was collected for this section.)"
		}
		cards.WriteString(fmt.Sprintf(`
        <details class="report-section" id="%s" open data-section>
          <summary>
            <span class="section-index">%02d</span>
            <span class="section-title"><strong>%s</strong><small>%s · %d lines · %s</small></span>
            %s
          </summary>
          <div class="section-body">
            <div class="section-actions"><button type="button" data-copy="output-%s">Copy section</button></div>
            <pre class="section-output" id="output-%s">%s</pre>
          </div>
        </details>`,
			html.EscapeString(section.id),
			index+1,
			html.EscapeString(section.label),
			html.EscapeString(strings.ToUpper(section.key)),
			section.lines,
			html.EscapeString(formatBytes(section.bytes)),
			emptyBadge,
			html.EscapeString(section.id),
			html.EscapeString(section.id),
			html.EscapeString(output),
		))
	}
	if cards.Len() == 0 {
		cards.WriteString("<section class='empty-panel'><h2>No decoded checks</h2><p>This report did not contain any readable collection sections.</p></section>")
	}

	kind := "Archived snapshot"
	kindShort := "Snapshot"
	analysisAction := "<span class='context-note'>Analysis is only attached to the current report.</span>"
	if current {
		kind = "Current report"
		kindShort = "Current"
		analysisAction = fmt.Sprintf("<a class='button primary-link' href='/analysis/%s'>Open analysis</a>", hostID)
	}
	collectedAs := stringValue(payload["collected_as"], "?")
	identityClass := "limited"
	identityLabel := "Limited collection"
	if collectedAs == "root" {
		identityClass = "ok"
		identityLabel = "Root collection"
	}
	receivedRaw := stringValue(payload["_received"], "")
	receivedRelative := "time unknown"
	if parsed, ok := parseReceived(receivedRaw); ok {
		receivedRelative = relativeTime(time.Now().UTC(), parsed)
	}
	agentVersion := stringValue(payload["agent_version"], "unknown")
	collectedAt := stringValue(payload["timestamp"], "unknown")
	totalLines := countReportLines(payload)
	coveredSections := coveredCheckCount(decodedMap(payload["_decoded"]))

	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Report - %s</title>
  <style>%s</style>
</head>
<body>
  <main class="shell" data-report-viewer>
    <nav class="breadcrumb" aria-label="Breadcrumb"><a href="/">Fleet</a><span>/</span><span>%s</span><span>/</span><strong>%s</strong></nav>
    <header class="topbar page-header">
      <div>
        <p class="eyebrow">%s</p>
        <h1>%s</h1>
        <p class="lede">%s</p>
      </div>
      <div class="actions" aria-label="Report links">
        <a class="button" href="%s">Plain text</a>
        <a class="button" href="/history/%s">History</a>
        %s
      </div>
    </header>

    <section class="report-hero" aria-label="Report summary">
      <div class="report-identity">
        <span class="badge %s">%s</span>
        <h2>%s</h2>
        <p>%s · collected as <strong>%s</strong></p>
      </div>
      <dl class="report-facts">
        <div><dt>Coverage</dt><dd>%d / %d</dd></div>
        <div><dt>Lines</dt><dd>%d</dd></div>
        <div><dt>Payload</dt><dd>%s</dd></div>
        <div><dt>Agent</dt><dd>v%s</dd></div>
      </dl>
      <p class="report-source">Agent timestamp: <code>%s</code> · Server received: <code>%s</code></p>
    </section>

    <section class="report-toolbar" aria-label="Report tools">
      <label class="search-box"><span>Search report</span><input type="search" id="report-search" placeholder="Try ssh, port 22, sudo…" autocomplete="off"></label>
      <div class="toolbar-actions">
        <span id="search-status" aria-live="polite">%d sections</span>
        <button type="button" id="toggle-wrap" aria-pressed="false">No wrap</button>
        <button type="button" id="expand-all">Expand all</button>
        <button type="button" id="collapse-all">Collapse all</button>
      </div>
    </section>

    <div class="report-layout">
      <aside class="report-nav" aria-label="Report sections"><span>Collection sections</span>%s</aside>
      <section class="report-stack">%s</section>
    </div>
  </main>
  <script>
  (() => {
    const root = document.querySelector('[data-report-viewer]');
    if (!root) return;
    const sections = [...root.querySelectorAll('[data-section]')];
    const search = root.querySelector('#report-search');
    const status = root.querySelector('#search-status');
    const wrap = root.querySelector('#toggle-wrap');
    const setOpen = value => sections.filter(section => !section.hidden).forEach(section => { section.open = value; });
    root.querySelector('#expand-all')?.addEventListener('click', () => setOpen(true));
    root.querySelector('#collapse-all')?.addEventListener('click', () => setOpen(false));
    wrap?.addEventListener('click', () => {
      const noWrap = root.classList.toggle('report-nowrap');
      wrap.setAttribute('aria-pressed', String(noWrap));
      wrap.textContent = noWrap ? 'Wrap lines' : 'No wrap';
    });
    search?.addEventListener('input', () => {
      const query = search.value.trim().toLowerCase();
      let visible = 0;
      sections.forEach(section => {
        const match = !query || section.textContent.toLowerCase().includes(query);
        section.hidden = !match;
        if (match) { visible += 1; if (query) section.open = true; }
      });
      status.textContent = query ? visible + ' of ' + sections.length + ' sections' : sections.length + ' sections';
    });
    root.addEventListener('click', async event => {
      const button = event.target.closest('[data-copy]');
      if (!button) return;
      const output = document.getElementById(button.dataset.copy);
      if (!output) return;
      const label = button.textContent;
      try {
        await navigator.clipboard.writeText(output.textContent);
        button.textContent = 'Copied';
      } catch (_) {
        button.textContent = 'Copy unavailable';
      }
      setTimeout(() => { button.textContent = label; }, 1400);
    });
  })();
  </script>
</body>
</html>`,
		displayHost,
		dashboardCSS,
		displayHost,
		html.EscapeString(kindShort),
		html.EscapeString(kind),
		displayHost,
		html.EscapeString(dateLabel),
		html.EscapeString(rawHref),
		hostID,
		analysisAction,
		identityClass,
		html.EscapeString(identityLabel),
		html.EscapeString(kindShort),
		html.EscapeString(receivedRelative),
		html.EscapeString(collectedAs),
		coveredSections,
		len(checkOrder),
		totalLines,
		html.EscapeString(formatBytes(totalBytes)),
		html.EscapeString(agentVersion),
		html.EscapeString(collectedAt),
		html.EscapeString(valueOr(receivedRaw, "unknown")),
		len(sections),
		nav.String(),
		cards.String(),
	)
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
	reportModTime := time.Time{}
	if info, err := os.Stat(a.reportPath(host)); err == nil {
		reportModTime = info.ModTime()
	}
	analysisState := a.analysisState(host, reportModTime)
	analysisStateLabel := map[string]string{
		"ready":   "Current",
		"stale":   "Stale",
		"failed":  "Failed",
		"pending": "Pending",
	}[analysisState]
	statusBanner := ""
	if analysisState == "stale" {
		statusBanner = fmt.Sprintf("<section class='status-banner stale'><div><strong>This analysis is out of date</strong><p>A newer host report arrived after these findings were generated.</p></div>%s</section>", a.analysisForm(host, "Refresh analysis", ""))
	}
	sideValues := [][2]string{
		{"Analysis", valueOr(analysisStateLabel, "Unknown")},
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

    %s
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
	          %s
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
		a.analysisForm(host, "Run Again", ""),
		hostID,
		hostID,
		hostID,
		hostID,
		statusBanner,
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

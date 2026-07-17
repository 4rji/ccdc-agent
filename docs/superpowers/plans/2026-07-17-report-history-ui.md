# Report History Summary + Navigable Raw Views Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `/history/<host>` into a summary table (readable date + total lines per stored report), wrap the raw report views in navigable HTML (keeping `?raw=1` / curl plain text unchanged), and port history support to the legacy `server.py` for parity.

**Architecture:** Server-rendered HTML pages, no JavaScript, no new dependencies. Line counts are computed by reading each stored JSON at render time (competition scale: tens of files per host). `server.go` is the source of truth; `server.py` mirrors the same routes, HTML, and copy.

**Tech Stack:** Go 1.22 stdlib (`net/http`, `html`, `time`), Go `testing` + `httptest`; Python 3.9+ / FastAPI (existing deps only).

**Spec:** `docs/superpowers/specs/2026-07-17-report-history-ui-design.md`

## Global Constraints

- No new dependencies in either server. Go: stdlib only. Python: FastAPI/uvicorn already required.
- Plain-text API is frozen: non-HTML `Accept` and `?raw=1` responses must be byte-identical to current behavior for existing endpoints (`/report/<host>` body, `/history/<host>` stamp list, `/history/<host>/<stamp>` body).
- All UI copy is **English**, matching the existing dashboard ("Back to dashboard", "Analyzed", etc.). The spec's Spanish labels translate as: "Actual" → badge `Current`, "ilegible" → `unreadable`, "Sin historial para X" → `No history for X`.
- History stamp filename format (both servers): `20060102T150405.000000Z` Go layout == `%Y%m%dT%H%M%S.%fZ` Python. `_received` format: `2006-01-02T15:04:05.999999Z` Go == `isoformat()+"Z"` Python.
- Human-readable date format everywhere: `2006-01-02 15:04:05 UTC` (Go) == `%Y-%m-%d %H:%M:%S UTC` (Python).
- Every Go task ends with `go test ./...` passing. Every commit message ends with the trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Do not stage or commit files you did not touch: the working tree has unrelated pending changes (`README.md`, `reports/`, `ccdc-agent` binary). `git add` only the files named in each task.

## File Structure

- `server.go` — all Go changes (this repo keeps the whole server in one file; follow that pattern):
  - time/line-count helpers (Task 1)
  - `.report-pre` CSS + `renderReportPage` + `renderMessagePage`, HTML raw views (Task 2)
  - `historyEntry` + `buildHistoryEntries` + `renderHistoryPage`, summary table + empty page (Task 3)
- `server_test.go` — tests for each Go task.
- `server.py` — history archiving + helpers (Task 4); routes, pages, dashboard button, CSS (Task 5).

---

### Task 1: Go time & line-count helpers

**Files:**
- Modify: `server.go` (constants near line 23; helpers near `formatDecodedReport`, ~line 1098; `receiveReport` ~line 738)
- Test: `server_test.go`

**Interfaces:**
- Consumes: existing `formatDecodedReport(payload map[string]any) string`, `decodedMap`, `orderedKeys`.
- Produces (used by Tasks 2–3):
  - `const historyStampLayout = "20060102T150405.000000Z"`
  - `const receivedLayout = "2006-01-02T15:04:05.999999Z"`
  - `const displayTimeLayout = "2006-01-02 15:04:05 UTC"`
  - `func formatStamp(stamp string) string` — readable date or input unchanged on parse failure
  - `func formatReceived(value string) string` — same, for `_received` values
  - `func countLines(text string) int` — 0 for empty/whitespace-only-newlines text
  - `func countReportLines(payload map[string]any) int` — lines of the decoded report text

- [ ] **Step 1: Write the failing tests**

Append to `server_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run 'TestFormatStamp|TestFormatReceived|TestCountReportLines'`
Expected: FAIL to compile — `undefined: formatStamp` (and friends).

- [ ] **Step 3: Implement the helpers**

In `server.go`, extend the `const` block at the top (after `maxReportBytes`):

```go
	historyStampLayout = "20060102T150405.000000Z"
	receivedLayout     = "2006-01-02T15:04:05.999999Z"
	displayTimeLayout  = "2006-01-02 15:04:05 UTC"
```

Add after `formatDecodedReport`:

```go
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
```

In `receiveReport`, replace the two inline layout literals with the new constants:
- `payload["_received"] = receivedAt.Format("2006-01-02T15:04:05.999999Z")` → `payload["_received"] = receivedAt.Format(receivedLayout)`
- `historyStamp := receivedAt.Format("20060102T150405.000000Z")` → `historyStamp := receivedAt.Format(historyStampLayout)`

- [ ] **Step 4: Run the full test suite**

Run: `go test ./...`
Expected: PASS (all tests, old and new).

- [ ] **Step 5: Commit**

```bash
git add server.go server_test.go
git commit -m "Add time and line-count helpers for history views

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Go HTML raw-report views (`/report/<host>` and `/history/<host>/<stamp>`)

**Files:**
- Modify: `server.go` (`dashboardCSS` ~line 553 before the `@media` block; `getReport` ~line 1081; entry branch of `getHistory` ~line 1122; new render funcs near `renderMissingAnalysisPage`)
- Test: `server_test.go`

**Interfaces:**
- Consumes (Task 1): `formatStamp`, `formatReceived`, `countLines`; existing `formatDecodedReport`, `readPayload`, `fileExists`, `safe`, `wantsHTML`, `writePlain`, `writeHTML`, `pluralSuffix`, `stringValue`, `dashboardCSS`.
- Produces (used by Task 3 and server.py port):
  - `func renderReportPage(host, dateLabel, text, rawHref string) string` — full HTML page with `<pre class="report-pre">`
  - `func renderMessagePage(title, message, actionsHTML string) string` — empty/error state page (`actionsHTML` is pre-built trusted HTML; `title`/`message` are escaped inside)
  - CSS class `.report-pre`
  - Test helpers `writeReportFile(t, a, host, payload)` and `writeHistoryFile(t, a, host, stamp, payload)`

- [ ] **Step 1: Write the failing tests**

Append to `server_test.go` (also add `"fmt"` to imports if the compiler asks; current test file imports do not include it and these tests do not need it):

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run 'TestReportPageHTMLAndRaw|TestHistoryEntryHTMLAndRaw'`
Expected: FAIL — html view missing report-pre block (handlers still return plain text).

- [ ] **Step 3: Add the CSS**

In `server.go`, inside the `dashboardCSS` string, insert immediately **before** the `@media (max-width: 760px) {` block:

```css
.report-pre {
  margin: 0;
  padding: 16px;
  overflow-x: auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.5;
  white-space: pre;
}
```

- [ ] **Step 4: Add the render functions**

Add to `server.go` after `renderMissingAnalysisPage`:

```go
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

// renderReportPage wraps a decoded report in the dashboard chrome. rawHref
// serves the same text as plain text (?raw=1).
func renderReportPage(host, dateLabel, text, rawHref string) string {
	hostID := html.EscapeString(safe(host))
	displayHost := html.EscapeString(host)
	lines := countLines(text)
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Report - %s</title>
  <style>%s</style>
</head>
<body>
  <main class="shell">
    <header class="topbar analysis-top">
      <div>
        <a class="back-link" href="/history/%s">Back to history</a>
        <p class="eyebrow">Raw Report</p>
        <h1>Report: %s</h1>
      </div>
      <div class="runtime" aria-label="Report links">
        <a class="button" href="/">Dashboard</a>
        <a class="button" href="%s">Plain text</a>
        <a class="button" href="/history/%s">History</a>
        <a class="button" href="/analysis/%s">Analysis</a>
      </div>
    </header>
    <section class="table-panel" aria-label="Decoded report">
      <div class="table-heading">
        <h2>%s</h2>
        <span>%d line%s</span>
      </div>
      <pre class="report-pre">%s</pre>
    </section>
  </main>
</body>
</html>`,
		displayHost,
		dashboardCSS,
		hostID,
		displayHost,
		html.EscapeString(rawHref),
		hostID,
		hostID,
		html.EscapeString(dateLabel),
		lines,
		pluralSuffix(lines),
		html.EscapeString(text),
	)
}
```

- [ ] **Step 5: Rewrite `getReport`**

Replace the whole `getReport` function body in `server.go` with:

```go
func (a *app) getReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	host := routeHost(r.URL.Path, "/report/")
	path := a.reportPath(host)
	raw := r.URL.Query().Has("raw")
	payload, err := readPayload(path)
	if err != nil {
		if fileExists(path) {
			log.Printf("report unreadable host=%s path=%s err=%v", host, path, err)
			if wantsHTML(r) && !raw {
				writeHTML(w, renderMessagePage(
					"Report unreadable: "+host,
					"The stored report file exists but is not valid JSON.",
					"<a class='button' href='/'>Back to Dashboard</a>",
				))
				return
			}
			writePlain(w, http.StatusOK, "report exists but is not valid JSON")
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
	writeHTML(w, renderReportPage(host, dateLabel, text, "/report/"+safe(host)+"?raw=1"))
}
```

- [ ] **Step 6: Rewrite the entry branch of `getHistory`**

In `getHistory`, replace the `if len(parts) == 2 && parts[1] != "" { ... }` block with:

```go
	if len(parts) == 2 && parts[1] != "" {
		stamp := safe(parts[1])
		path := a.historyReportPath(host, stamp)
		raw := r.URL.Query().Has("raw")
		payload, err := readPayload(path)
		if err != nil {
			if fileExists(path) {
				log.Printf("history entry unreadable host=%s stamp=%s err=%v", host, stamp, err)
				if wantsHTML(r) && !raw {
					writeHTML(w, renderMessagePage(
						"Snapshot unreadable",
						"This history snapshot exists but is not valid JSON.",
						fmt.Sprintf("<a class='button' href='/history/%s'>Back to History</a>", html.EscapeString(host)),
					))
					return
				}
				writePlain(w, http.StatusOK, "history entry exists but is not valid JSON")
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
		writeHTML(w, renderReportPage(host, dateLabel, text, fmt.Sprintf("/history/%s/%s?raw=1", safe(host), stamp)))
		return
	}
```

- [ ] **Step 7: Run the full test suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add server.go server_test.go
git commit -m "Wrap raw report views in navigable HTML, keep ?raw=1 plain text

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Go history summary table + proper empty page

**Files:**
- Modify: `server.go` (list branch of `getHistory`; new `historyEntry`/`buildHistoryEntries`/`renderHistoryPage`; delete the old inline `<ul class='history-list'>` page and the now-unused `.history-list` CSS block)
- Test: `server_test.go`

**Interfaces:**
- Consumes (Tasks 1–2): `formatStamp`, `formatReceived`, `countReportLines`, `renderMessagePage`, `renderReportPage` links; existing `listHistoryStamps`, `readPayload`, `fileExists`, `safe`, `stringValue`.
- Produces:
  - `type historyEntry struct { date, badge, href string; lines int; readable bool }`
  - `func (a *app) buildHistoryEntries(host string, stamps []string) []historyEntry` — live report first (badge `Current`), then snapshots newest-first
  - `func renderHistoryPage(host string, entries []historyEntry) string`

- [ ] **Step 1: Write the failing tests**

Append to `server_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run 'TestHistorySummaryPage|TestHistoryPlainTextListsStamps|TestEmptyHistoryPage'`
Expected: `TestHistoryPlainTextListsStamps` PASSES (behavior already exists); the other two FAIL.

- [ ] **Step 3: Add entry building and page rendering**

Add to `server.go` near the other history code:

```go
type historyEntry struct {
	date     string
	badge    string // "Current" for the live report, "" for snapshots
	href     string
	lines    int
	readable bool
}

// buildHistoryEntries lists the live report first, then snapshots newest-first.
func (a *app) buildHistoryEntries(host string, stamps []string) []historyEntry {
	hostID := safe(host)
	var entries []historyEntry
	if payload, err := readPayload(a.reportPath(host)); err == nil {
		entries = append(entries, historyEntry{
			date:     formatReceived(stringValue(payload["_received"], "?")),
			badge:    "Current",
			href:     "/report/" + hostID,
			lines:    countReportLines(payload),
			readable: true,
		})
	} else if fileExists(a.reportPath(host)) {
		entries = append(entries, historyEntry{
			date:  "current report",
			badge: "Current",
			href:  "/report/" + hostID,
		})
	}
	for i := len(stamps) - 1; i >= 0; i-- {
		stamp := stamps[i]
		entry := historyEntry{
			date: formatStamp(stamp),
			href: fmt.Sprintf("/history/%s/%s", hostID, stamp),
		}
		if payload, err := readPayload(a.historyReportPath(host, stamp)); err == nil {
			entry.lines = countReportLines(payload)
			entry.readable = true
		}
		entries = append(entries, entry)
	}
	return entries
}

func renderHistoryPage(host string, entries []historyEntry) string {
	displayHost := html.EscapeString(host)
	hostID := html.EscapeString(safe(host))
	var rows strings.Builder
	for _, entry := range entries {
		badge := ""
		if entry.badge != "" {
			badge = fmt.Sprintf(" <span class='badge ok'>%s</span>", html.EscapeString(entry.badge))
		}
		linesText := "unreadable"
		if entry.readable {
			linesText = strconv.Itoa(entry.lines)
		}
		rows.WriteString(fmt.Sprintf(
			"<tr><td>%s%s</td><td>%s</td><td><div class='actions'><a class='button' href='%s'>View report</a></div></td></tr>",
			html.EscapeString(entry.date),
			badge,
			html.EscapeString(linesText),
			entry.href,
		))
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
    <header class="topbar analysis-top">
      <div>
        <a class="back-link" href="/">Back to dashboard</a>
        <p class="eyebrow">Report Archive</p>
        <h1>History: %s</h1>
      </div>
      <div class="runtime" aria-label="History links">
        <a class="button" href="/report/%s">Current Report</a>
        <a class="button" href="/analysis/%s">Analysis</a>
      </div>
    </header>
    <section class="table-panel" aria-label="Stored reports">
      <div class="table-heading">
        <h2>Stored Reports</h2>
        <span>%d total</span>
      </div>
      <div class="table-scroll">
        <table>
          <thead>
            <tr><th>Date</th><th>Lines</th><th>Actions</th></tr>
          </thead>
          <tbody>%s</tbody>
        </table>
      </div>
    </section>
  </main>
</body>
</html>`,
		displayHost,
		dashboardCSS,
		displayHost,
		hostID,
		hostID,
		len(entries),
		rows.String(),
	)
}
```

- [ ] **Step 4: Rewrite the list branch of `getHistory`**

Replace everything in `getHistory` after the entry-branch block (from `stamps, err := a.listHistoryStamps(host)` to the end of the function) with:

```go
	stamps, err := a.listHistoryStamps(host)
	if err != nil || len(stamps) == 0 {
		if !wantsHTML(r) {
			writePlain(w, http.StatusOK, fmt.Sprintf("no report history yet for %s", host))
			return
		}
		actions := "<a class='button' href='/'>Back to Dashboard</a>"
		if fileExists(a.reportPath(host)) {
			actions = fmt.Sprintf("<a class='button' href='/report/%s'>View Current Report</a> %s", html.EscapeString(safe(host)), actions)
		}
		writeHTML(w, renderMessagePage(
			"No history for "+host,
			"No history snapshots have been stored for this host yet. Snapshots are archived every time the agent submits a report.",
			actions,
		))
		return
	}

	if !wantsHTML(r) {
		writePlain(w, http.StatusOK, strings.Join(stamps, "\n"))
		return
	}

	writeHTML(w, renderHistoryPage(host, a.buildHistoryEntries(host, stamps)))
}
```

Then delete the now-dead code this replaced: the `hostID := html.EscapeString(host)` / `rows` builder / `<ul class="history-list">` page literal, and the `pluralSuffix` call there (keep the `pluralSuffix` function — `renderReportPage` uses it). Also delete the `.history-list { ... }` block from `dashboardCSS` (nothing references it anymore).

- [ ] **Step 5: Run the full test suite and build**

Run: `go test ./... && go build -o /dev/null .`
Expected: PASS, clean build.

- [ ] **Step 6: Commit**

```bash
git add server.go server_test.go
git commit -m "Replace history stamp list with summary table and proper empty page

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: server.py history archiving + helpers

**Files:**
- Modify: `server.py` (helpers after `analysis_path` ~line 577; `receive_report` ~line 957; `get_report` ~line 1029 only to use the new formatter)

**Interfaces:**
- Consumes: existing `safe`, `DATA_DIR`, `report_path`, `logger`.
- Produces (used by Task 5):
  - `HISTORY_STAMP_FORMAT = "%Y%m%dT%H%M%S.%fZ"`, `DISPLAY_TIME_FORMAT = "%Y-%m-%d %H:%M:%S UTC"`
  - `history_dir(host) -> pathlib.Path`, `history_report_path(host, stamp) -> pathlib.Path`
  - `list_history_stamps(host) -> list[str]` (sorted ascending, no `.json` suffix)
  - `format_stamp(stamp: str) -> str`, `format_received(value: str) -> str`
  - `format_decoded_report(payload: dict) -> str` (same output as the old inline join in `get_report`)
  - `count_lines(text: str) -> int`, `count_report_lines(payload: dict) -> int`
  - `POST /report` also archives to `reports/history/<host>/<stamp>.json`

- [ ] **Step 1: Add the helpers**

Add to `server.py` after `analysis_path`:

```python
HISTORY_STAMP_FORMAT = "%Y%m%dT%H%M%S.%fZ"
DISPLAY_TIME_FORMAT = "%Y-%m-%d %H:%M:%S UTC"


def history_dir(host):
    return DATA_DIR / "history" / safe(host)


def history_report_path(host, stamp):
    return history_dir(host) / f"{safe(stamp)}.json"


def list_history_stamps(host) -> list:
    hdir = history_dir(host)
    if not hdir.is_dir():
        return []
    return sorted(p.stem for p in hdir.glob("*.json"))


def format_stamp(stamp: str) -> str:
    try:
        return datetime.datetime.strptime(stamp, HISTORY_STAMP_FORMAT).strftime(DISPLAY_TIME_FORMAT)
    except ValueError:
        return stamp


def format_received(value: str) -> str:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.datetime.strptime(value, fmt).strftime(DISPLAY_TIME_FORMAT)
        except ValueError:
            continue
    return value


def format_decoded_report(payload: dict) -> str:
    decoded = payload.get("_decoded", {})
    return "\n".join(f"===== {k.upper()} =====\n{v}\n" for k, v in decoded.items())


def count_lines(text: str) -> int:
    stripped = text.rstrip("\n")
    if not stripped:
        return 0
    return stripped.count("\n") + 1


def count_report_lines(payload: dict) -> int:
    return count_lines(format_decoded_report(payload))
```

- [ ] **Step 2: Archive a history copy in `receive_report`**

In `receive_report`, capture the receive time once and add the archive write. Replace the body between `payload = await request.json()` and the `logger.info(` call with:

```python
    payload = await request.json()
    received = datetime.datetime.utcnow()
    payload["_decoded"] = decode_checks(payload.get("checks", {}))
    payload["_received"] = received.isoformat() + "Z"
    payload.pop("checks", None)  # discard the base64 blob, keep the decoded data
    host = payload.get("hostname", "unknown")
    decoded = payload.get("_decoded", {})
    path = report_path(host)
    data = json.dumps(payload, indent=2)
    path.write_text(data)
    stamp = received.strftime(HISTORY_STAMP_FORMAT)
    try:
        hdir = history_dir(host)
        hdir.mkdir(parents=True, exist_ok=True)
        (hdir / f"{stamp}.json").write_text(data)
    except OSError as exc:
        logger.warning("could not write history report host=%s err=%s", host, exc)
```

- [ ] **Step 3: Use the shared formatter in `get_report`**

In `get_report`, replace the final two lines:

```python
    dec = json.loads(p.read_text()).get("_decoded", {})
    return "\n".join(f"===== {k.upper()} =====\n{v}\n" for k, v in dec.items())
```

with:

```python
    return format_decoded_report(json.loads(p.read_text()))
```

(The full HTML rewrite of `get_report` happens in Task 5; this step only removes the duplicated formatting logic.)

- [ ] **Step 4: Verify it compiles**

Run: `python3 -m py_compile server.py && echo OK`
Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add server.py
git commit -m "Port history archiving and report helpers to legacy server.py

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: server.py history routes, HTML report views, dashboard button

**Files:**
- Modify: `server.py` (`DASHBOARD_CSS` before its `@media` block; new render functions near `render_missing_analysis_page`; new routes after `get_analysis`; rewrite `get_report`; dashboard row buttons ~line 1069)

**Interfaces:**
- Consumes (Task 4): all helpers listed there; existing `wants_html`, `safe`, `DASHBOARD_CSS`, `render_missing_analysis_page` (untouched), `HTMLResponse`, `PlainTextResponse`, `HTTPException`.
- Produces: `GET /history/{host}`, `GET /history/{host}/{stamp}`, HTML-wrapped `GET /report/{host}`; `render_message_page`, `render_report_page`, `render_history_page`, `build_history_entries` — all mirroring the Go names and markup exactly.

- [ ] **Step 1: Add the CSS**

In `DASHBOARD_CSS`, insert immediately before the `@media (max-width: 760px) {` block (same block as Go):

```css
.report-pre {
  margin: 0;
  padding: 16px;
  overflow-x: auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.5;
  white-space: pre;
}
```

- [ ] **Step 2: Add the render functions**

Add to `server.py` after `render_missing_analysis_page`:

```python
def render_message_page(title: str, message: str, actions_html: str) -> str:
    safe_title = html.escape(title)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{safe_title}</title>
  <style>{DASHBOARD_CSS}</style>
</head>
<body>
  <main class="shell">
    <a class="back-link" href="/">Back to dashboard</a>
    <section class="empty-panel">
      <h2>{safe_title}</h2>
      <p>{html.escape(message)}</p>
      <div class="actions" style="justify-content:center">{actions_html}</div>
    </section>
  </main>
</body>
</html>"""


def render_report_page(host: str, date_label: str, text: str, raw_href: str) -> str:
    host_id = html.escape(safe(host))
    display_host = html.escape(host)
    lines = count_lines(text)
    plural = "" if lines == 1 else "s"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Report - {display_host}</title>
  <style>{DASHBOARD_CSS}</style>
</head>
<body>
  <main class="shell">
    <header class="topbar analysis-top">
      <div>
        <a class="back-link" href="/history/{host_id}">Back to history</a>
        <p class="eyebrow">Raw Report</p>
        <h1>Report: {display_host}</h1>
      </div>
      <div class="runtime" aria-label="Report links">
        <a class="button" href="/">Dashboard</a>
        <a class="button" href="{html.escape(raw_href)}">Plain text</a>
        <a class="button" href="/history/{host_id}">History</a>
        <a class="button" href="/analysis/{host_id}">Analysis</a>
      </div>
    </header>
    <section class="table-panel" aria-label="Decoded report">
      <div class="table-heading">
        <h2>{html.escape(date_label)}</h2>
        <span>{lines} line{plural}</span>
      </div>
      <pre class="report-pre">{html.escape(text)}</pre>
    </section>
  </main>
</body>
</html>"""


def build_history_entries(host: str, stamps: list) -> list:
    host_id = safe(host)
    entries = []
    current = report_path(host)
    if current.exists():
        try:
            payload = json.loads(current.read_text())
            entries.append({
                "date": format_received(payload.get("_received", "?")),
                "badge": "Current",
                "href": f"/report/{host_id}",
                "lines": count_report_lines(payload),
                "readable": True,
            })
        except ValueError:
            entries.append({
                "date": "current report",
                "badge": "Current",
                "href": f"/report/{host_id}",
                "lines": 0,
                "readable": False,
            })
    for stamp in reversed(stamps):
        entry = {
            "date": format_stamp(stamp),
            "badge": "",
            "href": f"/history/{host_id}/{stamp}",
            "lines": 0,
            "readable": False,
        }
        try:
            payload = json.loads(history_report_path(host, stamp).read_text())
            entry["lines"] = count_report_lines(payload)
            entry["readable"] = True
        except (OSError, ValueError):
            pass
        entries.append(entry)
    return entries


def render_history_page(host: str, entries: list) -> str:
    display_host = html.escape(host)
    host_id = html.escape(safe(host))
    rows = []
    for entry in entries:
        badge = ""
        if entry["badge"]:
            badge = f" <span class='badge ok'>{html.escape(entry['badge'])}</span>"
        lines_text = str(entry["lines"]) if entry["readable"] else "unreadable"
        rows.append(
            f"<tr><td>{html.escape(entry['date'])}{badge}</td>"
            f"<td>{html.escape(lines_text)}</td>"
            f"<td><div class='actions'><a class='button' href='{entry['href']}'>View report</a></div></td></tr>"
        )
    body = "".join(rows)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>History - {display_host}</title>
  <style>{DASHBOARD_CSS}</style>
</head>
<body>
  <main class="shell">
    <header class="topbar analysis-top">
      <div>
        <a class="back-link" href="/">Back to dashboard</a>
        <p class="eyebrow">Report Archive</p>
        <h1>History: {display_host}</h1>
      </div>
      <div class="runtime" aria-label="History links">
        <a class="button" href="/report/{host_id}">Current Report</a>
        <a class="button" href="/analysis/{host_id}">Analysis</a>
      </div>
    </header>
    <section class="table-panel" aria-label="Stored reports">
      <div class="table-heading">
        <h2>Stored Reports</h2>
        <span>{len(entries)} total</span>
      </div>
      <div class="table-scroll">
        <table>
          <thead>
            <tr><th>Date</th><th>Lines</th><th>Actions</th></tr>
          </thead>
          <tbody>{body}</tbody>
        </table>
      </div>
    </section>
  </main>
</body>
</html>"""
```

- [ ] **Step 3: Add the history routes and rewrite `get_report`**

Replace the whole `get_report` function with, and add the two history routes directly below it:

```python
@app.get("/report/{host}")
def get_report(host: str, request: Request, raw: str = ""):
    p = report_path(host)
    if not p.exists():
        logger.warning("report not found host=%s path=%s", host, p)
        raise HTTPException(404, "no report")
    try:
        payload = json.loads(p.read_text())
    except ValueError:
        logger.warning("report unreadable host=%s path=%s", host, p)
        if wants_html(request) and not raw:
            return HTMLResponse(render_message_page(
                f"Report unreadable: {host}",
                "The stored report file exists but is not valid JSON.",
                "<a class='button' href='/'>Back to Dashboard</a>",
            ))
        return PlainTextResponse("report exists but is not valid JSON")
    logger.info("served report host=%s path=%s", host, p)
    text = format_decoded_report(payload)
    if raw or not wants_html(request):
        return PlainTextResponse(text)
    date_label = "Current report - " + format_received(payload.get("_received", "?"))
    return HTMLResponse(render_report_page(host, date_label, text, f"/report/{safe(host)}?raw=1"))


@app.get("/history/{host}")
def get_history(host: str, request: Request):
    stamps = list_history_stamps(host)
    if not stamps:
        if not wants_html(request):
            return PlainTextResponse(f"no report history yet for {host}")
        actions = "<a class='button' href='/'>Back to Dashboard</a>"
        if report_path(host).exists():
            actions = (
                f"<a class='button' href='/report/{html.escape(safe(host))}'>View Current Report</a> "
                + actions
            )
        return HTMLResponse(render_message_page(
            f"No history for {host}",
            "No history snapshots have been stored for this host yet. "
            "Snapshots are archived every time the agent submits a report.",
            actions,
        ))
    if not wants_html(request):
        return PlainTextResponse("\n".join(stamps))
    return HTMLResponse(render_history_page(host, build_history_entries(host, stamps)))


@app.get("/history/{host}/{stamp}")
def get_history_entry(host: str, stamp: str, request: Request, raw: str = ""):
    path = history_report_path(host, stamp)
    if not path.exists():
        logger.warning("history entry not found host=%s stamp=%s", host, stamp)
        raise HTTPException(404, "no history entry")
    try:
        payload = json.loads(path.read_text())
    except ValueError:
        logger.warning("history entry unreadable host=%s stamp=%s", host, stamp)
        if wants_html(request) and not raw:
            return HTMLResponse(render_message_page(
                "Snapshot unreadable",
                "This history snapshot exists but is not valid JSON.",
                f"<a class='button' href='/history/{html.escape(safe(host))}'>Back to History</a>",
            ))
        return PlainTextResponse("history entry exists but is not valid JSON")
    logger.info("served history entry host=%s stamp=%s", host, stamp)
    text = format_decoded_report(payload)
    if raw or not wants_html(request):
        return PlainTextResponse(text)
    date_label = "Snapshot - " + format_stamp(safe(stamp))
    return HTMLResponse(render_report_page(host, date_label, text, f"/history/{safe(host)}/{safe(stamp)}?raw=1"))
```

Note: the old `get_report` used `response_class=PlainTextResponse` in the decorator — the new one must NOT have it (responses are built explicitly).

- [ ] **Step 4: Add the History button to the dashboard rows**

In `dashboard()`, in the actions cell, add between the Report and Analysis links:

```python
            f"<a class='button' href='/history/{host_id}'>History</a>"
```

- [ ] **Step 5: Verify it compiles**

Run: `python3 -m py_compile server.py && echo OK`
Expected: `OK`

- [ ] **Step 6: Manual smoke test (only if fastapi/uvicorn are installed; skip otherwise and note it)**

```bash
cd /Users/tess/github/ccdc-agent
python3 -c "import fastapi, uvicorn" 2>/dev/null || { echo "fastapi not installed - skipping smoke test"; exit 0; }
HARDEN_DATA=$(mktemp -d) HARDEN_TOKEN=ccdcagent2026 python3 -m uvicorn server:app --port 8001 &
sleep 2
curl -s -X POST localhost:8001/report -H 'X-Auth-Token: ccdcagent2026' -H 'Content-Type: application/json' \
  -d "{\"hostname\":\"pytest01\",\"collected_as\":\"root\",\"timestamp\":\"t\",\"checks\":{\"system\":\"$(printf 'kernel info' | base64)\"}}"
curl -s localhost:8001/history/pytest01                                   # expect: one stamp, plain text
curl -s -H 'Accept: text/html' localhost:8001/history/pytest01 | grep -c "View report"   # expect: 2 (Current + snapshot)
curl -s -H 'Accept: text/html' localhost:8001/report/pytest01 | grep -c "report-pre"     # expect: >= 1
curl -s 'localhost:8001/report/pytest01?raw=1'                            # expect: ===== SYSTEM ===== \n kernel info
kill %1
```

- [ ] **Step 7: Commit**

```bash
git add server.py
git commit -m "Add history routes, summary table, and HTML report views to server.py

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Self-Review Notes

- Spec coverage: summary table (Task 3 Go, Task 5 Python), readable dates for both stamp and `_received` sources (Task 1/4), HTML raw views with `?raw=1` passthrough (Task 2/5), proper empty-history page replacing the misused analysis-pending page (Task 3/5), corrupt-JSON rows show `unreadable` and corrupt raw views return a legible message instead of a 500 (Tasks 2, 3, 5), history archiving ported to server.py (Task 4), dashboard History button in server.py (Task 5).
- Naming is mirrored across servers: `formatStamp`/`format_stamp`, `countReportLines`/`count_report_lines`, `renderReportPage`/`render_report_page`, `renderMessagePage`/`render_message_page`, `buildHistoryEntries`/`build_history_entries`, `renderHistoryPage`/`render_history_page`.
- The spec's Spanish UI labels are rendered in English per Global Constraints (existing UI is entirely English).

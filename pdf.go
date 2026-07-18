package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	pdfPageWidth        = 612.0
	pdfPageHeight       = 792.0
	pdfContentLeft      = 42.0
	pdfContentRight     = 570.0
	pdfContentTop       = 684.0
	pdfContentBottom    = 54.0
	pdfMaxAnalysisBytes = 512 << 10
)

type pdfColor struct {
	r float64
	g float64
	b float64
}

var (
	pdfNavy         = pdfColor{0.031, 0.043, 0.063}
	pdfPanel        = pdfColor{0.067, 0.086, 0.118}
	pdfPaper        = pdfColor{0.969, 0.976, 0.984}
	pdfCard         = pdfColor{1, 1, 1}
	pdfSoft         = pdfColor{0.925, 0.945, 0.965}
	pdfInk          = pdfColor{0.067, 0.086, 0.118}
	pdfMuted        = pdfColor{0.36, 0.42, 0.50}
	pdfLine         = pdfColor{0.80, 0.84, 0.89}
	pdfWhite        = pdfColor{0.957, 0.969, 0.980}
	pdfAccent       = pdfColor{0.345, 0.784, 0.961}
	pdfPurple       = pdfColor{0.655, 0.545, 0.980}
	pdfSuccess      = pdfColor{0.384, 0.831, 0.612}
	pdfWarning      = pdfColor{0.961, 0.741, 0.337}
	pdfDanger       = pdfColor{1.000, 0.455, 0.498}
	pdfTextReplacer = strings.NewReplacer(
		"\u00a0", " ",
		"\u2010", "-",
		"\u2011", "-",
		"\u2012", "-",
		"\u2013", "-",
		"\u2014", "-",
		"\u2015", "-",
		"\u2018", "'",
		"\u2019", "'",
		"\u201c", "\"",
		"\u201d", "\"",
		"\u2026", "...",
		"\u2022", "-",
	)
)

type analysisPDFData struct {
	title       string
	host        string
	body        string
	generatedAt time.Time
	analyzedAt  time.Time
	status      string
	provider    string
	model       string
	collectedAs string
	collectedAt string
}

type pdfCanvas struct {
	commands bytes.Buffer
}

type analysisPDFLayout struct {
	pages          []*pdfCanvas
	page           *pdfCanvas
	y              float64
	currentSection string
	sectionColor   pdfColor
}

func (a *app) writePDFDownload(w http.ResponseWriter, host, text string) {
	metadata := loadReportMetadata(a, host)
	displayHost := valueOr(metadata["host"], host)
	reportModTime := time.Time{}
	if info, err := os.Stat(a.reportPath(host)); err == nil {
		reportModTime = info.ModTime()
	}
	analysisTime := time.Time{}
	if info, err := os.Stat(a.analysisPath(host)); err == nil {
		analysisTime = info.ModTime().UTC()
	}
	status := map[string]string{
		"ready":   "Current",
		"stale":   "Stale",
		"failed":  "Failed",
		"pending": "Pending",
	}[a.analysisState(host, reportModTime)]
	provider := selectProvider()
	data := analysisPDFData{
		title:       "CCDC Hardening Analysis: " + displayHost,
		host:        displayHost,
		body:        text,
		generatedAt: a.now().UTC(),
		analyzedAt:  analysisTime,
		status:      valueOr(status, "Unknown"),
		provider:    provider,
		model:       modelFor(provider),
		collectedAs: valueOr(metadata["collected_as"], "Unknown"),
		collectedAt: valueOr(metadata["timestamp"], "Unknown"),
	}
	pdfBytes := generateAnalysisPDF(data)
	filename := safe(host) + "-analysis.pdf"
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(pdfBytes)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdfBytes)
}

func generateAnalysisPDF(data analysisPDFData) []byte {
	if data.generatedAt.IsZero() {
		data.generatedAt = time.Now().UTC()
	}
	data.generatedAt = data.generatedAt.UTC()
	if data.title == "" {
		data.title = "CCDC Hardening Analysis"
	}
	if data.host == "" {
		data.host = "Unknown host"
	}

	body, truncated := limitPDFAnalysis(data.body, pdfMaxAnalysisBytes)
	sections := splitAnalysisSections(body)
	contentSections := make([]analysisSection, 0, len(sections)+1)
	for _, section := range sections {
		if section.title != "HARDENING SCORE" {
			contentSections = append(contentSections, section)
		}
	}
	if len(contentSections) == 0 {
		contentSections = sections
	}
	if truncated {
		contentSections = append(contentSections, analysisSection{
			title: "EXPORT NOTICE",
			lines: []string{"The saved analysis exceeded the PDF safety limit. This export contains the first 512 KiB."},
		})
	}

	layout := &analysisPDFLayout{}
	layout.newPage()
	layout.addExecutiveSummary(data, body, len(contentSections))
	for index, section := range contentSections {
		layout.addSection(index+1, section)
	}
	return assembleAnalysisPDF(layout.pages, data)
}

func limitPDFAnalysis(text string, limit int) (string, bool) {
	if limit <= 0 || len(text) <= limit {
		return text, false
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut], true
}

func (l *analysisPDFLayout) newPage() {
	l.page = &pdfCanvas{}
	l.pages = append(l.pages, l.page)
	l.y = pdfContentTop
	if l.currentSection != "" {
		l.page.text(pdfContentLeft, l.y, 8, "F2", l.sectionColor, "CONTINUED")
		l.y -= 18
		l.page.text(pdfContentLeft, l.y, 11, "F2", pdfInk, l.currentSection)
		l.y -= 28
	}
}

func (l *analysisPDFLayout) ensureSpace(height float64) {
	if l.y-height < pdfContentBottom {
		l.newPage()
	}
}

func (l *analysisPDFLayout) addExecutiveSummary(data analysisPDFData, body string, sectionCount int) {
	l.page.text(pdfContentLeft, l.y, 9, "F2", pdfAccent, "SECURITY POSTURE")
	l.y -= 29
	titleLines := wrapPDFText(data.host, pdfContentRight-pdfContentLeft, 24, "F2")
	if len(titleLines) > 2 {
		titleLines = titleLines[:2]
		titleLines[1] = pdfEllipsize(titleLines[1], pdfContentRight-pdfContentLeft, 24, "F2")
	}
	for _, line := range titleLines {
		l.page.text(pdfContentLeft, l.y, 24, "F2", pdfInk, line)
		l.y -= 28
	}
	l.page.text(pdfContentLeft, l.y+4, 9, "F1", pdfMuted, "Operational hardening analysis and prioritized response plan")
	l.y -= 23

	cardTop := l.y
	cardHeight := 118.0
	scoreWidth := 146.0
	summaryX := pdfContentLeft + scoreWidth + 12
	summaryWidth := pdfContentRight - summaryX
	score := extractScore(body)
	statusClass, statusLabel := scoreStatus(score, body)
	statusColor := pdfColorForStatus(statusClass)

	l.page.card(pdfContentLeft, cardTop-cardHeight, scoreWidth, cardHeight, 8, pdfNavy, pdfNavy)
	l.page.fillRect(pdfContentLeft, cardTop-4, scoreWidth, 4, statusColor)
	l.page.text(pdfContentLeft+14, cardTop-21, 7.5, "F2", pdfAccent, "HARDENING SCORE")
	centerX := pdfContentLeft + scoreWidth/2
	centerY := cardTop - 63
	l.page.circleStroke(centerX, centerY, 28, statusColor, 3)
	scoreText := "--"
	if score != nil {
		scoreText = strconv.Itoa(*score)
	}
	l.page.textCentered(centerX, centerY-6, 23, "F2", pdfWhite, scoreText)
	l.page.textCentered(centerX, centerY-19, 7, "F1", pdfMuted, "/ 100")
	l.page.textCentered(centerX, cardTop-cardHeight+12, 8.5, "F2", statusColor, statusLabel)

	l.page.card(summaryX, cardTop-cardHeight, summaryWidth, cardHeight, 8, pdfCard, pdfLine)
	l.page.text(summaryX+14, cardTop-21, 7.5, "F2", pdfPurple, "EXECUTIVE SUMMARY")
	summaryLines := wrapPDFText(scoreSummary(body), summaryWidth-28, 9.5, "F1")
	if len(summaryLines) > 5 {
		summaryLines = summaryLines[:5]
		summaryLines[4] = pdfEllipsize(summaryLines[4]+"...", summaryWidth-28, 9.5, "F1")
	}
	lineY := cardTop - 42
	for _, line := range summaryLines {
		l.page.text(summaryX+14, lineY, 9.5, "F1", pdfInk, line)
		lineY -= 13
	}
	l.page.text(summaryX+14, cardTop-cardHeight+12, 7.5, "F2", pdfMuted, fmt.Sprintf("%d STRUCTURED SECTIONS", sectionCount))
	l.y = cardTop - cardHeight - 14

	metaGap := 9.0
	metaWidth := (pdfContentRight - pdfContentLeft - 2*metaGap) / 3
	metaHeight := 49.0
	meta := [][2]string{
		{"COLLECTED AS", valueOr(data.collectedAs, "Unknown")},
		{"COLLECTED", valueOr(data.collectedAt, "Unknown")},
		{"ANALYZED", pdfTimeLabel(data.analyzedAt)},
	}
	for index, pair := range meta {
		x := pdfContentLeft + float64(index)*(metaWidth+metaGap)
		l.page.card(x, l.y-metaHeight, metaWidth, metaHeight, 6, pdfCard, pdfLine)
		l.page.text(x+11, l.y-16, 7, "F2", pdfMuted, pair[0])
		l.page.text(x+11, l.y-34, 8.5, "F2", pdfInk, pdfEllipsize(pair[1], metaWidth-22, 8.5, "F2"))
	}
	l.y -= metaHeight + 20
}

func (l *analysisPDFLayout) addSection(index int, section analysisSection) {
	label := pdfSectionLabel(section.title)
	color := pdfSectionColor(section.title, index)
	l.currentSection = ""
	l.ensureSpace(70)
	l.currentSection = label
	l.sectionColor = color

	top := l.y
	height := 39.0
	l.page.card(pdfContentLeft, top-height, pdfContentRight-pdfContentLeft, height, 6, pdfPanel, pdfPanel)
	l.page.fillRect(pdfContentLeft, top-height, 4, height, color)
	l.page.circleFill(pdfContentLeft+24, top-height/2, 11, color)
	l.page.textCentered(pdfContentLeft+24, top-height/2-3.2, 8, "F2", pdfNavy, strconv.Itoa(index))
	l.page.text(pdfContentLeft+44, top-25, 11, "F2", pdfWhite, label)
	count := sectionItemCount(section.lines)
	countLabel := "DETAILS"
	if count > 0 {
		countLabel = fmt.Sprintf("%d ITEMS", count)
	}
	l.page.textRight(pdfContentRight-14, top-24, 7, "F2", pdfMuted, countLabel)
	l.y = top - height - 12
	l.addSectionLines(section.lines, color)
	l.y -= 8
	l.currentSection = ""
}

func (l *analysisPDFLayout) addSectionLines(lines []string, color pdfColor) {
	number := 0
	for index := 0; index < len(lines); {
		raw := strings.TrimSpace(lines[index])
		if raw == "" {
			l.y -= 5
			index++
			continue
		}
		if strings.HasPrefix(raw, "```") {
			index++
			var code []string
			for index < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[index]), "```") {
				code = append(code, lines[index])
				index++
			}
			if index < len(lines) {
				index++
			}
			l.addCodeBlock(code, color)
			continue
		}
		if isTableLine(raw) || isTableSeparator(raw) {
			var table []string
			for index < len(lines) && (isTableLine(lines[index]) || isTableSeparator(lines[index])) {
				table = append(table, lines[index])
				index++
			}
			l.addTable(table, color)
			continue
		}
		if match := bulletRE.FindStringSubmatch(raw); len(match) == 2 {
			l.addItem("", match[1], color)
			index++
			continue
		}
		if match := numberedItemRE.FindStringSubmatch(raw); len(match) == 2 {
			number++
			l.addItem(strconv.Itoa(number), match[1], color)
			index++
			continue
		}
		if strings.HasPrefix(raw, "#") {
			l.addSubheading(stripAnalysisMarkup(raw), color)
			index++
			continue
		}
		var paragraph []string
		for index < len(lines) {
			candidate := strings.TrimSpace(lines[index])
			if candidate == "" || strings.HasPrefix(candidate, "```") || isTableLine(candidate) || isTableSeparator(candidate) || bulletRE.MatchString(candidate) || numberedItemRE.MatchString(candidate) || strings.HasPrefix(candidate, "#") {
				break
			}
			paragraph = append(paragraph, stripAnalysisMarkup(candidate))
			index++
		}
		text := strings.TrimSpace(strings.Join(paragraph, " "))
		if strings.HasPrefix(text, "[analyzer]") {
			l.addCallout(text, pdfDanger)
		} else {
			l.addParagraph(text)
		}
	}
}

func (l *analysisPDFLayout) addSubheading(text string, color pdfColor) {
	if text == "" {
		return
	}
	l.ensureSpace(28)
	l.page.text(pdfContentLeft+4, l.y, 9.5, "F2", color, text)
	l.y -= 20
}

func (l *analysisPDFLayout) addParagraph(text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	lines := wrapPDFText(text, pdfContentRight-pdfContentLeft-8, 9.4, "F1")
	if len(lines) <= 4 {
		l.ensureSpace(float64(len(lines))*13 + 4)
	}
	for _, line := range lines {
		l.ensureSpace(15)
		l.page.text(pdfContentLeft+4, l.y, 9.4, "F1", pdfInk, line)
		l.y -= 13
	}
	l.y -= 5
}

func (l *analysisPDFLayout) addItem(number, text string, color pdfColor) {
	text = stripAnalysisMarkup(text)
	lines := wrapPDFText(text, pdfContentRight-pdfContentLeft-48, 9.1, "F1")
	if len(lines) == 0 {
		return
	}
	for len(lines) > 0 {
		take := len(lines)
		if take > 14 {
			take = 14
		}
		chunk := lines[:take]
		lines = lines[take:]
		height := float64(len(chunk))*12.2 + 16
		l.ensureSpace(height + 5)
		top := l.y
		l.page.card(pdfContentLeft, top-height, pdfContentRight-pdfContentLeft, height, 5, pdfCard, pdfLine)
		markerX := pdfContentLeft + 18
		markerY := top - 18
		if number == "" {
			l.page.circleFill(markerX, markerY+1, 3.2, color)
		} else {
			l.page.circleFill(markerX, markerY+1, 8.5, color)
			l.page.textCentered(markerX, markerY-1.8, 7, "F2", pdfNavy, number)
		}
		textY := top - 20
		for _, line := range chunk {
			l.page.text(pdfContentLeft+34, textY, 9.1, "F1", pdfInk, line)
			textY -= 12.2
		}
		l.y = top - height - 5
		number = ""
	}
}

func (l *analysisPDFLayout) addCallout(text string, color pdfColor) {
	lines := wrapPDFText(stripAnalysisMarkup(text), pdfContentRight-pdfContentLeft-32, 9.2, "F2")
	if len(lines) == 0 {
		return
	}
	for len(lines) > 0 {
		take := len(lines)
		if take > 24 {
			take = 24
		}
		chunk := lines[:take]
		lines = lines[take:]
		height := float64(len(chunk))*12.5 + 18
		l.ensureSpace(height + 6)
		top := l.y
		l.page.card(pdfContentLeft, top-height, pdfContentRight-pdfContentLeft, height, 5, pdfCard, color)
		l.page.fillRect(pdfContentLeft, top-height, 4, height, color)
		textY := top - 20
		for _, line := range chunk {
			l.page.text(pdfContentLeft+17, textY, 9.2, "F2", pdfInk, line)
			textY -= 12.5
		}
		l.y = top - height - 7
	}
}

func (l *analysisPDFLayout) addCodeBlock(rawLines []string, color pdfColor) {
	var lines []string
	for _, raw := range rawLines {
		wrapped := wrapPDFCodeLine(raw, pdfContentRight-pdfContentLeft-30, 8.1)
		if len(wrapped) == 0 {
			wrapped = []string{" "}
		}
		lines = append(lines, wrapped...)
	}
	if len(lines) == 0 {
		return
	}
	for len(lines) > 0 {
		take := len(lines)
		if take > 28 {
			take = 28
		}
		chunk := lines[:take]
		lines = lines[take:]
		height := float64(len(chunk))*10.5 + 17
		l.ensureSpace(height + 7)
		top := l.y
		l.page.card(pdfContentLeft, top-height, pdfContentRight-pdfContentLeft, height, 5, pdfNavy, pdfNavy)
		l.page.fillRect(pdfContentLeft, top-height, 3, height, color)
		textY := top - 15
		for _, line := range chunk {
			l.page.text(pdfContentLeft+13, textY, 8.1, "F3", pdfWhite, line)
			textY -= 10.5
		}
		l.y = top - height - 7
	}
}

func (l *analysisPDFLayout) addTable(rawLines []string, color pdfColor) {
	var rows [][]string
	hasHeader := len(rawLines) > 1 && isTableSeparator(rawLines[1])
	maxColumns := 0
	for _, raw := range rawLines {
		if isTableSeparator(raw) {
			continue
		}
		cells := tableCells(raw)
		if len(cells) == 0 {
			continue
		}
		rows = append(rows, cells)
		if len(cells) > maxColumns {
			maxColumns = len(cells)
		}
	}
	if len(rows) == 0 {
		return
	}
	if maxColumns > 5 {
		l.addCodeBlock(rawLines, color)
		return
	}
	width := pdfContentRight - pdfContentLeft
	columnWidth := width / float64(maxColumns)
	for rowIndex, row := range rows {
		wrapped := make([][]string, maxColumns)
		maxLines := 1
		for column := 0; column < maxColumns; column++ {
			value := ""
			if column < len(row) {
				value = stripAnalysisMarkup(row[column])
			}
			wrapped[column] = wrapPDFText(value, columnWidth-14, 7.5, "F1")
			if len(wrapped[column]) == 0 {
				wrapped[column] = []string{""}
			}
			if len(wrapped[column]) > maxLines {
				maxLines = len(wrapped[column])
			}
		}
		if maxLines > 12 {
			l.addCodeBlock(rawLines, color)
			return
		}
		rowHeight := float64(maxLines)*10 + 14
		l.ensureSpace(rowHeight)
		top := l.y
		fill := pdfCard
		textColor := pdfInk
		font := "F1"
		if hasHeader && rowIndex == 0 {
			fill = pdfPanel
			textColor = pdfWhite
			font = "F2"
		} else if rowIndex%2 == 0 {
			fill = pdfSoft
		}
		l.page.fillRect(pdfContentLeft, top-rowHeight, width, rowHeight, fill)
		l.page.strokeRect(pdfContentLeft, top-rowHeight, width, rowHeight, pdfLine, 0.7)
		for column := 0; column < maxColumns; column++ {
			x := pdfContentLeft + float64(column)*columnWidth
			if column > 0 {
				l.page.line(x, top-rowHeight, x, top, pdfLine, 0.6)
			}
			textY := top - 13
			for _, line := range wrapped[column] {
				l.page.text(x+7, textY, 7.5, font, textColor, line)
				textY -= 10
			}
		}
		l.y = top - rowHeight
	}
	l.y -= 10
}

func assembleAnalysisPDF(pages []*pdfCanvas, data analysisPDFData) []byte {
	if len(pages) == 0 {
		pages = []*pdfCanvas{{}}
	}
	const catalogObject = 1
	const pagesObject = 2
	const regularFontObject = 3
	const boldFontObject = 4
	const monoFontObject = 5
	const infoObject = 6
	pageObjectNumbers := make([]int, len(pages))
	contentObjectNumbers := make([]int, len(pages))
	for index := range pages {
		pageObjectNumbers[index] = 7 + index*2
		contentObjectNumbers[index] = 8 + index*2
	}
	totalObjects := 6 + len(pages)*2

	var output bytes.Buffer
	offsets := make([]int, totalObjects+1)
	record := func(number int) {
		offsets[number] = output.Len()
	}
	output.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

	record(catalogObject)
	fmt.Fprintf(&output, "%d 0 obj\n<< /Type /Catalog /Pages %d 0 R >>\nendobj\n", catalogObject, pagesObject)
	record(pagesObject)
	fmt.Fprintf(&output, "%d 0 obj\n<< /Type /Pages /Kids [", pagesObject)
	for index, number := range pageObjectNumbers {
		if index > 0 {
			output.WriteByte(' ')
		}
		fmt.Fprintf(&output, "%d 0 R", number)
	}
	fmt.Fprintf(&output, "] /Count %d >>\nendobj\n", len(pages))

	record(regularFontObject)
	fmt.Fprintf(&output, "%d 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n", regularFontObject)
	record(boldFontObject)
	fmt.Fprintf(&output, "%d 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\nendobj\n", boldFontObject)
	record(monoFontObject)
	fmt.Fprintf(&output, "%d 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>\nendobj\n", monoFontObject)
	record(infoObject)
	fmt.Fprintf(&output,
		"%d 0 obj\n<< /Title (%s) /Creator (CCDC Hardening Tracker) /Producer (CCDC Go PDF Engine) /CreationDate (%s) >>\nendobj\n",
		infoObject,
		pdfEscape(data.title),
		data.generatedAt.Format("D:20060102150405Z"),
	)

	for index, page := range pages {
		pageObject := pageObjectNumbers[index]
		contentObject := contentObjectNumbers[index]
		content := styledPDFPage(page, index+1, len(pages), data)

		record(pageObject)
		fmt.Fprintf(&output,
			"%d 0 obj\n<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.0f %.0f] /Resources << /ProcSet [/PDF /Text] /Font << /F1 %d 0 R /F2 %d 0 R /F3 %d 0 R >> >> /Contents %d 0 R >>\nendobj\n",
			pageObject, pagesObject, pdfPageWidth, pdfPageHeight, regularFontObject, boldFontObject, monoFontObject, contentObject,
		)
		record(contentObject)
		fmt.Fprintf(&output, "%d 0 obj\n<< /Length %d >>\nstream\n", contentObject, len(content))
		output.Write(content)
		output.WriteString("\nendstream\nendobj\n")
	}

	xrefStart := output.Len()
	fmt.Fprintf(&output, "xref\n0 %d\n", totalObjects+1)
	output.WriteString("0000000000 65535 f \n")
	for number := 1; number <= totalObjects; number++ {
		fmt.Fprintf(&output, "%010d 00000 n \n", offsets[number])
	}
	fmt.Fprintf(&output,
		"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		totalObjects+1, catalogObject, infoObject, xrefStart,
	)
	return output.Bytes()
}

func styledPDFPage(body *pdfCanvas, pageNumber, totalPages int, data analysisPDFData) []byte {
	canvas := &pdfCanvas{}
	canvas.fillRect(0, 0, pdfPageWidth, pdfPageHeight, pdfPaper)
	canvas.fillRect(0, 714, pdfPageWidth, 78, pdfNavy)
	canvas.fillRect(0, 788, pdfPageWidth/2, 4, pdfAccent)
	canvas.fillRect(pdfPageWidth/2, 788, pdfPageWidth/2, 4, pdfPurple)
	canvas.text(pdfContentLeft, 765, 7.5, "F2", pdfAccent, "CCDC HARDENING TRACKER")
	canvas.text(pdfContentLeft, 740, 13, "F2", pdfWhite, pdfEllipsize(data.host, 350, 13, "F2"))
	statusColor := pdfColorForStatus(strings.ToLower(data.status))
	canvas.card(480, 742, 90, 24, 12, statusColor, statusColor)
	canvas.textCentered(525, 750, 7.5, "F2", pdfNavy, strings.ToUpper(valueOr(data.status, "UNKNOWN")))

	canvas.line(pdfContentLeft, 39, pdfContentRight, 39, pdfLine, 0.8)
	footer := fmt.Sprintf("Exported %s / %s / %s", data.generatedAt.Format("2006-01-02 15:04 UTC"), valueOr(data.provider, "provider unknown"), valueOr(data.model, "model unknown"))
	canvas.text(pdfContentLeft, 23, 7, "F1", pdfMuted, pdfEllipsize(footer, 420, 7, "F1"))
	canvas.textRight(pdfContentRight, 23, 7, "F2", pdfMuted, fmt.Sprintf("PAGE %d OF %d", pageNumber, totalPages))
	canvas.commands.Write(body.commands.Bytes())
	return canvas.commands.Bytes()
}

func pdfSectionLabel(title string) string {
	if label := analysisSectionLabels[title]; label != "" {
		return label
	}
	words := strings.Fields(strings.ToLower(strings.ReplaceAll(title, "_", " ")))
	for index := range words {
		runes := []rune(words[index])
		if len(runes) > 0 {
			runes[0] = unicode.ToUpper(runes[0])
			words[index] = string(runes)
		}
	}
	if len(words) == 0 {
		return "Analysis Output"
	}
	return strings.Join(words, " ")
}

func pdfSectionColor(title string, index int) pdfColor {
	switch title {
	case "PROBABLE COMPROMISE / RED-TEAM ARTIFACTS":
		return pdfDanger
	case "HARDENING GAPS":
		return pdfWarning
	case "SUSPICIOUS PROCESSES / SERVICES / TASKS":
		return pdfPurple
	case "DO-NOW CHECKLIST":
		return pdfSuccess
	case "EXPORT NOTICE":
		return pdfWarning
	}
	colors := []pdfColor{pdfAccent, pdfPurple, pdfSuccess, pdfWarning}
	return colors[(index-1)%len(colors)]
}

func pdfColorForStatus(status string) pdfColor {
	switch strings.ToLower(status) {
	case "ok", "strong", "ready", "current":
		return pdfSuccess
	case "warn", "needs work", "stale", "pending":
		return pdfWarning
	case "danger", "critical", "failed", "analyzer error":
		return pdfDanger
	default:
		return pdfAccent
	}
}

func pdfTimeLabel(value time.Time) string {
	if value.IsZero() {
		return "Unknown"
	}
	return value.UTC().Format("2006-01-02 15:04 UTC")
}

func wrapPDFText(text string, maxWidth, fontSize float64, font string) []string {
	text = pdfNormalizeText(strings.TrimSpace(text))
	if text == "" {
		return nil
	}
	words := strings.Fields(text)
	var lines []string
	current := ""
	for _, word := range words {
		parts := splitPDFWord(word, maxWidth, fontSize, font)
		for _, part := range parts {
			candidate := part
			if current != "" {
				candidate = current + " " + part
			}
			if current != "" && pdfTextWidth(candidate, fontSize, font) > maxWidth {
				lines = append(lines, current)
				current = part
			} else {
				current = candidate
			}
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func splitPDFWord(word string, maxWidth, fontSize float64, font string) []string {
	if pdfTextWidth(word, fontSize, font) <= maxWidth {
		return []string{word}
	}
	var parts []string
	current := ""
	for _, r := range word {
		candidate := current + string(r)
		if current != "" && pdfTextWidth(candidate, fontSize, font) > maxWidth {
			parts = append(parts, current)
			current = string(r)
		} else {
			current = candidate
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func wrapPDFCodeLine(text string, maxWidth, fontSize float64) []string {
	text = strings.ReplaceAll(pdfNormalizeText(text), "\t", "    ")
	if text == "" {
		return nil
	}
	var lines []string
	current := ""
	for _, r := range text {
		candidate := current + string(r)
		if current != "" && pdfTextWidth(candidate, fontSize, "F3") > maxWidth {
			lines = append(lines, current)
			current = string(r)
		} else {
			current = candidate
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func pdfEllipsize(text string, maxWidth, fontSize float64, font string) string {
	text = pdfNormalizeText(text)
	if pdfTextWidth(text, fontSize, font) <= maxWidth {
		return text
	}
	suffix := "..."
	var out []rune
	for _, r := range text {
		candidate := string(append(out, r)) + suffix
		if pdfTextWidth(candidate, fontSize, font) > maxWidth {
			break
		}
		out = append(out, r)
	}
	return strings.TrimSpace(string(out)) + suffix
}

func pdfTextWidth(text string, fontSize float64, font string) float64 {
	width := 0.0
	for _, r := range pdfNormalizeText(text) {
		factor := 0.52
		switch {
		case font == "F3":
			factor = 0.60
		case r == ' ':
			factor = 0.278
		case strings.ContainsRune("ilI.,'`:;!|", r):
			factor = 0.24
		case strings.ContainsRune("MW@%&", r):
			factor = 0.82
		case unicode.IsUpper(r):
			factor = 0.62
		case unicode.IsDigit(r):
			factor = 0.56
		case !unicode.IsLetter(r):
			factor = 0.32
		}
		if font == "F2" {
			factor *= 1.03
		}
		width += factor * fontSize
	}
	return width
}

func pdfNormalizeText(text string) string {
	return pdfTextReplacer.Replace(text)
}

func pdfEscape(text string) string {
	var escaped strings.Builder
	for _, r := range pdfNormalizeText(text) {
		switch {
		case r == '\\' || r == '(' || r == ')':
			escaped.WriteByte('\\')
			escaped.WriteRune(r)
		case r == '\n' || r == '\r' || r == '\t':
			escaped.WriteByte(' ')
		case r < 0x20:
			// Drop non-printing control characters.
		case r < 0x80:
			escaped.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&escaped, "\\%03o", byte(r))
		default:
			escaped.WriteByte('?')
		}
	}
	return escaped.String()
}

func (c *pdfCanvas) text(x, y, size float64, font string, color pdfColor, text string) {
	fmt.Fprintf(&c.commands,
		"BT /%s %.2f Tf %.3f %.3f %.3f rg 1 0 0 1 %.2f %.2f Tm (%s) Tj ET\n",
		font, size, color.r, color.g, color.b, x, y, pdfEscape(text),
	)
}

func (c *pdfCanvas) textCentered(x, y, size float64, font string, color pdfColor, text string) {
	c.text(x-pdfTextWidth(text, size, font)/2, y, size, font, color, text)
}

func (c *pdfCanvas) textRight(x, y, size float64, font string, color pdfColor, text string) {
	c.text(x-pdfTextWidth(text, size, font), y, size, font, color, text)
}

func (c *pdfCanvas) fillRect(x, y, width, height float64, color pdfColor) {
	fmt.Fprintf(&c.commands, "q %.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f Q\n", color.r, color.g, color.b, x, y, width, height)
}

func (c *pdfCanvas) strokeRect(x, y, width, height float64, color pdfColor, lineWidth float64) {
	fmt.Fprintf(&c.commands, "q %.3f %.3f %.3f RG %.2f w %.2f %.2f %.2f %.2f re S Q\n", color.r, color.g, color.b, lineWidth, x, y, width, height)
}

func (c *pdfCanvas) line(x1, y1, x2, y2 float64, color pdfColor, lineWidth float64) {
	fmt.Fprintf(&c.commands, "q %.3f %.3f %.3f RG %.2f w %.2f %.2f m %.2f %.2f l S Q\n", color.r, color.g, color.b, lineWidth, x1, y1, x2, y2)
}

func (c *pdfCanvas) card(x, y, width, height, radius float64, fill, stroke pdfColor) {
	c.roundedPath(x, y, width, height, radius, fill, true, 0)
	c.roundedPath(x, y, width, height, radius, stroke, false, 0.7)
}

func (c *pdfCanvas) roundedPath(x, y, width, height, radius float64, color pdfColor, fill bool, lineWidth float64) {
	if radius < 0 {
		radius = 0
	}
	if radius > width/2 {
		radius = width / 2
	}
	if radius > height/2 {
		radius = height / 2
	}
	k := radius * 0.55228475
	operator := "f"
	colorOperator := "rg"
	if !fill {
		operator = "S"
		colorOperator = "RG"
	}
	fmt.Fprintf(&c.commands, "q %.3f %.3f %.3f %s %.2f w ", color.r, color.g, color.b, colorOperator, lineWidth)
	fmt.Fprintf(&c.commands, "%.2f %.2f m ", x+radius, y)
	fmt.Fprintf(&c.commands, "%.2f %.2f l %.2f %.2f %.2f %.2f %.2f %.2f c ", x+width-radius, y, x+width-radius+k, y, x+width, y+radius-k, x+width, y+radius)
	fmt.Fprintf(&c.commands, "%.2f %.2f l %.2f %.2f %.2f %.2f %.2f %.2f c ", x+width, y+height-radius, x+width, y+height-radius+k, x+width-radius+k, y+height, x+width-radius, y+height)
	fmt.Fprintf(&c.commands, "%.2f %.2f l %.2f %.2f %.2f %.2f %.2f %.2f c ", x+radius, y+height, x+radius-k, y+height, x, y+height-radius+k, x, y+height-radius)
	fmt.Fprintf(&c.commands, "%.2f %.2f l %.2f %.2f %.2f %.2f %.2f %.2f c h %s Q\n", x, y+radius, x, y+radius-k, x+radius-k, y, x+radius, y, operator)
}

func (c *pdfCanvas) circleFill(x, y, radius float64, color pdfColor) {
	c.circlePath(x, y, radius, color, true, 0)
}

func (c *pdfCanvas) circleStroke(x, y, radius float64, color pdfColor, lineWidth float64) {
	c.circlePath(x, y, radius, color, false, lineWidth)
}

func (c *pdfCanvas) circlePath(x, y, radius float64, color pdfColor, fill bool, lineWidth float64) {
	k := radius * 0.55228475
	operator := "f"
	colorOperator := "rg"
	if !fill {
		operator = "S"
		colorOperator = "RG"
	}
	fmt.Fprintf(&c.commands, "q %.3f %.3f %.3f %s %.2f w ", color.r, color.g, color.b, colorOperator, lineWidth)
	fmt.Fprintf(&c.commands, "%.2f %.2f m ", x+radius, y)
	fmt.Fprintf(&c.commands, "%.2f %.2f %.2f %.2f %.2f %.2f c ", x+radius, y+k, x+k, y+radius, x, y+radius)
	fmt.Fprintf(&c.commands, "%.2f %.2f %.2f %.2f %.2f %.2f c ", x-k, y+radius, x-radius, y+k, x-radius, y)
	fmt.Fprintf(&c.commands, "%.2f %.2f %.2f %.2f %.2f %.2f c ", x-radius, y-k, x-k, y-radius, x, y-radius)
	fmt.Fprintf(&c.commands, "%.2f %.2f %.2f %.2f %.2f %.2f c h %s Q\n", x+k, y-radius, x+radius, y-k, x+radius, y, operator)
}

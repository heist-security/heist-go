package main

import (
	"context"
	"errors"
	"fmt"
	"image/color"
	"io"
	"strings"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/heist-security/heist-go/heist"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/spf13/cobra"
)

func newBrowseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "browse",
		Short: "Browse findings and reports in a full-screen terminal UI",
		Long: `Browse findings and reports in a full-screen terminal UI.

Keys:
  tab         switch between findings and reports
  ↑/↓, j/k    move
  enter       open the selected finding or report
  esc         back to the list
  s           save the selected report's latest PDF as <id>.pdf
  r           reload
  q           quit

browse needs a terminal. Scripts should use heist findings and heist reports.

` + envUsage,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !isTerminal(cmd.InOrStdin()) || !isTerminal(cmd.OutOrStdout()) {
				return errors.New("needs a terminal; use heist findings and heist reports in scripts")
			}
			client, err := newClient()
			if err != nil {
				return err
			}
			m := newBrowseModel(cmd.Context(), client)
			_, err = tea.NewProgram(m,
				tea.WithContext(cmd.Context()),
				tea.WithInput(cmd.InOrStdin()),
				tea.WithOutput(cmd.OutOrStdout()),
			).Run()
			return err
		},
	}
}

const (
	findingsTab = iota
	reportsTab
)

// browseModel is the state of `heist browse`: a list of findings and a list
// of reports, and the detail of an opened finding or report.
type browseModel struct {
	ctx    context.Context
	client *heist.ClientWithResponses

	width, height int
	palette       palette
	tab           int
	findings      []heist.Finding
	reports       []reportRow
	cursors       [2]listCursor
	loading       int // requests in flight
	spinner       spinner.Model
	detail        *viewport.Model // set while a finding or report is open
	status        string          // the result of the last action, or an error
}

// listCursor is the selected row of a list, and the first row shown.
type listCursor struct{ pos, offset int }

// move moves the cursor by delta within n rows, scrolling so it stays within
// the height rows shown.
func (c *listCursor) move(delta, n, height int) {
	c.pos = max(0, min(c.pos+delta, n-1))
	c.offset = max(min(c.offset, c.pos), c.pos-height+1, 0)
}

type findingsLoadedMsg struct {
	findings []heist.Finding
	err      error
}

type reportsLoadedMsg struct {
	reports []reportRow
	err     error
}

// detailMsg is a rendered finding or report detail.
type detailMsg struct {
	content string
	err     error
}

// statusMsg is the result of an action, such as saving a PDF.
type statusMsg struct {
	text string
	err  error
}

func newBrowseModel(ctx context.Context, client *heist.ClientWithResponses) browseModel {
	return browseModel{
		ctx:     ctx,
		client:  client,
		palette: newPalette(true), // until the terminal reports its background
		spinner: spinner.New(spinner.WithSpinner(spinner.Line)),
		loading: 2, // Init loads findings and reports
	}
}

func (m browseModel) Init() tea.Cmd {
	return tea.Batch(tea.RequestBackgroundColor, m.spinner.Tick, m.loadFindings, m.loadReports)
}

// styles are the styles for detail views and status lines.
func (m browseModel) styles() styles {
	return styles{on: true, width: m.width, palette: m.palette}
}

func (m browseModel) loadFindings() tea.Msg {
	var findings []heist.Finding
	for f, err := range m.client.AllFindings(m.ctx, heist.ListFindingsParams{}) {
		if err != nil {
			return findingsLoadedMsg{err: err}
		}
		findings = append(findings, f)
	}
	return findingsLoadedMsg{findings: findings}
}

func (m browseModel) loadReports() tea.Msg {
	res, err := m.client.ListReportsWithResponse(m.ctx, &heist.ListReportsParams{})
	if err != nil {
		return reportsLoadedMsg{err: err}
	}
	if res.JSON200 == nil {
		return reportsLoadedMsg{err: fmt.Errorf("unexpected %s response", res.Status())}
	}
	rows := make([]reportRow, len(*res.JSON200))
	for i, r := range *res.JSON200 {
		rows[i] = newReportRow(r.Id, string(r.ReportType), string(r.Status), r.ScopeName, r.CreatedAt, r.Title)
	}
	return reportsLoadedMsg{reports: rows}
}

// openSelected fetches and renders the selected finding or report with the
// same detail output as heist findings get and heist reports get.
func (m browseModel) openSelected() tea.Cmd {
	i := m.cursors[m.tab].pos
	var id string
	var render func(id openapi_types.UUID, w io.Writer) error
	switch {
	case m.tab == findingsTab && i < len(m.findings):
		id, render = m.findings[i].Id, m.renderFinding
	case m.tab == reportsTab && i < len(m.reports):
		id, render = m.reports[i].ID, m.renderReport
	default:
		return nil
	}
	return func() tea.Msg {
		parsed, err := parseUUID(id)
		if err != nil {
			return detailMsg{err: err}
		}
		var b strings.Builder
		err = render(parsed, &b)
		return detailMsg{content: b.String(), err: err}
	}
}

func (m browseModel) renderFinding(id openapi_types.UUID, w io.Writer) error {
	res, err := m.client.GetFindingWithResponse(m.ctx, id)
	if err != nil {
		return err
	}
	if res.JSON200 == nil {
		return fmt.Errorf("unexpected %s response", res.Status())
	}
	return writeFindingDetail(w, m.styles(), res.JSON200)
}

func (m browseModel) renderReport(id openapi_types.UUID, w io.Writer) error {
	res, err := m.client.GetReportWithResponse(m.ctx, id)
	if err != nil {
		return err
	}
	if res.JSON200 == nil {
		return fmt.Errorf("unexpected %s response", res.Status())
	}
	return writeReportDetail(w, m.styles(), res)
}

// saveSelectedReport saves the selected report's latest PDF to the current
// directory, like heist reports download.
func (m browseModel) saveSelectedReport() tea.Cmd {
	i := m.cursors[reportsTab].pos
	if m.tab != reportsTab || i >= len(m.reports) {
		return nil
	}
	id := m.reports[i].ID
	return func() tea.Msg {
		parsed, err := parseUUID(id)
		if err != nil {
			return statusMsg{err: err}
		}
		pdf, err := openReportPDF(m.ctx, m.client, parsed, heist.DownloadReportParams{})
		if err != nil {
			return statusMsg{err: err}
		}
		defer pdf.Close()
		file := id + ".pdf"
		if err := writeFileAtomic(file, pdf); err != nil {
			return statusMsg{err: err}
		}
		return statusMsg{text: "Saved " + file}
	}
}

func (m browseModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.BackgroundColorMsg:
		m.palette = newPalette(msg.IsDark())
		return m, nil

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		if m.detail != nil {
			m.detail.SetWidth(m.width - 2)
			m.detail.SetHeight(m.bodyHeight())
		}
		for i := range m.cursors {
			m.cursors[i].move(0, m.rows(i), m.bodyHeight())
		}
		return m, nil

	case findingsLoadedMsg:
		m.loading--
		m.findings = msg.findings
		m.setStatus("", msg.err)
		m.cursors[findingsTab].move(0, len(m.findings), m.bodyHeight())
		return m, nil

	case reportsLoadedMsg:
		m.loading--
		m.reports = msg.reports
		m.setStatus("", msg.err)
		m.cursors[reportsTab].move(0, len(m.reports), m.bodyHeight())
		return m, nil

	case detailMsg:
		m.loading--
		if msg.err != nil {
			m.setStatus("", msg.err)
			return m, nil
		}
		vp := viewport.New(viewport.WithWidth(m.width-2), viewport.WithHeight(m.bodyHeight()))
		vp.SoftWrap = true
		vp.SetContent(msg.content)
		m.detail = &vp
		return m, nil

	case statusMsg:
		m.loading--
		m.setStatus(msg.text, msg.err)
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tea.KeyPressMsg:
		key := msg.String()
		if key == "q" || key == "ctrl+c" {
			return m, tea.Quit
		}
		if m.detail != nil {
			if key == "esc" || key == "backspace" {
				m.detail = nil
				return m, nil
			}
			vp, cmd := m.detail.Update(msg)
			m.detail = &vp
			return m, cmd
		}
		page := m.bodyHeight()
		moves := map[string]int{
			"up": -1, "k": -1, "down": 1, "j": 1,
			"pgup": -page, "b": -page, "pgdown": page, "f": page, "space": page,
			"home": -m.rows(m.tab), "g": -m.rows(m.tab), "end": m.rows(m.tab), "G": m.rows(m.tab),
		}
		if delta, ok := moves[key]; ok {
			m.cursors[m.tab].move(delta, m.rows(m.tab), page)
			return m, nil
		}
		switch key {
		case "tab", "shift+tab":
			m.tab = 1 - m.tab
		case "enter":
			return m.start(m.openSelected())
		case "s":
			return m.start(m.saveSelectedReport())
		case "r":
			m.loading += 2
			return m, tea.Batch(m.loadFindings, m.loadReports)
		}
	}
	return m, nil
}

// start runs cmd as a request, showing the spinner until it returns.
func (m browseModel) start(cmd tea.Cmd) (tea.Model, tea.Cmd) {
	if cmd == nil {
		return m, nil
	}
	m.loading++
	m.status = ""
	return m, cmd
}

func (m *browseModel) setStatus(text string, err error) {
	s := m.styles()
	switch {
	case err != nil:
		m.status = s.fail(strings.TrimPrefix(err.Error(), "heist: "))
	case text != "":
		m.status = s.ok(text)
	default:
		m.status = ""
	}
}

// rows is the number of rows in a tab's list.
func (m browseModel) rows(tab int) int {
	if tab == findingsTab {
		return len(m.findings)
	}
	return len(m.reports)
}

// bodyHeight is the height of the list or detail, between the tab bar and
// the status line.
func (m browseModel) bodyHeight() int { return max(m.height-4, 1) }

// cell is a column of a list row. A width of 0 takes the space the other
// columns leave.
type cell struct {
	text  string
	width int
	fg    color.Color
	bold  bool
}

// row renders a list row in the style of the heist.security terminal
// mockup: a pointer and a light background mark the selected row.
func (m browseModel) row(selected bool, cells ...cell) string {
	pointer := "  "
	if selected {
		pointer = "> "
	}
	cells = append([]cell{{text: pointer, width: 2}}, cells...)
	flex := m.width
	for _, c := range cells {
		flex -= c.width
	}
	var b strings.Builder
	for i, c := range cells {
		width := c.width
		if width == 0 {
			width = max(flex, 1)
		}
		text := c.text
		if i > 0 { // leave a gap after each column but the pointer
			text = ansi.Truncate(text, width-2, "…")
		}
		style := lipgloss.NewStyle().Width(width).Foreground(c.fg).Bold(c.bold || selected && c.fg == nil)
		if selected {
			style = style.Background(m.palette.selected)
		}
		b.WriteString(style.Render(text))
	}
	return b.String()
}

func (m browseModel) listView() string {
	c := m.cursors[m.tab]
	end := min(c.offset+m.bodyHeight(), m.rows(m.tab))
	var lines []string
	for i := c.offset; i < end; i++ {
		selected := i == c.pos
		if m.tab == findingsTab {
			f := m.findings[i]
			sev := string(f.Severity)
			fg := m.palette.severityColor(sev)
			if fg == nil {
				fg = m.palette.dim
			}
			lines = append(lines, m.row(selected,
				cell{text: sev, width: 15, fg: fg, bold: true},
				cell{text: oneLine(f.Title)},
				cell{text: m.styles().status(string(f.ValidationStatus)), width: 22, fg: m.palette.dim},
			))
		} else {
			r := m.reports[i]
			scope := r.Scope
			if scope == "-" {
				scope = ""
			}
			lines = append(lines, m.row(selected,
				cell{text: r.Title},
				cell{text: joinDot(r.Type, scope, m.styles().date(r.Created)), width: 40, fg: m.palette.dim},
				cell{text: r.Status, width: 12, fg: m.palette.dim},
			))
		}
	}
	if len(lines) == 0 && m.loading == 0 {
		return m.styles().dim("  Nothing here yet")
	}
	return strings.Join(lines, "\n")
}

func (m browseModel) View() tea.View {
	s := m.styles()
	tabs := []string{
		fmt.Sprintf("Findings %s", s.dim(fmt.Sprint(len(m.findings)))),
		fmt.Sprintf("Reports %s", s.dim(fmt.Sprint(len(m.reports)))),
	}
	tabs[m.tab] = s.bold(tabs[m.tab])
	for i := range tabs {
		if i != m.tab {
			tabs[i] = s.dim(ansi.Strip(tabs[i]))
		}
	}
	bar := "  " + strings.Join(tabs, "   ")

	body := m.listView()
	help := "↑↓ move · enter open · tab switch · r reload · q quit"
	if m.tab == reportsTab {
		help = "↑↓ move · enter open · s save PDF · tab switch · q quit"
	}
	if m.detail != nil {
		body = lipgloss.NewStyle().PaddingLeft(2).Render(m.detail.View())
		help = "↑↓ scroll · esc back · q quit"
	}

	footer := m.status
	if m.loading > 0 {
		footer = s.dim(m.spinner.View()) + " Loading"
	}
	if footer == "" {
		footer = s.dim(help)
	}

	v := tea.NewView(lipgloss.JoinVertical(lipgloss.Left, bar, "", body, "", "  "+footer))
	v.AltScreen = true
	return v
}

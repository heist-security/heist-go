package main

import (
	"bytes"
	"context"
	"fmt"
	"image/color"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"
)

// isTerminal reports whether v, a command's input or output, is a terminal.
func isTerminal(v any) bool {
	f, ok := v.(*os.File)
	return ok && term.IsTerminal(f.Fd())
}

type darkBackgroundKey struct{}

// withDarkBackground returns ctx with a lookup of whether the terminal on in
// and out has a dark background. The terminal is asked at most once, when
// styled output first needs it.
func withDarkBackground(ctx context.Context, in io.Reader, out io.Writer) context.Context {
	return context.WithValue(ctx, darkBackgroundKey{}, sync.OnceValue(func() bool {
		inFile, inOK := in.(*os.File)
		outFile, outOK := out.(*os.File)
		return !inOK || !outOK || lipgloss.HasDarkBackground(inFile, outFile)
	}))
}

// terminalIsDark reports whether the command's terminal has a dark
// background, assuming dark when it can't tell.
func terminalIsDark(cmd *cobra.Command) bool {
	isDark, ok := cmd.Context().Value(darkBackgroundKey{}).(func() bool)
	return !ok || isDark()
}

// printStyled writes a command's table or detail output with render. Output
// to a terminal is styled, with colors adapted to the terminal and NO_COLOR,
// and goes through the user's pager when it is taller than the terminal.
// Other output, such as a pipe, is plain text.
func printStyled(cmd *cobra.Command, render func(w io.Writer, s styles) error) error {
	stdout := cmd.OutOrStdout()
	if !isTerminal(stdout) {
		return render(stdout, styles{})
	}
	width, height, err := term.GetSize(stdout.(*os.File).Fd())
	if err != nil {
		width, height = 0, 0
	}
	s := styles{on: true, width: width, palette: newPalette(terminalIsDark(cmd))}
	var buf bytes.Buffer
	if err := render(&colorprofile.Writer{Forward: &buf, Profile: colorprofile.Detect(stdout, os.Environ())}, s); err != nil {
		return err
	}
	if height > 0 && bytes.Count(buf.Bytes(), []byte("\n")) >= height {
		if paged := runPager(buf.Bytes(), stdout, cmd.ErrOrStderr()); paged {
			return nil
		}
	}
	_, err = stdout.Write(buf.Bytes())
	return err
}

// runPager shows out in $PAGER, or less, and reports whether it ran. Like
// git, it sets LESS=FRX unless LESS is set, so less keeps colors and leaves
// the output on the screen.
func runPager(out []byte, stdout, stderr io.Writer) bool {
	pager := strings.Fields(os.Getenv("PAGER"))
	if len(pager) == 0 {
		pager = []string{"less"}
	}
	if _, err := exec.LookPath(pager[0]); err != nil {
		return false
	}
	c := exec.Command(pager[0], pager[1:]...)
	c.Stdin, c.Stdout, c.Stderr = bytes.NewReader(out), stdout, stderr
	if os.Getenv("LESS") == "" {
		c.Env = append(os.Environ(), "LESS=FRX")
	}
	// The pager handles Ctrl+C itself; don't exit underneath it.
	signal.Ignore(os.Interrupt)
	defer signal.Reset(os.Interrupt)
	return c.Run() == nil
}

// palette holds the colors of the heist.security terminal mockup, in their
// light or dark background variant.
type palette struct {
	critical, high, medium, low, success color.Color
	// dim is secondary text; selected is the background of the selected row
	// in heist browse.
	dim, selected color.Color
}

func newPalette(dark bool) palette {
	lightDark := lipgloss.LightDark(dark)
	c := func(light, dark string) color.Color {
		return lightDark(lipgloss.Color(light), lipgloss.Color(dark))
	}
	return palette{
		critical: c("#d42325", "#e74355"),
		high:     c("#c75400", "#eb6e19"),
		medium:   c("#d79700", "#edb21d"),
		low:      c("#2174de", "#599cec"),
		success:  c("#05893e", "#42bf64"),
		dim:      c("#898c92", "#8c8b85"),
		selected: c("#e4e5e8", "#313130"),
	}
}

// styles styles table and detail output. The zero value leaves output plain,
// exactly as scripts have always seen it.
type styles struct {
	on bool
	// width is the terminal width that tables shorten to fit, or 0 to not
	// limit their width.
	width   int
	palette palette
}

func (s styles) fg(c color.Color, v string) string {
	if !s.on || v == "" {
		return v
	}
	return lipgloss.NewStyle().Foreground(c).Render(v)
}

// dim styles secondary text, such as IDs and metadata.
func (s styles) dim(v string) string { return s.fg(s.palette.dim, v) }

func (s styles) bold(v string) string {
	if !s.on || v == "" {
		return v
	}
	return lipgloss.NewStyle().Bold(true).Render(v)
}

// ok styles a result line with a check mark.
func (s styles) ok(v string) string { return s.fg(s.palette.success, "✓") + " " + v }

// fail styles a failed result line with a cross.
func (s styles) fail(v string) string { return s.fg(s.palette.critical, "✗") + " " + v }

// severityColor is the color of a finding severity, or nil for
// INFORMATIONAL and unknown values.
func (p palette) severityColor(v string) color.Color {
	switch v {
	case "CRITICAL":
		return p.critical
	case "HIGH":
		return p.high
	case "MEDIUM":
		return p.medium
	case "LOW":
		return p.low
	}
	return nil
}

// severity styles a finding severity: bold and colored, or dim for
// INFORMATIONAL.
func (s styles) severity(v string) string {
	if c := s.palette.severityColor(v); c != nil && s.on {
		return lipgloss.NewStyle().Bold(true).Foreground(c).Render(v)
	}
	return s.dim(v)
}

// findingStatuses are the names styled output uses for finding statuses. The
// API's finding counts call PUBLISHED findings open.
var findingStatuses = map[string]string{
	"PUBLISHED":            "open",
	"FIXED":                "fixed",
	"ACCEPTED":             "accepted",
	"COMPENSATING_CONTROL": "compensating control",
}

// status names a finding status for people in styled output.
func (s styles) status(v string) string {
	if !s.on {
		return v
	}
	if name, ok := findingStatuses[v]; ok {
		return name
	}
	return strings.ToLower(strings.ReplaceAll(v, "_", " "))
}

// date shortens an API timestamp to its date in styled output.
func (s styles) date(v string) string {
	if t, err := time.Parse(time.RFC3339, v); err == nil && s.on {
		return t.Local().Format("2006-01-02")
	}
	return v
}

// time shortens an API timestamp to local minutes in styled output.
func (s styles) time(v string) string {
	if t, err := time.Parse(time.RFC3339, v); err == nil && s.on {
		return t.Local().Format("2006-01-02 15:04")
	}
	return v
}

// joinDot joins the non-empty parts with middle dots.
func joinDot(parts ...string) string {
	return strings.Join(slices.DeleteFunc(parts, func(p string) bool { return p == "" }), " · ")
}

// fieldWriter writes a detail view's label and value pairs as aligned
// columns, skipping empty values. Plain labels end with a colon; styled labels
// are dim.
type fieldWriter struct {
	s      styles
	fields [][2]string
}

func (f *fieldWriter) add(label, value string) {
	if value != "" {
		f.fields = append(f.fields, [2]string{label, value})
	}
}

func (f *fieldWriter) write(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, kv := range f.fields {
		label := kv[0] + ":"
		if f.s.on {
			// Every styled label has the same escape codes around it, so
			// tabwriter still aligns the values.
			label = f.s.dim(kv[0])
		}
		fmt.Fprintf(tw, "%s\t%s\n", label, kv[1])
	}
	return tw.Flush()
}

// section writes a detail section's heading and text.
func (s styles) section(w io.Writer, title, text string) error {
	heading := title + ":"
	if s.on {
		heading = s.bold(title)
	}
	_, err := fmt.Fprintf(w, "\n%s\n%s\n", heading, strings.TrimRight(text, "\n"))
	return err
}

// minFlexWidth is the narrowest a list's flexible column, usually the title,
// is shortened to before the table wraps instead.
const minFlexWidth = 12

// writeTable writes rows under headers. Plain output is tab-aligned columns.
// Styled output has dim headers, colored severities and human statuses, and
// shortens the last column to fit the terminal.
func writeTable(w io.Writer, s styles, headers []string, rows [][]string) error {
	if !s.on {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, strings.Join(headers, "\t"))
		for _, r := range rows {
			fmt.Fprintln(tw, strings.Join(r, "\t"))
		}
		return tw.Flush()
	}
	styled := [][]string{make([]string, len(headers))}
	for i, h := range headers {
		styled[0][i] = s.dim(h)
	}
	for _, r := range rows {
		row := make([]string, len(r))
		for i, v := range r {
			if s.palette.severityColor(v) != nil || v == "INFORMATIONAL" {
				v = s.severity(v)
			}
			row[i] = v
		}
		styled = append(styled, row)
	}
	return s.list(w, styled, len(headers)-1)
}

// list writes styled rows as aligned columns without borders, shortening
// column flex so the list fits the terminal.
func (s styles) list(w io.Writer, rows [][]string, flex int) error {
	if len(rows) == 0 {
		return nil
	}
	last := len(rows[0]) - 1
	build := func(rows [][]string) *table.Table {
		return table.New().
			BorderTop(false).BorderBottom(false).BorderLeft(false).BorderRight(false).
			BorderColumn(false).BorderHeader(false).
			Rows(rows...).
			StyleFunc(func(_, col int) lipgloss.Style {
				if col == last {
					return lipgloss.NewStyle()
				}
				return lipgloss.NewStyle().PaddingRight(2)
			})
	}
	t := build(rows)
	if over := lipgloss.Width(t.Render()) - s.width; s.width > 0 && over > 0 {
		width := 0
		for _, r := range rows {
			width = max(width, lipgloss.Width(r[flex]))
		}
		if width-over >= minFlexWidth {
			short := make([][]string, len(rows))
			for i, r := range rows {
				short[i] = slices.Clone(r)
				short[i][flex] = ansi.Truncate(r[flex], width-over, "…")
			}
			t = build(short)
		} else {
			t.Width(s.width)
		}
	}
	_, err := fmt.Fprintln(w, t.Render())
	return err
}

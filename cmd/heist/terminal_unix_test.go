//go:build unix

package main

import (
	"image/color"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
	"github.com/creack/pty"
)

// These tests run the CLI on a pseudo-terminal, the only place styled
// output, progress and heist browse appear. The other tests write to buffers
// and cover plain output.

var (
	darkBackground  = lipgloss.Color("#1a1a17")
	lightBackground = lipgloss.Color("#ffffff")
)

// terminal is a pseudo-terminal whose output is drawn by a terminal emulator.
// The emulator answers queries such as the background color, like a real
// terminal.
type terminal struct {
	t      *testing.T
	ptmx   *os.File // the terminal side: write keys here
	tty    *os.File // the CLI's stdin, stdout and stderr
	screen *vt.SafeEmulator
}

func newTerminal(t *testing.T, background color.Color) *terminal {
	t.Helper()
	const cols, rows = 100, 20
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	if err := pty.Setsize(ptmx, &pty.Winsize{Cols: cols, Rows: rows}); err != nil {
		t.Fatal(err)
	}
	screen := vt.NewSafeEmulator(cols, rows)
	screen.SetBackgroundColor(background)
	go io.Copy(screen, ptmx) // the CLI's output
	// The emulator's answers to queries. The emulator is never closed: its
	// Close races with Read in vt v0.1.0, so this goroutine stays blocked
	// until the test binary exits.
	go io.Copy(ptmx, screen)
	t.Cleanup(func() {
		ptmx.Close()
		tty.Close()
	})
	// The pager and NO_COLOR must not depend on the developer's environment.
	t.Setenv("PAGER", "cat")
	t.Setenv("NO_COLOR", "")
	return &terminal{t: t, ptmx: ptmx, tty: tty, screen: screen}
}

// start runs the CLI on the terminal and returns its exit status when done.
func (term *terminal) start(args ...string) <-chan int {
	code := make(chan int, 1)
	go func() { code <- run(args, term.tty, term.tty, term.tty) }()
	return code
}

// text is the screen's text, with trailing spaces and blank lines removed.
func (term *terminal) text() string {
	lines := strings.Split(ansi.Strip(term.screen.Render()), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

// waitFor waits until the screen satisfies ok, failing the test after a few
// seconds.
func (term *terminal) waitFor(what string, ok func(screen string) bool) {
	term.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok(term.text()) {
		if time.Now().After(deadline) {
			term.t.Fatalf("timed out waiting for %s; screen:\n%s", what, term.text())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (term *terminal) waitForText(s string) {
	term.t.Helper()
	term.waitFor(strconv.Quote(s), func(screen string) bool { return strings.Contains(screen, s) })
}

func (term *terminal) press(keys string) {
	term.t.Helper()
	if _, err := io.WriteString(term.ptmx, keys); err != nil {
		term.t.Fatal(err)
	}
}

func sameColor(a, b color.Color) bool {
	if a == nil || b == nil {
		return a == b
	}
	ar, ag, ab, _ := a.RGBA()
	br, bg, bb, _ := b.RGBA()
	return ar == br && ag == bg && ab == bb
}

func TestTerminalFindingsList(t *testing.T) {
	for _, tt := range []struct {
		name       string
		background color.Color
		critical   string // the critical severity color for this background
	}{
		{"dark", darkBackground, "#e74355"},
		{"light", lightBackground, "#d42325"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			newFindingsServer(t, finding("a", "CRITICAL", "PUBLISHED"), finding("b", "LOW", "FIXED"))
			term := newTerminal(t, tt.background)
			if code := <-term.start("findings", "list"); code != 0 {
				t.Fatalf("exit %d; screen:\n%s", code, term.text())
			}
			want := "CRITICAL  Finding a  open   a\n" +
				"LOW       Finding b  fixed  b\n" +
				"\n" +
				"2 findings · 1 open"
			term.waitFor("the findings list", func(screen string) bool { return strings.TrimSpace(screen) == want })

			// The list starts where the progress line was, at the top.
			if fg := term.screen.CellAt(0, 0).Style.Fg; !sameColor(fg, lipgloss.Color(tt.critical)) {
				t.Errorf("CRITICAL color = %v, want %s", fg, tt.critical)
			}
		})
	}
}

func TestTerminalGenerateWaitShowsProgress(t *testing.T) {
	interval := exportPollInterval
	exportPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { exportPollInterval = interval })
	done := make(chan struct{})
	reportsServer(t, map[string]http.HandlerFunc{
		"POST /reports": respondJSON(http.StatusAccepted, `{"workflowId":"wf","exportId":"`+exportID+`"}`),
		"GET /report-exports/{id}": func(w http.ResponseWriter, r *http.Request) {
			status := "RUNNING"
			select {
			case <-done:
				status = "COMPLETED"
			default:
			}
			respondJSON(http.StatusOK, `{"exportId":"`+exportID+`","workflowId":"wf","runId":null,"status":"`+status+
				`","startedAt":null,"closedAt":null,"failure":null,"reports":[]}`)(w, r)
		},
	})
	term := newTerminal(t, darkBackground)
	code := term.start("reports", "generate", "--wait")
	term.waitForText("Generating reports · 0 reports so far")
	close(done)
	if c := <-code; c != 0 {
		t.Fatalf("exit %d; screen:\n%s", c, term.text())
	}
	want := "✓ Reports generated · 0 reports\nexport " + exportID
	term.waitFor("the result", func(screen string) bool { return strings.TrimSpace(screen) == want })
}

func TestTerminalBrowse(t *testing.T) {
	const otherID = "6b7c8d9e-0f1a-4b2c-8d4e-5f6a7b8c9d0e"
	findings := `{"items":[` +
		`{"id":"` + findingID + `","title":"Stored XSS","severity":"CRITICAL","validationStatus":"PUBLISHED"},` +
		`{"id":"` + otherID + `","title":"Verbose errors","severity":"LOW","validationStatus":"FIXED"}` +
		`],"total":2,"page":1,"size":100}`
	reportsServer(t, map[string]http.HandlerFunc{
		"GET /findings": respondJSON(http.StatusOK, findings),
		"GET /findings/{id}": respondJSON(http.StatusOK, `{"id":"`+otherID+`","title":"Verbose errors",`+
			`"severity":"LOW","validationStatus":"FIXED","category":"web","type":"info","description":"Stack traces leak."}`),
		"GET /reports": respondJSON(http.StatusOK, "["+reportJSON+"]"),
	})
	term := newTerminal(t, darkBackground)
	code := term.start("browse")

	term.waitForText("> CRITICAL       Stored XSS")
	term.press("j")
	term.waitForText("> LOW            Verbose errors")
	term.press("\r")
	term.waitForText("Stack traces leak.")
	if !strings.Contains(term.text(), "LOW  Verbose errors\n  fixed · web · info") {
		t.Errorf("detail heading missing; screen:\n%s", term.text())
	}
	term.press("\t")
	term.waitForText("Stack traces leak.") // tab does nothing in a detail view
	term.press("\x1b")                     // esc: back to the list
	term.waitForText("> LOW            Verbose errors")
	term.press("\t")
	term.waitForText("> Pentest summary")
	term.press("q")
	if c := <-code; c != 0 {
		t.Fatalf("exit %d; screen:\n%s", c, term.text())
	}
	if term.screen.IsAltScreen() {
		t.Error("browse left the terminal in the alternate screen")
	}
}

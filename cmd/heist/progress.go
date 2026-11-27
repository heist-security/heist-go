package main

import (
	"context"
	"errors"
	"fmt"

	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/spf13/cobra"
)

// exitInterrupted is the exit status after Ctrl+C stops a command that shows
// progress, as the shell reports for a process killed by SIGINT.
const exitInterrupted = 130

// progressFunc reports a step of a long-running command. When total is
// positive, done of total is shown as a progress bar.
type progressFunc func(status string, done, total int)

// withProgress runs work, showing its progress on stderr while it runs when
// stdout and stderr are terminals and quiet is false. Commands pass quiet for
// --json. The progress line is removed before withProgress returns, so the
// command's output follows directly.
func withProgress(cmd *cobra.Command, quiet bool, status string, work func(ctx context.Context, progress progressFunc) error) error {
	ctx := cmd.Context()
	stderr := cmd.ErrOrStderr()
	if quiet || !isTerminal(cmd.OutOrStdout()) || !isTerminal(stderr) {
		return work(ctx, func(string, int, int) {})
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Input is disabled: the progress line never reads the keyboard, and
	// Bubble Tea still turns Ctrl+C into an interrupt.
	p := tea.NewProgram(newProgressModel(status, terminalIsDark(cmd)), tea.WithInput(nil), tea.WithOutput(stderr))
	result := make(chan error, 1)
	go func() {
		err := work(ctx, func(status string, done, total int) {
			p.Send(progressMsg{status, done, total})
		})
		result <- err
		p.Send(workDoneMsg{})
	}()
	if _, err := p.Run(); err != nil {
		cancel()
		<-result
		if errors.Is(err, tea.ErrInterrupted) {
			return &exitError{exitInterrupted, "interrupted"}
		}
		return err
	}
	return <-result
}

type progressMsg struct {
	status      string
	done, total int
}

type workDoneMsg struct{}

type progressModel struct {
	spinner     spinner.Model
	bar         progress.Model
	status      string
	done, total int
	finished    bool
}

// newProgressModel shows status after a line spinner, as in the
// heist.security terminal mockup.
func newProgressModel(status string, dark bool) progressModel {
	p := newPalette(dark)
	return progressModel{
		spinner: spinner.New(spinner.WithSpinner(spinner.Line), spinner.WithStyle(lipgloss.NewStyle().Foreground(p.dim))),
		bar:     progress.New(progress.WithWidth(24), progress.WithColors(p.success), progress.WithoutPercentage()),
		status:  status,
	}
}

func (m progressModel) Init() tea.Cmd { return m.spinner.Tick }

func (m progressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case progressMsg:
		m.status, m.done, m.total = msg.status, msg.done, msg.total
	case workDoneMsg:
		m.finished = true
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m progressModel) View() tea.View {
	if m.finished {
		return tea.NewView("") // remove the progress line before output
	}
	line := m.spinner.View() + " " + m.status
	if m.total > 0 {
		line += fmt.Sprintf("  %s %d/%d", m.bar.ViewAs(float64(m.done)/float64(m.total)), m.done, m.total)
	}
	return tea.NewView(line)
}

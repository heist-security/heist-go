// Command heist is the Heist command-line interface.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/heist-security/heist-go/heist"
	"github.com/spf13/cobra"
)

// version is the CLI release, set by release builds with
// -ldflags "-X main.version=vX.Y.Z". go install reports the module version.
var version = ""

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run executes the command line in args and returns the exit status: 0 for
// success, 1 for errors, 2 for usage errors, or a command's exitError code.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	root := newRootCmd()
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	cmd, err := root.ExecuteContextC(context.Background())
	if err == nil {
		return 0
	}
	// SDK errors already start with "heist: ".
	fmt.Fprintf(stderr, "%s: %s\n", cmd.CommandPath(), strings.TrimPrefix(err.Error(), "heist: "))
	var usage usageError
	if errors.As(err, &usage) {
		fmt.Fprintf(stderr, "\n%s", cmd.UsageString())
		return 2
	}
	var exit *exitError
	if errors.As(err, &exit) {
		return exit.code
	}
	return 1
}

func newRootCmd() *cobra.Command {
	root := groupCmd(&cobra.Command{
		Use:           "heist",
		Short:         "Heist command-line interface",
		SilenceErrors: true,
		SilenceUsage:  true,
	})
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{err}
	})
	root.AddCommand(newAPICmd(), newDomainsCmd(), newFindingsCmd(), newReportsCmd(), &cobra.Command{
		Use:   "version",
		Short: "Print the CLI version and targeted API contract version",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "heist %s (API contract %s)\n", cliVersion(), heist.APIVersion)
			return err
		},
	})
	// Add Cobra's completion command now, rather than during Execute, so it
	// rejects an unknown shell and extra arguments as usage errors.
	root.InitDefaultCompletionCmd()
	if completion, _, err := root.Find([]string{"completion"}); err == nil {
		groupCmd(completion)
		for _, shell := range completion.Commands() {
			shell.Args = noArgs
		}
	}
	return root
}

// groupCmd makes cmd reject a missing or unknown subcommand as a usage
// error. Without this, Cobra prints help and exits 0 for a mistyped
// subcommand of a nested command.
func groupCmd(cmd *cobra.Command) *cobra.Command {
	cmd.Args = cobra.ArbitraryArgs
	cmd.SuggestionsMinimumDistance = 2 // Cobra's default for root commands
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return usageErrorf("expected a command")
		}
		msg := fmt.Sprintf("unknown command %q", args[0])
		if s := cmd.SuggestionsFor(args[0]); len(s) > 0 {
			msg += "; did you mean " + strings.Join(s, " or ") + "?"
		}
		return usageError{errors.New(msg)}
	}
	return cmd
}

// usageError is an invalid command line. It exits with status 2 and prints
// the command's usage.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }

func usageErrorf(format string, a ...any) error {
	return usageError{fmt.Errorf(format, a...)}
}

// exitError reports a result that exits with a status other than 1, such as
// a --fail-on threshold being reached.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// noArgs rejects positional arguments.
func noArgs(_ *cobra.Command, args []string) error {
	if len(args) != 0 {
		return usageErrorf("unexpected arguments")
	}
	return nil
}

// oneArg requires exactly one positional argument, described by what.
func oneArg(what string) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) != 1 {
			return usageErrorf("expected one %s", what)
		}
		return nil
	}
}

func cliVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}

const envUsage = `Environment:
  HEIST_CLIENT_ID, HEIST_CLIENT_SECRET   OAuth app credentials (required)
  HEIST_SERVER_URL                       API server URL (default ` + heist.DefaultServerURL + `)
  HEIST_TOKEN_URL                        OAuth token URL (default ` + heist.DefaultTokenURL + `)`

// newClient returns an SDK client authenticated with the OAuth app
// credentials from the environment.
func newClient() (*heist.ClientWithResponses, error) {
	tokens := &heist.ClientCredentials{
		ClientID:     os.Getenv("HEIST_CLIENT_ID"),
		ClientSecret: os.Getenv("HEIST_CLIENT_SECRET"),
		TokenURL:     os.Getenv("HEIST_TOKEN_URL"),
	}
	if tokens.ClientID == "" || tokens.ClientSecret == "" {
		return nil, errors.New("HEIST_CLIENT_ID and HEIST_CLIENT_SECRET must be set")
	}
	return heist.New(tokens, heist.Config{
		ServerURL: os.Getenv("HEIST_SERVER_URL"),
		UserAgent: "heist-cli/" + cliVersion(),
	})
}

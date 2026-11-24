// Command heist is the Heist command-line interface.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/heist-security/heist-go/heist"
)

// version is the CLI release, set by release builds with
// -ldflags "-X main.version=vX.Y.Z". go install reports the module version.
var version = ""

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "api":
		return runAPI(args[1:], stdin, stdout, stderr)
	case "findings":
		return runFindings(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "heist %s (API contract %s)\n", cliVersion(), heist.APIVersion)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "heist: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: heist <command>

Commands:
  api        Make an authenticated API request and print the response
  findings   List, show and count findings, and gate CI on severity
  version    Print the CLI version and targeted API contract version
  help       Show this help
`)
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
  HEIST_TOKEN_URL                        OAuth token URL (default ` + heist.DefaultTokenURL + `)
`

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

// printError reports a command failure on stderr and returns exit code 1.
func printError(stderr io.Writer, command string, err error) int {
	// SDK errors already start with "heist: ".
	fmt.Fprintf(stderr, "heist %s: %s\n", command, strings.TrimPrefix(err.Error(), "heist: "))
	return 1
}

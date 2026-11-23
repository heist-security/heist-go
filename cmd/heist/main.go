// Command heist is the Heist command-line interface.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/heist-security/heist-go/heist"
)

// version is the CLI release, set by release builds with
// -ldflags "-X main.version=vX.Y.Z". go install reports the module version.
var version = ""

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
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

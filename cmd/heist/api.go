package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/heist-security/heist-go/heist"
)

const apiUsage = `Usage: heist api [-X method] [--input file] <path>

Send an authenticated request to the Heist API and write the response body
to stdout. The path is relative to the API server URL, for example
/findings?severity=high.

Flags:
  -X, --method method   HTTP method (default GET, or POST with --input)
      --input file      Send the file as a JSON request body; use - for stdin

` + envUsage

func runAPI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("api", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	method := fs.String("X", "", "")
	fs.StringVar(method, "method", "", "")
	input := fs.String("input", "", "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, apiUsage)
			return 0
		}
		fmt.Fprintf(stderr, "heist api: %v\n\n%s", err, apiUsage)
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(stderr, "heist api: expected one path argument\n\n%s", apiUsage)
		return 2
	}
	if *method == "" {
		*method = http.MethodGet
		if *input != "" {
			*method = http.MethodPost
		}
	}
	if err := apiRequest(context.Background(), strings.ToUpper(*method), fs.Arg(0), *input, stdin, stdout); err != nil {
		return printError(stderr, "api", err)
	}
	return 0
}

func apiRequest(ctx context.Context, method, path, input string, stdin io.Reader, stdout io.Writer) error {
	client, err := newClient()
	if err != nil {
		return err
	}
	// heist.New always wraps a *heist.Client, whose doer adds authentication
	// and converts error responses into *heist.APIError.
	raw := client.ClientInterface.(*heist.Client)

	var body io.Reader
	switch input {
	case "":
	case "-":
		body = stdin
	default:
		f, err := os.Open(input)
		if err != nil {
			return err
		}
		defer f.Close()
		body = f
	}
	// The server URL ends with "/", so the request stays under it.
	req, err := http.NewRequestWithContext(ctx, method, raw.Server+strings.TrimLeft(path, "/"), body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := raw.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(stdout, resp.Body)
	return err
}

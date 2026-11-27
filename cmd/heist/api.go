package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/heist-security/heist-go/heist"
	"github.com/spf13/cobra"
)

func newAPICmd() *cobra.Command {
	var method, input string
	cmd := &cobra.Command{
		Use:   "api <path>",
		Short: "Make an authenticated API request and print the response",
		Long: `Send an authenticated request to the Heist API and write the response body
to stdout. The path is relative to the API server URL, for example
/findings?severity=high.

` + envUsage,
		Args: oneArg("path argument"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if method == "" {
				method = http.MethodGet
				if input != "" {
					method = http.MethodPost
				}
			}
			return apiRequest(cmd.Context(), strings.ToUpper(method), args[0], input, cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVarP(&method, "method", "X", "", "HTTP `method` (default GET, or POST with --input)")
	cmd.Flags().StringVar(&input, "input", "", "send the `file` as a JSON request body; use - for stdin")
	return cmd
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

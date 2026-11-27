package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/heist-security/heist-go/heist"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/spf13/cobra"
)

// exitExportFailed is the exit status of `heist reports export-status` when
// the export ended without completing. 1 and 2 are errors and usage errors.
const exitExportFailed = 3

// failedExportStatuses are the export statuses that mean the export ended
// without completing. It may still have written some reports.
var failedExportStatuses = []heist.GetReportExport200JSONResponseBodyStatus{
	"FAILED", "CANCELLED", "TERMINATED", "TIMED_OUT",
}

func newReportsCmd() *cobra.Command {
	cmd := groupCmd(&cobra.Command{
		Use:   "reports",
		Short: "List, generate and download reports, and manage report scopes",
		Long: `List, generate and download reports, and manage report scopes.

Generating reports and changing report scopes require the Admin role and a
plan with reports.

` + envUsage,
	})
	cmd.AddCommand(
		newReportsListCmd(),
		newReportsGetCmd(),
		newReportsGenerateCmd(),
		newReportsExportStatusCmd(),
		newReportsDownloadCmd(),
		newReportScopesCmd(),
	)
	return cmd
}

func newReportScopesCmd() *cobra.Command {
	cmd := groupCmd(&cobra.Command{
		Use:   "scopes",
		Short: "List, create, update and delete report scopes",
		Long: `List, create, update and delete report scopes.

When a workspace has report scopes, reports generated automatically after a
pentest are produced once per scope.

` + envUsage,
	})
	cmd.AddCommand(
		newReportScopesListCmd(),
		newReportScopesCreateCmd(),
		newReportScopesUpdateCmd(),
		newReportScopesDeleteCmd(),
	)
	return cmd
}

// uuidsFlag collects comma-separated or repeated UUIDs. Empty values are
// rejected so that an empty shell variable can't widen `generate` to every
// application.
type uuidsFlag []openapi_types.UUID

func (u *uuidsFlag) String() string {
	s := make([]string, len(*u))
	for i, id := range *u {
		s[i] = id.String()
	}
	return strings.Join(s, ",")
}

func (u *uuidsFlag) Type() string { return "ids" }

func (u *uuidsFlag) Set(value string) error {
	for v := range strings.SplitSeq(value, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			return errors.New("empty ID")
		}
		id, err := parseUUID(v)
		if err != nil {
			return err
		}
		*u = append(*u, id)
	}
	return nil
}

func parseUUID(s string) (openapi_types.UUID, error) {
	var id openapi_types.UUID
	if err := id.UnmarshalText([]byte(s)); err != nil {
		return id, fmt.Errorf("invalid ID %q", s)
	}
	return id, nil
}

// reportRow is a report as shown in tables. The list and export responses
// use different generated types for the same report fields.
type reportRow struct {
	ID, Type, Status, Scope, Created, Title string
}

func newReportRow(id, reportType, status string, scopeName *string, created, title string) reportRow {
	scope := "-"
	if scopeName != nil && *scopeName != "" {
		scope = *scopeName
	}
	return reportRow{ID: id, Type: reportType, Status: status, Scope: scope, Created: created, Title: oneLine(title)}
}

// writeReportsTable writes reports as a table. Styled output leads with the
// title and dims the other fields.
func writeReportsTable(w io.Writer, s styles, reports []reportRow) error {
	rows := make([][]string, len(reports))
	if !s.on {
		for i, r := range reports {
			rows[i] = []string{r.ID, r.Type, r.Status, r.Scope, r.Created, r.Title}
		}
		return writeTable(w, s, []string{"ID", "TYPE", "STATUS", "SCOPE", "CREATED", "TITLE"}, rows)
	}
	for i, r := range reports {
		scope := r.Scope
		if scope == "-" {
			scope = ""
		}
		rows[i] = []string{r.Title, s.dim(joinDot(r.Type, scope, s.date(r.Created))), s.dim(r.Status), s.dim(r.ID)}
	}
	return s.list(w, rows, 0)
}

func newReportsListCmd() *cobra.Command {
	var exportID string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List workspace reports",
		Long:  "List workspace reports.\n\n" + envUsage,
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var params heist.ListReportsParams
			if exportID != "" {
				id, err := parseUUID(exportID)
				if err != nil {
					return usageErrorf("--export-id: %w", err)
				}
				params.ExportId = &id
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			var res *heist.ListReportsResponse
			err = withProgress(cmd, asJSON, "Fetching reports", func(ctx context.Context, _ progressFunc) error {
				res, err = client.ListReportsWithResponse(ctx, &params)
				return err
			})
			if err != nil {
				return err
			}
			if res.JSON200 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			}
			rows := make([]reportRow, len(*res.JSON200))
			for i, r := range *res.JSON200 {
				rows[i] = newReportRow(r.Id, string(r.ReportType), string(r.Status), r.ScopeName, r.CreatedAt, r.Title)
			}
			return printStyled(cmd, func(w io.Writer, s styles) error {
				return writeReportsTable(w, s, rows)
			})
		},
	}
	cmd.Flags().StringVar(&exportID, "export-id", "", "only reports from this export `id`, as printed by\nheist reports generate")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

func newReportsGetCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Show a report and its PDF versions",
		Long:  "Show a report and its retained PDF versions, newest first.\n\n" + envUsage,
		Args:  oneArg("report ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseUUID(args[0])
			if err != nil {
				return usageError{err}
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			var res *heist.GetReportResponse
			err = withProgress(cmd, asJSON, "Fetching report", func(ctx context.Context, _ progressFunc) error {
				res, err = client.GetReportWithResponse(ctx, id)
				return err
			})
			if err != nil {
				return err
			}
			if res.JSON200 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			}
			return printStyled(cmd, func(w io.Writer, s styles) error {
				return writeReportDetail(w, s, res)
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

// writeReportDetail writes a report and its versions. res must have a 200
// body. Styled output puts the title first, with the type, status, scope and
// date on one dim line.
func writeReportDetail(w io.Writer, s styles, res *heist.GetReportResponse) error {
	r := res.JSON200
	var scope string
	if r.ScopeName != nil {
		scope = *r.ScopeName
	}
	fields := fieldWriter{s: s}
	field := fields.add
	if s.on {
		_, err := fmt.Fprintf(w, "%s\n%s\n%s\n", s.bold(oneLine(r.Title)),
			s.dim(joinDot(string(r.ReportType), string(r.Status), scope, "created "+s.date(r.CreatedAt))),
			s.dim(r.Id))
		if err != nil {
			return err
		}
	} else {
		field("Title", oneLine(r.Title))
		field("ID", r.Id)
		field("Type", string(r.ReportType))
		field("Status", string(r.Status))
		field("Scope", scope)
	}
	if r.ScopeApplicationIds != nil {
		field("Applications", strings.Join(*r.ScopeApplicationIds, ", "))
	} else if r.ScopeApplicationId != nil {
		field("Applications", *r.ScopeApplicationId)
	}
	if !s.on {
		field("Created", r.CreatedAt)
	}
	if s.on && len(fields.fields) > 0 {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	if err := fields.write(w); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	rows := make([][]string, len(r.Versions))
	for i, v := range r.Versions {
		rows[i] = []string{v.Id, s.time(v.CreatedAt)}
	}
	return writeTable(w, s, []string{"VERSION", "CREATED"}, rows)
}

// exportPollInterval is how often `heist reports generate --wait` checks the
// export.
var exportPollInterval = 3 * time.Second

func newReportsGenerateCmd() *cobra.Command {
	var applications uuidsFlag
	var asJSON, wait bool
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Start generating reports and print the export ID",
		Long: `Start generating full, summary and attestation PDF reports, and print the
export ID. Generation runs in the background; check it with
heist reports export-status <export-id>. Previous reports are kept.

--wait waits for the export to end, then prints its state and reports, and
exits like heist reports export-status. With --json it prints the final
export-status JSON.

` + envUsage,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var body heist.GenerateReportJSONRequestBody
			if len(applications) > 0 {
				ids := []openapi_types.UUID(applications)
				body.ApplicationIds = &ids
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			res, err := client.GenerateReportWithResponse(cmd.Context(), body)
			if err != nil {
				return err
			}
			if res.JSON202 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			if wait {
				export, err := waitForExport(cmd, client, res.JSON202.ExportId, asJSON)
				if err != nil {
					return err
				}
				return writeExportResult(cmd, export, asJSON)
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			}
			id := res.JSON202.ExportId
			return printStyled(cmd, func(w io.Writer, s styles) error {
				if !s.on {
					_, err := fmt.Fprintln(w, id)
					return err
				}
				_, err := fmt.Fprintf(w, "%s\n%s\n", s.ok("Started generating reports "+s.dim("· export "+id.String())),
					s.dim("  Check on it with heist reports export-status "+id.String()))
				return err
			})
		},
	}
	cmd.Flags().Var(&applications, "application", "include this application, comma-separated or\nrepeated (default all in-scope applications)")
	cmd.Flags().BoolVar(&wait, "wait", false, "wait for the export to end and print its state")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

// waitForExport polls an export until it ends, showing its progress unless
// quiet is set. The returned response has a 200 body.
func waitForExport(cmd *cobra.Command, client *heist.ClientWithResponses, id openapi_types.UUID, quiet bool) (*heist.GetReportExportResponse, error) {
	var res *heist.GetReportExportResponse
	status := "Generating reports · export " + id.String()
	err := withProgress(cmd, quiet, status, func(ctx context.Context, progress progressFunc) error {
		for {
			var err error
			res, err = client.GetReportExportWithResponse(ctx, id)
			if err != nil {
				return err
			}
			if res.JSON200 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			switch s := res.JSON200.Status; {
			case s == "COMPLETED", s == "NOT_FOUND", slices.Contains(failedExportStatuses, s):
				return nil
			}
			progress(joinDot("Generating reports", plural(len(res.JSON200.Reports), "report")+" so far", "export "+id.String()), 0, 0)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(exportPollInterval):
			}
		}
	})
	return res, err
}

func newReportsExportStatusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "export-status <export-id>",
		Short: "Show a report export's state and its reports",
		Long: `Show a report export's state and the reports it has written so far.

Exit status:
  0   Success, and the export has not failed (it may still be RUNNING)
  1   Error, for example an API or authentication failure, or NOT_FOUND: no
      export has this ID, or its history has expired (its reports remain
      listed by heist reports list --export-id)
  2   Invalid usage
  3   The export ended without completing: FAILED, CANCELLED, TERMINATED or
      TIMED_OUT. It may still have written some reports.

` + envUsage,
		Args: oneArg("export ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseUUID(args[0])
			if err != nil {
				return usageError{err}
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			res, err := client.GetReportExportWithResponse(cmd.Context(), id)
			if err != nil {
				return err
			}
			if res.JSON200 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			return writeExportResult(cmd, res, asJSON)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

// writeExportResult writes an export's state, and returns an error when the
// export was not found or ended without completing. res must have a 200 body.
func writeExportResult(cmd *cobra.Command, res *heist.GetReportExportResponse, asJSON bool) error {
	var err error
	if asJSON {
		err = writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
	} else {
		err = printStyled(cmd, func(w io.Writer, s styles) error {
			return writeExportStatus(w, s, res)
		})
	}
	if err != nil {
		return err
	}
	switch status := res.JSON200.Status; {
	case status == "NOT_FOUND":
		return errors.New("export not found, or its history has expired")
	case slices.Contains(failedExportStatuses, status):
		return &exitError{exitExportFailed, fmt.Sprintf("export %s", status)}
	}
	return nil
}

// writeExportStatus writes an export's state and its reports. res must have
// a 200 body.
//
// Styled output starts with a result line: a check mark when the export
// completed, a cross when it failed, or how far it has got.
func writeExportStatus(w io.Writer, s styles, res *heist.GetReportExportResponse) error {
	e := res.JSON200
	value := func(v *string) string {
		if v == nil {
			return ""
		}
		return oneLine(*v)
	}
	if s.on {
		status := strings.ToLower(strings.ReplaceAll(string(e.Status), "_", " "))
		var result string
		switch {
		case e.Status == "COMPLETED":
			result = s.ok(joinDot("Reports generated", plural(len(e.Reports), "report")))
		case e.Status == "NOT_FOUND":
			result = s.fail("Export not found, or its history has expired")
		case slices.Contains(failedExportStatuses, e.Status):
			result = s.fail(joinDot("Export "+status, value(e.Failure)))
		default:
			result = joinDot("Export "+status, plural(len(e.Reports), "report")+" so far")
		}
		var closed string
		if e.ClosedAt != nil {
			closed = "closed " + s.time(*e.ClosedAt)
		}
		var started string
		if e.StartedAt != nil {
			started = "started " + s.time(*e.StartedAt)
		}
		if _, err := fmt.Fprintf(w, "%s\n%s\n", result, s.dim(joinDot("export "+e.ExportId, started, closed))); err != nil {
			return err
		}
	} else {
		fields := fieldWriter{s: s}
		fields.add("Export", e.ExportId)
		fields.add("Status", string(e.Status))
		fields.add("Started", value(e.StartedAt))
		fields.add("Closed", value(e.ClosedAt))
		fields.add("Failure", value(e.Failure))
		if err := fields.write(w); err != nil {
			return err
		}
	}
	if len(e.Reports) == 0 {
		return nil
	}
	rows := make([]reportRow, len(e.Reports))
	for i, r := range e.Reports {
		rows[i] = newReportRow(r.Id, string(r.ReportType), string(r.Status), r.ScopeName, r.CreatedAt, r.Title)
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	return writeReportsTable(w, s, rows)
}

func newReportsDownloadCmd() *cobra.Command {
	var versionID, output string
	cmd := &cobra.Command{
		Use:   "download <id>",
		Short: "Save a report's PDF",
		Long:  "Save a report's PDF.\n\n" + envUsage,
		Args:  oneArg("report ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseUUID(args[0])
			if err != nil {
				return usageError{err}
			}
			var params heist.DownloadReportParams
			if versionID != "" {
				v, err := parseUUID(versionID)
				if err != nil {
					return usageErrorf("--version: %w", err)
				}
				params.VersionId = &v
			}
			if output == "" {
				output = id.String() + ".pdf"
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			if output == "-" {
				pdf, err := openReportPDF(cmd.Context(), client, id, params)
				if err != nil {
					return err
				}
				defer pdf.Close()
				_, err = io.Copy(cmd.OutOrStdout(), pdf)
				return err
			}
			err = withProgress(cmd, false, "Downloading report", func(ctx context.Context, _ progressFunc) error {
				pdf, err := openReportPDF(ctx, client, id, params)
				if err != nil {
					return err
				}
				defer pdf.Close()
				return writeFileAtomic(output, pdf)
			})
			if err != nil {
				return err
			}
			return printStyled(cmd, func(w io.Writer, s styles) error {
				if !s.on {
					return nil // scripts see no output, as before
				}
				_, err := fmt.Fprintln(w, s.ok("Saved "+output))
				return err
			})
		},
	}
	cmd.Flags().StringVar(&versionID, "version", "", "download this version `id` (default the latest)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to `file` (default <id>.pdf); use - for stdout")
	return cmd
}

// openReportPDF requests a signed download URL for a report version and
// returns the PDF body. The caller closes it.
func openReportPDF(ctx context.Context, client *heist.ClientWithResponses, id openapi_types.UUID, params heist.DownloadReportParams) (io.ReadCloser, error) {
	res, err := client.DownloadReportWithResponse(ctx, id, &params)
	if err != nil {
		return nil, err
	}
	if res.JSON200 == nil {
		return nil, fmt.Errorf("unexpected %s response", res.Status())
	}
	// The signed URL is not an API endpoint, so fetch it without the SDK's
	// authentication.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, res.JSON200.Url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download PDF: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("download PDF: HTTP %s", resp.Status)
	}
	return resp.Body, nil
}

// writeFileAtomic writes r to path through a temporary file in the same
// directory, so a failed download leaves no partial file. The file is created
// with mode 0666 less the umask, like any other new file; os.CreateTemp would
// make it 0600.
func writeFileAtomic(path string, r io.Reader) error {
	tmp := filepath.Join(filepath.Dir(path), ".heist-download-"+rand.Text())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op after a successful rename
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func writeReportScopes(w io.Writer, s styles, scopes []heist.ReportScope) error {
	rows := make([][]string, len(scopes))
	for i, sc := range scopes {
		rows[i] = []string{sc.Id, oneLine(sc.Name), s.date(sc.CreatedAt), strings.Join(sc.ApplicationIds, ",")}
	}
	return writeTable(w, s, []string{"ID", "NAME", "CREATED", "APPLICATIONS"}, rows)
}

func newReportScopesListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List report scopes",
		Long:  "List report scopes.\n\n" + envUsage,
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			res, err := client.ListReportScopesWithResponse(cmd.Context())
			if err != nil {
				return err
			}
			if res.JSON200 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			}
			return printStyled(cmd, func(w io.Writer, s styles) error {
				return writeReportScopes(w, s, *res.JSON200)
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

// scopeInput holds the flags shared by scope create and update.
type scopeInput struct {
	name         string
	applications uuidsFlag
	json         bool
}

func (in *scopeInput) addFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&in.name, "name", "", "scope `name` (required)")
	cmd.Flags().Var(&in.applications, "application", "include this application, comma-separated or\nrepeated (at least one required)")
	cmd.Flags().BoolVar(&in.json, "json", false, "print the API's JSON response")
}

// body returns the request body. The API requires a name and at least one
// application for both create and update.
func (in *scopeInput) body() (heist.CreateReportScopeJSONRequestBody, error) {
	if strings.TrimSpace(in.name) == "" {
		return heist.CreateReportScopeJSONRequestBody{}, errors.New("--name is required")
	}
	if len(in.applications) == 0 {
		return heist.CreateReportScopeJSONRequestBody{}, errors.New("at least one --application is required")
	}
	return heist.CreateReportScopeJSONRequestBody{Name: in.name, ApplicationIds: in.applications}, nil
}

func newReportScopesCreateCmd() *cobra.Command {
	var in scopeInput
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a report scope",
		Long:  "Create a report scope from in-scope applications.\n\n" + envUsage,
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			body, err := in.body()
			if err != nil {
				return usageError{err}
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			res, err := client.CreateReportScopeWithResponse(cmd.Context(), body)
			if err != nil {
				return err
			}
			if res.JSON201 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			if in.json {
				return writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			}
			return printStyled(cmd, func(w io.Writer, s styles) error {
				return writeReportScopes(w, s, []heist.ReportScope{*res.JSON201})
			})
		},
	}
	in.addFlags(cmd)
	return cmd
}

func newReportScopesUpdateCmd() *cobra.Command {
	var in scopeInput
	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Replace a report scope's name and applications",
		Long: `Replace a report scope's name and applications. Existing reports keep the scope
name they were generated with.

` + envUsage,
		Args: oneArg("scope ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseUUID(args[0])
			if err != nil {
				return usageError{err}
			}
			body, err := in.body()
			if err != nil {
				return usageError{err}
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			res, err := client.UpdateReportScopeWithResponse(cmd.Context(), id, heist.UpdateReportScopeJSONRequestBody(body))
			if err != nil {
				return err
			}
			if res.JSON200 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			if in.json {
				return writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			}
			return printStyled(cmd, func(w io.Writer, s styles) error {
				return writeReportScopes(w, s, []heist.ReportScope{*res.JSON200})
			})
		},
	}
	in.addFlags(cmd)
	return cmd
}

func newReportScopesDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a report scope",
		Long:  "Delete a report scope. Reports generated for it are kept.\n\n" + envUsage,
		Args:  oneArg("scope ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseUUID(args[0])
			if err != nil {
				return usageError{err}
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			res, err := client.DeleteReportScopeWithResponse(cmd.Context(), id)
			if err != nil {
				return err
			}
			if res.JSON200 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			return nil
		},
	}
}

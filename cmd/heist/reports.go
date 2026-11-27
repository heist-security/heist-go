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
	"text/tabwriter"

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

func writeReportsTable(w io.Writer, reports []reportRow) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTYPE\tSTATUS\tSCOPE\tCREATED\tTITLE")
	for _, r := range reports {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Type, r.Status, r.Scope, r.Created, r.Title)
	}
	return tw.Flush()
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
			res, err := client.ListReportsWithResponse(cmd.Context(), &params)
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
			return writeReportsTable(cmd.OutOrStdout(), rows)
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
			res, err := client.GetReportWithResponse(cmd.Context(), id)
			if err != nil {
				return err
			}
			if res.JSON200 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			}
			return writeReportDetail(cmd.OutOrStdout(), res)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

// writeReportDetail writes a report and its versions. res must have a 200
// body.
func writeReportDetail(w io.Writer, res *heist.GetReportResponse) error {
	r := res.JSON200
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	field := func(label, value string) {
		if value != "" {
			fmt.Fprintf(tw, "%s:\t%s\n", label, value)
		}
	}
	field("Title", oneLine(r.Title))
	field("ID", r.Id)
	field("Type", string(r.ReportType))
	field("Status", string(r.Status))
	if r.ScopeName != nil {
		field("Scope", *r.ScopeName)
	}
	if r.ScopeApplicationIds != nil {
		field("Applications", strings.Join(*r.ScopeApplicationIds, ", "))
	} else if r.ScopeApplicationId != nil {
		field("Applications", *r.ScopeApplicationId)
	}
	field("Created", r.CreatedAt)
	if err := tw.Flush(); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "VERSION\tCREATED")
	for _, v := range r.Versions {
		fmt.Fprintf(tw, "%s\t%s\n", v.Id, v.CreatedAt)
	}
	return tw.Flush()
}

func newReportsGenerateCmd() *cobra.Command {
	var applications uuidsFlag
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Start generating reports and print the export ID",
		Long: `Start generating full, summary and attestation PDF reports, and print the
export ID. Generation runs in the background; check it with
heist reports export-status <export-id>. Previous reports are kept.

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
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), res.JSON202.ExportId)
			return err
		},
	}
	cmd.Flags().Var(&applications, "application", "include this application, comma-separated or\nrepeated (default all in-scope applications)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
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
			if asJSON {
				err = writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			} else {
				err = writeExportStatus(cmd.OutOrStdout(), res)
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
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

// writeExportStatus writes an export's state and its reports. res must have
// a 200 body.
func writeExportStatus(w io.Writer, res *heist.GetReportExportResponse) error {
	e := res.JSON200
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	field := func(label string, value *string) {
		if value != nil && *value != "" {
			fmt.Fprintf(tw, "%s:\t%s\n", label, oneLine(*value))
		}
	}
	status := string(e.Status)
	field("Export", &e.ExportId)
	field("Status", &status)
	field("Started", e.StartedAt)
	field("Closed", e.ClosedAt)
	field("Failure", e.Failure)
	if err := tw.Flush(); err != nil {
		return err
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
	return writeReportsTable(w, rows)
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
			pdf, err := openReportPDF(cmd.Context(), client, id, params)
			if err != nil {
				return err
			}
			defer pdf.Close()
			if output == "-" {
				_, err = io.Copy(cmd.OutOrStdout(), pdf)
				return err
			}
			return writeFileAtomic(output, pdf)
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

func writeReportScopes(w io.Writer, scopes []heist.ReportScope) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tCREATED\tAPPLICATIONS")
	for _, s := range scopes {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.Id, oneLine(s.Name), s.CreatedAt, strings.Join(s.ApplicationIds, ","))
	}
	return tw.Flush()
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
			return writeReportScopes(cmd.OutOrStdout(), *res.JSON200)
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
			return writeReportScopes(cmd.OutOrStdout(), []heist.ReportScope{*res.JSON201})
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
			return writeReportScopes(cmd.OutOrStdout(), []heist.ReportScope{*res.JSON200})
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

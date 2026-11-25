package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
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
)

// exitExportFailed is the exit status of `heist reports export-status` when
// the export ended without completing. 1 and 2 are errors and usage errors.
const exitExportFailed = 3

// failedExportStatuses are the export statuses that mean the export ended
// without completing. It may still have written some reports.
var failedExportStatuses = []heist.GetReportExport200JSONResponseBodyStatus{
	"FAILED", "CANCELLED", "TERMINATED", "TIMED_OUT",
}

const reportsUsage = `Usage: heist reports <command> [flags]

Commands:
  list            List workspace reports
  get             Show a report and its PDF versions
  generate        Start generating reports and print the export ID
  export-status   Show a report export's state and its reports
  download        Save a report's PDF
  scopes          List, create, update and delete report scopes

Run heist reports <command> -h for each command's flags. Generating reports
and changing report scopes require the Admin role and a plan with reports.

` + envUsage

const reportsListUsage = `Usage: heist reports list [--export-id id] [--json]

List workspace reports.

Flags:
      --export-id id   Only reports from this export, as printed by
                       heist reports generate
      --json           Print the API's JSON response

` + envUsage

const reportsGetUsage = `Usage: heist reports get [--json] <id>

Show a report and its retained PDF versions, newest first.

Flags:
      --json   Print the API's JSON response

` + envUsage

const reportsGenerateUsage = `Usage: heist reports generate [--application id]... [--json]

Start generating full, summary and attestation PDF reports, and print the
export ID. Generation runs in the background; check it with
heist reports export-status <export-id>. Previous reports are kept.

Flags:
      --application id   Include this application, comma-separated or
                         repeated (default all in-scope applications)
      --json             Print the API's JSON response

` + envUsage

const reportsExportStatusUsage = `Usage: heist reports export-status [--json] <export-id>

Show a report export's state and the reports it has written so far.

Flags:
      --json   Print the API's JSON response

Exit status:
  0   Success, and the export has not failed (it may still be RUNNING)
  1   Error, for example an API or authentication failure
  2   Invalid usage
  3   The export ended without completing: FAILED, CANCELLED, TERMINATED or
      TIMED_OUT. It may still have written some reports.

` + envUsage

const reportsDownloadUsage = `Usage: heist reports download [--version id] [-o file] <id>

Save a report's PDF.

Flags:
      --version id   Download this version (default the latest)
  -o, --output file  Write to file (default <id>.pdf); use - for stdout

` + envUsage

const reportScopesUsage = `Usage: heist reports scopes <command> [flags]

Commands:
  list     List report scopes
  create   Create a report scope
  update   Replace a report scope's name and applications
  delete   Delete a report scope

When a workspace has report scopes, reports generated automatically after a
pentest are produced once per scope. Run heist reports scopes <command> -h for
each command's flags.

` + envUsage

const reportScopesListUsage = `Usage: heist reports scopes list [--json]

List report scopes.

Flags:
      --json   Print the API's JSON response

` + envUsage

const reportScopesCreateUsage = `Usage: heist reports scopes create --name name --application id... [--json]

Create a report scope from in-scope applications.

Flags:
      --name name        Scope name (required)
      --application id   Include this application, comma-separated or
                         repeated (at least one required)
      --json             Print the API's JSON response

` + envUsage

const reportScopesUpdateUsage = `Usage: heist reports scopes update --name name --application id... [--json] <id>

Replace a report scope's name and applications. Existing reports keep the scope
name they were generated with.

Flags:
      --name name        Scope name (required)
      --application id   Include this application, comma-separated or
                         repeated (at least one required)
      --json             Print the API's JSON response

` + envUsage

const reportScopesDeleteUsage = `Usage: heist reports scopes delete <id>

Delete a report scope. Reports generated for it are kept.

` + envUsage

func runReports(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, reportsUsage)
		return 2
	}
	switch args[0] {
	case "list":
		return runReportsList(args[1:], stdout, stderr)
	case "get":
		return runReportsGet(args[1:], stdout, stderr)
	case "generate":
		return runReportsGenerate(args[1:], stdout, stderr)
	case "export-status":
		return runReportsExportStatus(args[1:], stdout, stderr)
	case "download":
		return runReportsDownload(args[1:], stdout, stderr)
	case "scopes":
		return runReportScopes(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, reportsUsage)
		return 0
	default:
		fmt.Fprintf(stderr, "heist reports: unknown command %q\n\n%s", args[0], reportsUsage)
		return 2
	}
}

func runReportScopes(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, reportScopesUsage)
		return 2
	}
	switch args[0] {
	case "list":
		return runReportScopesList(args[1:], stdout, stderr)
	case "create":
		return runReportScopesCreate(args[1:], stdout, stderr)
	case "update":
		return runReportScopesUpdate(args[1:], stdout, stderr)
	case "delete":
		return runReportScopesDelete(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, reportScopesUsage)
		return 0
	default:
		fmt.Fprintf(stderr, "heist reports scopes: unknown command %q\n\n%s", args[0], reportScopesUsage)
		return 2
	}
}

// uuidsFlag collects comma-separated or repeated UUIDs.
type uuidsFlag []openapi_types.UUID

func (u *uuidsFlag) String() string {
	s := make([]string, len(*u))
	for i, id := range *u {
		s[i] = id.String()
	}
	return strings.Join(s, ",")
}

func (u *uuidsFlag) Set(value string) error {
	for v := range strings.SplitSeq(value, ",") {
		if v = strings.TrimSpace(v); v == "" {
			continue
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

// idArg parses the single ID argument of a command.
func idArg(fs *flag.FlagSet, kind string) (openapi_types.UUID, error) {
	if fs.NArg() != 1 {
		return openapi_types.UUID{}, fmt.Errorf("expected one %s ID", kind)
	}
	return parseUUID(fs.Arg(0))
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

func runReportsList(args []string, stdout, stderr io.Writer) int {
	const name = "reports list"
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	exportID := fs.String("export-id", "", "")
	asJSON := fs.Bool("json", false, "")
	if code, ok := parseFlags(fs, args, reportsListUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 {
		return usageError(stderr, name, "unexpected arguments", reportsListUsage)
	}
	var params heist.ListReportsParams
	if *exportID != "" {
		id, err := parseUUID(*exportID)
		if err != nil {
			return usageError(stderr, name, "--export-id: "+err.Error(), reportsListUsage)
		}
		params.ExportId = &id
	}

	client, err := newClient()
	if err != nil {
		return printError(stderr, name, err)
	}
	res, err := client.ListReportsWithResponse(context.Background(), &params)
	if err != nil {
		return printError(stderr, name, err)
	}
	if res.JSON200 == nil {
		return printError(stderr, name, fmt.Errorf("unexpected %s response", res.Status()))
	}
	if *asJSON {
		err = writeJSON(stdout, json.RawMessage(res.Body))
	} else {
		rows := make([]reportRow, len(*res.JSON200))
		for i, r := range *res.JSON200 {
			rows[i] = newReportRow(r.Id, string(r.ReportType), string(r.Status), r.ScopeName, r.CreatedAt, r.Title)
		}
		err = writeReportsTable(stdout, rows)
	}
	if err != nil {
		return printError(stderr, name, err)
	}
	return 0
}

func runReportsGet(args []string, stdout, stderr io.Writer) int {
	const name = "reports get"
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	if code, ok := parseFlags(fs, args, reportsGetUsage, stdout, stderr); !ok {
		return code
	}
	id, err := idArg(fs, "report")
	if err != nil {
		return usageError(stderr, name, err.Error(), reportsGetUsage)
	}

	client, err := newClient()
	if err != nil {
		return printError(stderr, name, err)
	}
	res, err := client.GetReportWithResponse(context.Background(), id)
	if err != nil {
		return printError(stderr, name, err)
	}
	if res.JSON200 == nil {
		return printError(stderr, name, fmt.Errorf("unexpected %s response", res.Status()))
	}
	if *asJSON {
		err = writeJSON(stdout, json.RawMessage(res.Body))
	} else {
		err = writeReportDetail(stdout, res)
	}
	if err != nil {
		return printError(stderr, name, err)
	}
	return 0
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

func runReportsGenerate(args []string, stdout, stderr io.Writer) int {
	const name = "reports generate"
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	var applications uuidsFlag
	fs.Var(&applications, "application", "")
	asJSON := fs.Bool("json", false, "")
	if code, ok := parseFlags(fs, args, reportsGenerateUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 {
		return usageError(stderr, name, "unexpected arguments", reportsGenerateUsage)
	}
	var body heist.GenerateReportJSONRequestBody
	if len(applications) > 0 {
		ids := []openapi_types.UUID(applications)
		body.ApplicationIds = &ids
	}

	client, err := newClient()
	if err != nil {
		return printError(stderr, name, err)
	}
	res, err := client.GenerateReportWithResponse(context.Background(), body)
	if err != nil {
		return printError(stderr, name, err)
	}
	if res.JSON202 == nil {
		return printError(stderr, name, fmt.Errorf("unexpected %s response", res.Status()))
	}
	if *asJSON {
		err = writeJSON(stdout, json.RawMessage(res.Body))
	} else {
		_, err = fmt.Fprintln(stdout, res.JSON202.ExportId)
	}
	if err != nil {
		return printError(stderr, name, err)
	}
	return 0
}

func runReportsExportStatus(args []string, stdout, stderr io.Writer) int {
	const name = "reports export-status"
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	if code, ok := parseFlags(fs, args, reportsExportStatusUsage, stdout, stderr); !ok {
		return code
	}
	id, err := idArg(fs, "export")
	if err != nil {
		return usageError(stderr, name, err.Error(), reportsExportStatusUsage)
	}

	client, err := newClient()
	if err != nil {
		return printError(stderr, name, err)
	}
	res, err := client.GetReportExportWithResponse(context.Background(), id)
	if err != nil {
		return printError(stderr, name, err)
	}
	if res.JSON200 == nil {
		return printError(stderr, name, fmt.Errorf("unexpected %s response", res.Status()))
	}
	if *asJSON {
		err = writeJSON(stdout, json.RawMessage(res.Body))
	} else {
		err = writeExportStatus(stdout, res)
	}
	if err != nil {
		return printError(stderr, name, err)
	}
	if status := res.JSON200.Status; slices.Contains(failedExportStatuses, status) {
		fmt.Fprintf(stderr, "heist %s: export %s\n", name, status)
		return exitExportFailed
	}
	return 0
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

func runReportsDownload(args []string, stdout, stderr io.Writer) int {
	const name = "reports download"
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	versionID := fs.String("version", "", "")
	output := fs.String("o", "", "")
	fs.StringVar(output, "output", "", "")
	if code, ok := parseFlags(fs, args, reportsDownloadUsage, stdout, stderr); !ok {
		return code
	}
	id, err := idArg(fs, "report")
	if err != nil {
		return usageError(stderr, name, err.Error(), reportsDownloadUsage)
	}
	var params heist.DownloadReportParams
	if *versionID != "" {
		v, err := parseUUID(*versionID)
		if err != nil {
			return usageError(stderr, name, "--version: "+err.Error(), reportsDownloadUsage)
		}
		params.VersionId = &v
	}
	if *output == "" {
		*output = id.String() + ".pdf"
	}

	client, err := newClient()
	if err != nil {
		return printError(stderr, name, err)
	}
	ctx := context.Background()
	pdf, err := openReportPDF(ctx, client, id, params)
	if err != nil {
		return printError(stderr, name, err)
	}
	defer pdf.Close()
	if *output == "-" {
		_, err = io.Copy(stdout, pdf)
	} else {
		err = writeFileAtomic(*output, pdf)
	}
	if err != nil {
		return printError(stderr, name, err)
	}
	return 0
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
// directory, so a failed download leaves no partial file.
func writeFileAtomic(path string, r io.Reader) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".heist-download-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op after a successful rename
	// CreateTemp makes the file private; use the usual mode for a download.
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
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

func runReportScopesList(args []string, stdout, stderr io.Writer) int {
	const name = "reports scopes list"
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	if code, ok := parseFlags(fs, args, reportScopesListUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 {
		return usageError(stderr, name, "unexpected arguments", reportScopesListUsage)
	}

	client, err := newClient()
	if err != nil {
		return printError(stderr, name, err)
	}
	res, err := client.ListReportScopesWithResponse(context.Background())
	if err != nil {
		return printError(stderr, name, err)
	}
	if res.JSON200 == nil {
		return printError(stderr, name, fmt.Errorf("unexpected %s response", res.Status()))
	}
	if *asJSON {
		err = writeJSON(stdout, json.RawMessage(res.Body))
	} else {
		err = writeReportScopes(stdout, *res.JSON200)
	}
	if err != nil {
		return printError(stderr, name, err)
	}
	return 0
}

// scopeInput holds the flags shared by scope create and update.
type scopeInput struct {
	name         string
	applications uuidsFlag
	json         bool
}

func newScopeFlags(name string) (*flag.FlagSet, *scopeInput) {
	in := &scopeInput{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&in.name, "name", "", "")
	fs.Var(&in.applications, "application", "")
	fs.BoolVar(&in.json, "json", false, "")
	return fs, in
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

func runReportScopesCreate(args []string, stdout, stderr io.Writer) int {
	const name = "reports scopes create"
	fs, in := newScopeFlags(name)
	if code, ok := parseFlags(fs, args, reportScopesCreateUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 {
		return usageError(stderr, name, "unexpected arguments", reportScopesCreateUsage)
	}
	body, err := in.body()
	if err != nil {
		return usageError(stderr, name, err.Error(), reportScopesCreateUsage)
	}

	client, err := newClient()
	if err != nil {
		return printError(stderr, name, err)
	}
	res, err := client.CreateReportScopeWithResponse(context.Background(), body)
	if err != nil {
		return printError(stderr, name, err)
	}
	if res.JSON201 == nil {
		return printError(stderr, name, fmt.Errorf("unexpected %s response", res.Status()))
	}
	if in.json {
		err = writeJSON(stdout, json.RawMessage(res.Body))
	} else {
		err = writeReportScopes(stdout, []heist.ReportScope{*res.JSON201})
	}
	if err != nil {
		return printError(stderr, name, err)
	}
	return 0
}

func runReportScopesUpdate(args []string, stdout, stderr io.Writer) int {
	const name = "reports scopes update"
	fs, in := newScopeFlags(name)
	if code, ok := parseFlags(fs, args, reportScopesUpdateUsage, stdout, stderr); !ok {
		return code
	}
	id, err := idArg(fs, "scope")
	if err != nil {
		return usageError(stderr, name, err.Error(), reportScopesUpdateUsage)
	}
	body, err := in.body()
	if err != nil {
		return usageError(stderr, name, err.Error(), reportScopesUpdateUsage)
	}

	client, err := newClient()
	if err != nil {
		return printError(stderr, name, err)
	}
	res, err := client.UpdateReportScopeWithResponse(context.Background(), id, heist.UpdateReportScopeJSONRequestBody(body))
	if err != nil {
		return printError(stderr, name, err)
	}
	if res.JSON200 == nil {
		return printError(stderr, name, fmt.Errorf("unexpected %s response", res.Status()))
	}
	if in.json {
		err = writeJSON(stdout, json.RawMessage(res.Body))
	} else {
		err = writeReportScopes(stdout, []heist.ReportScope{*res.JSON200})
	}
	if err != nil {
		return printError(stderr, name, err)
	}
	return 0
}

func runReportScopesDelete(args []string, stdout, stderr io.Writer) int {
	const name = "reports scopes delete"
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	if code, ok := parseFlags(fs, args, reportScopesDeleteUsage, stdout, stderr); !ok {
		return code
	}
	id, err := idArg(fs, "scope")
	if err != nil {
		return usageError(stderr, name, err.Error(), reportScopesDeleteUsage)
	}

	client, err := newClient()
	if err != nil {
		return printError(stderr, name, err)
	}
	res, err := client.DeleteReportScopeWithResponse(context.Background(), id)
	if err != nil {
		return printError(stderr, name, err)
	}
	if res.JSON200 == nil {
		return printError(stderr, name, fmt.Errorf("unexpected %s response", res.Status()))
	}
	return 0
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"iter"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/heist-security/heist-go/heist"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

// exitFailOn is the exit status of `heist findings list --fail-on` when a
// finding reaches the threshold. 1 and 2 are errors and usage errors.
const exitFailOn = 3

// severities lists finding severities from lowest to highest.
var severities = []heist.ListFindingsParamsSeverity{
	heist.ListFindingsParamsSeverityINFORMATIONAL,
	heist.ListFindingsParamsSeverityLOW,
	heist.ListFindingsParamsSeverityMEDIUM,
	heist.ListFindingsParamsSeverityHIGH,
	heist.ListFindingsParamsSeverityCRITICAL,
}

// openStatuses are the statuses --fail-on and counts consider by default.
// The API's /findings/counts "open" bucket is PUBLISHED findings.
var openStatuses = []heist.ListFindingsParamsStatus{heist.ListFindingsParamsStatusPUBLISHED}

const findingsUsage = `Usage: heist findings <command> [flags]

Commands:
  list     List findings, optionally failing on a severity threshold
  get      Show a finding's full detail
  counts   Count findings by status and severity

Run heist findings <command> -h for each command's flags.

` + envUsage

const findingsListUsage = `Usage: heist findings list [flags]

List findings matching the filters, following pagination, as a table or JSON.

Flags:
      --severity list   Only these severities, comma-separated or repeated:
                        INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
      --status list     Only these statuses, comma-separated or repeated:
                        PUBLISHED (open), FIXED, ACCEPTED, COMPENSATING_CONTROL
      --search text     Only findings matching the search text
      --limit n         Print at most n findings (default all)
      --fail-on sev     Exit 3 when any finding matching the filters is at or
                        above severity sev. Only open (PUBLISHED) findings
                        count unless --status is given. --limit does not
                        affect the check.
      --json            Print a JSON array of findings

Exit status:
  0   Success, and no finding reached the --fail-on severity
  1   Error, for example an API or authentication failure
  2   Invalid usage
  3   A finding reached the --fail-on severity

` + envUsage

const findingsGetUsage = `Usage: heist findings get [--json] <id>

Show a finding's full detail, including its report and linked application,
repository, and route.

Flags:
      --json   Print the API's JSON response

` + envUsage

const findingsCountsUsage = `Usage: heist findings counts [--status list] [--json]

Count findings by status, and by severity for the given statuses.

Flags:
      --status list   Statuses the severity counts include, comma-separated or
                      repeated (default PUBLISHED, the open findings)
      --json          Print the counts as JSON

` + envUsage

func runFindings(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, findingsUsage)
		return 2
	}
	switch args[0] {
	case "list":
		return runFindingsList(args[1:], stdout, stderr)
	case "get":
		return runFindingsGet(args[1:], stdout, stderr)
	case "counts":
		return runFindingsCounts(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, findingsUsage)
		return 0
	default:
		fmt.Fprintf(stderr, "heist findings: unknown command %q\n\n%s", args[0], findingsUsage)
		return 2
	}
}

// listFlag collects comma-separated or repeated values, upper-cased to match
// the API's enum values.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(value string) error {
	for v := range strings.SplitSeq(value, ",") {
		if v = strings.TrimSpace(v); v != "" {
			*l = append(*l, strings.ToUpper(v))
		}
	}
	return nil
}

// parseFlags parses args, printing usage on -h or a parse error. It returns
// ok=false with the exit status when the command should stop.
func parseFlags(fs *flag.FlagSet, args []string, usage string, stdout, stderr io.Writer) (code int, ok bool) {
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return 0, false
		}
		fmt.Fprintf(stderr, "heist %s: %v\n\n%s", fs.Name(), err, usage)
		return 2, false
	}
	return 0, true
}

func usageError(stderr io.Writer, command, msg, usage string) int {
	fmt.Fprintf(stderr, "heist %s: %s\n\n%s", command, msg, usage)
	return 2
}

func runFindingsList(args []string, stdout, stderr io.Writer) int {
	const name = "findings list"
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	var severity, status listFlag
	fs.Var(&severity, "severity", "")
	fs.Var(&status, "status", "")
	search := fs.String("search", "", "")
	limit := fs.Int("limit", 0, "")
	failOn := fs.String("fail-on", "", "")
	asJSON := fs.Bool("json", false, "")
	if code, ok := parseFlags(fs, args, findingsListUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 {
		return usageError(stderr, name, "unexpected arguments", findingsListUsage)
	}
	if *limit < 0 {
		return usageError(stderr, name, "--limit must not be negative", findingsListUsage)
	}
	threshold := -1
	if *failOn != "" {
		threshold = slices.Index(severities, heist.ListFindingsParamsSeverity(strings.ToUpper(*failOn)))
		if threshold < 0 {
			return usageError(stderr, name, fmt.Sprintf("unknown --fail-on severity %q", *failOn), findingsListUsage)
		}
	}

	params := listParams(severity, status, *search)
	if *limit > 0 {
		size := min(*limit, 100) // the API's maximum page size
		params.Size = &size
	}
	client, err := newClient()
	if err != nil {
		return printError(stderr, name, err)
	}
	ctx := context.Background()
	findings := []json.RawMessage{}
	for finding, err := range allRawFindings(ctx, client, params) {
		if err != nil {
			return printError(stderr, name, err)
		}
		findings = append(findings, finding)
		if len(findings) == *limit {
			break
		}
	}
	if *asJSON {
		err = writeJSON(stdout, findings)
	} else {
		typed := make([]heist.Finding, len(findings))
		for i, raw := range findings {
			if err := json.Unmarshal(raw, &typed[i]); err != nil {
				return printError(stderr, name, err)
			}
		}
		err = writeFindingsTable(stdout, typed)
	}
	if err != nil {
		return printError(stderr, name, err)
	}

	if threshold < 0 {
		return 0
	}
	n, err := countAtOrAbove(ctx, client, params, severities[threshold])
	if err != nil {
		return printError(stderr, name, err)
	}
	if n > 0 {
		fmt.Fprintf(stderr, "heist %s: %d finding(s) at or above %s\n", name, n, severities[threshold])
		return exitFailOn
	}
	return 0
}

// allRawFindings yields every finding matching params as the API's JSON, so
// --json output keeps fields added by later API releases. It ignores
// params.Page.
func allRawFindings(ctx context.Context, client *heist.ClientWithResponses, params heist.ListFindingsParams) iter.Seq2[json.RawMessage, error] {
	return heist.Paginate(ctx, func(ctx context.Context, page int) ([]json.RawMessage, int, error) {
		params.Page = &page
		res, err := client.ListFindingsWithResponse(ctx, &params)
		if err != nil {
			return nil, 0, err
		}
		if res.JSON200 == nil {
			return nil, 0, fmt.Errorf("unexpected %s response", res.Status())
		}
		var body struct {
			Items []json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(res.Body, &body); err != nil {
			return nil, 0, err
		}
		return body.Items, res.JSON200.Total, nil
	})
}

// countAtOrAbove counts findings matching params whose severity is at or
// above threshold, considering only open findings unless params sets statuses.
func countAtOrAbove(ctx context.Context, client *heist.ClientWithResponses, params heist.ListFindingsParams, threshold heist.ListFindingsParamsSeverity) (int, error) {
	gate := severities[slices.Index(severities, threshold):]
	if params.Severity != nil {
		gate = slices.DeleteFunc(slices.Clone(gate), func(s heist.ListFindingsParamsSeverity) bool {
			return !slices.Contains(*params.Severity, s)
		})
		if len(gate) == 0 {
			return 0, nil
		}
	}
	params.Severity = &gate
	if params.Status == nil {
		params.Status = &openStatuses
	}
	return client.CountFindings(ctx, params)
}

func listParams(severity, status []string, search string) heist.ListFindingsParams {
	var params heist.ListFindingsParams
	if len(severity) > 0 {
		s := make([]heist.ListFindingsParamsSeverity, len(severity))
		for i, v := range severity {
			s[i] = heist.ListFindingsParamsSeverity(v)
		}
		params.Severity = &s
	}
	if len(status) > 0 {
		s := make([]heist.ListFindingsParamsStatus, len(status))
		for i, v := range status {
			s[i] = heist.ListFindingsParamsStatus(v)
		}
		params.Status = &s
	}
	if search != "" {
		params.Search = &search
	}
	return params
}

func writeFindingsTable(w io.Writer, findings []heist.Finding) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tSTATUS\tTITLE")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Id, f.Severity, f.ValidationStatus, oneLine(f.Title))
	}
	return tw.Flush()
}

func runFindingsGet(args []string, stdout, stderr io.Writer) int {
	const name = "findings get"
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	if code, ok := parseFlags(fs, args, findingsGetUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 1 {
		return usageError(stderr, name, "expected one finding ID", findingsGetUsage)
	}
	var id openapi_types.UUID
	if err := id.UnmarshalText([]byte(fs.Arg(0))); err != nil {
		return usageError(stderr, name, fmt.Sprintf("invalid finding ID %q", fs.Arg(0)), findingsGetUsage)
	}

	client, err := newClient()
	if err != nil {
		return printError(stderr, name, err)
	}
	res, err := client.GetFindingWithResponse(context.Background(), id)
	if err != nil {
		return printError(stderr, name, err)
	}
	if res.JSON200 == nil {
		return printError(stderr, name, fmt.Errorf("unexpected %s response", res.Status()))
	}
	if *asJSON {
		err = writeJSON(stdout, json.RawMessage(res.Body))
	} else {
		err = writeFindingDetail(stdout, res.JSON200)
	}
	if err != nil {
		return printError(stderr, name, err)
	}
	return 0
}

func writeFindingDetail(w io.Writer, f *heist.FindingDetail) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	field := func(label, value string) {
		if value != "" {
			fmt.Fprintf(tw, "%s:\t%s\n", label, value)
		}
	}
	field("Title", oneLine(f.Title))
	field("ID", f.Id)
	field("Severity", string(f.Severity))
	field("Status", string(f.ValidationStatus))
	field("Category", f.Category)
	field("Type", f.Type)
	field("Source", string(f.SourceKind))
	field("Created", f.CreatedAt)
	field("Updated", f.UpdatedAt)
	if f.Application != nil {
		field("Application", f.Application.Url)
	}
	if f.Repository != nil {
		field("Repository", f.Repository.Owner+"/"+f.Repository.Name)
	}
	if r := f.Route; r != nil {
		route := r.Url
		if r.HttpMethods != nil && len(*r.HttpMethods) > 0 {
			route = strings.Join(*r.HttpMethods, ",") + " " + route
		}
		if r.GraphqlOperationName != nil {
			route += " (" + *r.GraphqlOperationName + ")"
		}
		field("Route", route)
	}
	if f.InjectionPoint != nil {
		field("Injection point", f.InjectionPoint.Type)
	}
	if m := f.IssueMetadata; m != nil {
		field("Issue", m.Provider+" "+m.IssueUrl)
	}
	if f.RuntimeValidationOutcome != nil {
		field("Runtime validation", string(*f.RuntimeValidationOutcome))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	sections := []struct {
		title string
		text  *string
	}{
		{"Description", &f.Description},
		{"Attack scenario", f.AttackScenario},
		{"Impact", f.Impact},
		{"Likelihood", f.Likelihood},
		{"Evidence", f.Evidence},
		{"Steps to reproduce", f.StepsToReproduce},
		{"Recommendation", f.Recommendation},
		{"References", f.References},
		{"Runtime validation reason", f.RuntimeValidationReason},
		{"Validation reason", f.ValidationReason},
		{"Accept reason", f.AcceptReason},
		{"Compensating control reason", f.CompensatingControlReason},
		{"Retest comment", f.RetestComment},
	}
	for _, s := range sections {
		if s.text == nil || strings.TrimSpace(*s.text) == "" {
			continue
		}
		if _, err := fmt.Fprintf(w, "\n%s:\n%s\n", s.title, strings.TrimRight(*s.text, "\n")); err != nil {
			return err
		}
	}
	return nil
}

// findingCounts is the JSON output of `heist findings counts`.
type findingCounts struct {
	// Status is the API's /findings/counts response, as received.
	Status json.RawMessage `json:"status"`
	// Severity counts findings with SeverityStatuses by severity.
	Severity         map[heist.ListFindingsParamsSeverity]int `json:"severity"`
	SeverityStatuses []heist.ListFindingsParamsStatus         `json:"severityStatuses"`
}

func runFindingsCounts(args []string, stdout, stderr io.Writer) int {
	const name = "findings counts"
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	var status listFlag
	fs.Var(&status, "status", "")
	asJSON := fs.Bool("json", false, "")
	if code, ok := parseFlags(fs, args, findingsCountsUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 {
		return usageError(stderr, name, "unexpected arguments", findingsCountsUsage)
	}

	client, err := newClient()
	if err != nil {
		return printError(stderr, name, err)
	}
	ctx := context.Background()
	res, err := client.FindingCountsWithResponse(ctx)
	if err != nil {
		return printError(stderr, name, err)
	}
	if res.JSON200 == nil {
		return printError(stderr, name, fmt.Errorf("unexpected %s response", res.Status()))
	}
	params := listParams(nil, status, "")
	if params.Status == nil {
		params.Status = &openStatuses
	}
	counts := findingCounts{
		Status:           res.Body,
		Severity:         map[heist.ListFindingsParamsSeverity]int{},
		SeverityStatuses: *params.Status,
	}
	for _, s := range severities {
		params.Severity = &[]heist.ListFindingsParamsSeverity{s}
		if counts.Severity[s], err = client.CountFindings(ctx, params); err != nil {
			return printError(stderr, name, err)
		}
	}

	if *asJSON {
		err = writeJSON(stdout, counts)
	} else {
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		c := res.JSON200
		fmt.Fprintf(tw, "STATUS\tCOUNT\nopen\t%d\nclosed\t%d\naccepted\t%d\ncompensating control\t%d\nall\t%d\n",
			c.Open, c.Closed, c.Accepted, c.CompensatingControl, c.All)
		var scope []string
		for _, s := range counts.SeverityStatuses {
			scope = append(scope, string(s))
		}
		fmt.Fprintf(tw, "\nSEVERITY (%s)\tCOUNT\n", strings.Join(scope, ","))
		for _, s := range slices.Backward(severities) {
			fmt.Fprintf(tw, "%s\t%d\n", s, counts.Severity[s])
		}
		err = tw.Flush()
	}
	if err != nil {
		return printError(stderr, name, err)
	}
	return 0
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// oneLine collapses whitespace so a value fits on one table row.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

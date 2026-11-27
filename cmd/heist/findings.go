package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/heist-security/heist-go/heist"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/spf13/cobra"
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

func newFindingsCmd() *cobra.Command {
	cmd := groupCmd(&cobra.Command{
		Use:   "findings",
		Short: "List, show and count findings, and gate CI on severity",
		Long:  "List, show and count findings, and gate CI on severity.\n\n" + envUsage,
	})
	cmd.AddCommand(newFindingsListCmd(), newFindingsGetCmd(), newFindingsCountsCmd())
	return cmd
}

// listFlag collects comma-separated or repeated values, upper-cased to match
// the API's enum values.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Type() string { return "list" }

func (l *listFlag) Set(value string) error {
	for v := range strings.SplitSeq(value, ",") {
		if v = strings.TrimSpace(v); v != "" {
			*l = append(*l, strings.ToUpper(v))
		}
	}
	return nil
}

func newFindingsListCmd() *cobra.Command {
	var severity, status listFlag
	var search, failOn string
	var limit int
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List findings, optionally failing on a severity threshold",
		Long: `List findings matching the filters, following pagination, as a table or JSON.

--fail-on exits with status 3 when any finding matching the filters is at or
above the given severity. Only open (PUBLISHED) findings count unless --status
is given. --limit does not affect the check.

Exit status:
  0   Success, and no finding reached the --fail-on severity
  1   Error, for example an API or authentication failure
  2   Invalid usage
  3   A finding reached the --fail-on severity

` + envUsage,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit < 0 {
				return usageErrorf("--limit must not be negative")
			}
			threshold := -1
			if failOn != "" {
				threshold = slices.Index(severities, heist.ListFindingsParamsSeverity(strings.ToUpper(failOn)))
				if threshold < 0 {
					return usageErrorf("unknown --fail-on severity %q", failOn)
				}
			}

			params := listParams(severity, status, search)
			if limit > 0 {
				size := min(limit, 100) // the API's maximum page size
				params.Size = &size
			}
			client, err := newClient()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			findings := []json.RawMessage{}
			for finding, err := range allRawFindings(ctx, client, params) {
				if err != nil {
					return err
				}
				findings = append(findings, finding)
				if len(findings) == limit {
					break
				}
			}
			if asJSON {
				err = writeJSON(cmd.OutOrStdout(), findings)
			} else {
				typed := make([]heist.Finding, len(findings))
				for i, raw := range findings {
					if err := json.Unmarshal(raw, &typed[i]); err != nil {
						return err
					}
				}
				err = writeFindingsTable(cmd.OutOrStdout(), typed)
			}
			if err != nil {
				return err
			}

			if threshold < 0 {
				return nil
			}
			n, err := countAtOrAbove(ctx, client, params, severities[threshold])
			if err != nil {
				return err
			}
			if n > 0 {
				return &exitError{exitFailOn, fmt.Sprintf("%d finding(s) at or above %s", n, severities[threshold])}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.Var(&severity, "severity", "only these severities, comma-separated or repeated:\nINFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL")
	f.Var(&status, "status", "only these statuses, comma-separated or repeated:\nPUBLISHED (open), FIXED, ACCEPTED, COMPENSATING_CONTROL")
	f.StringVar(&search, "search", "", "only findings matching the search `text`")
	f.IntVar(&limit, "limit", 0, "print at most `n` findings (default all)")
	f.StringVar(&failOn, "fail-on", "", "exit 3 when a finding is at or above `severity`")
	f.BoolVar(&asJSON, "json", false, "print a JSON array of findings")
	return cmd
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

func newFindingsGetCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Show a finding's full detail",
		Long: `Show a finding's full detail, including its report and linked application,
repository, and route.

` + envUsage,
		Args: oneArg("finding ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			var id openapi_types.UUID
			if err := id.UnmarshalText([]byte(args[0])); err != nil {
				return usageErrorf("invalid finding ID %q", args[0])
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			res, err := client.GetFindingWithResponse(cmd.Context(), id)
			if err != nil {
				return err
			}
			if res.JSON200 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			}
			return writeFindingDetail(cmd.OutOrStdout(), res.JSON200)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
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

func newFindingsCountsCmd() *cobra.Command {
	var status listFlag
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "counts",
		Short: "Count findings by status and severity",
		Long:  "Count findings by status, and by severity for the given statuses.\n\n" + envUsage,
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			res, err := client.FindingCountsWithResponse(ctx)
			if err != nil {
				return err
			}
			if res.JSON200 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
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
					return err
				}
			}

			if asJSON {
				return writeJSON(cmd.OutOrStdout(), counts)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
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
			return tw.Flush()
		},
	}
	cmd.Flags().Var(&status, "status", "statuses the severity counts include, comma-separated or\nrepeated (default PUBLISHED, the open findings)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the counts as JSON")
	return cmd
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

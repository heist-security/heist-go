package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"slices"
	"strconv"
	"strings"

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
		Short: "List, show, count, retest and triage findings, and gate CI on severity",
		Long:  "List, show, count, retest and triage findings, and gate CI on severity.\n\n" + envUsage,
	})
	cmd.AddCommand(newFindingsListCmd(), newFindingsGetCmd(), newFindingsCountsCmd())
	cmd.AddCommand(findingActionCmds()...)
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
			findings := []json.RawMessage{}
			total := 0 // findings matching the filters, ignoring --limit
			err = withProgress(cmd, asJSON, "Fetching findings", func(ctx context.Context, progress progressFunc) error {
				track := func(status string, done, n int) {
					total = n
					progress(status, done, n)
				}
				for finding, err := range allRawFindings(ctx, client, params, track) {
					if err != nil {
						return err
					}
					findings = append(findings, finding)
					if len(findings) == limit {
						break
					}
				}
				return nil
			})
			if err != nil {
				return err
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
				err = printStyled(cmd, func(w io.Writer, s styles) error {
					return writeFindingsTable(w, s, typed, total)
				})
			}
			if err != nil {
				return err
			}

			if threshold < 0 {
				return nil
			}
			n, err := countAtOrAbove(cmd.Context(), client, params, severities[threshold])
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
// params.Page. It reports the findings fetched so far to progress.
func allRawFindings(ctx context.Context, client *heist.ClientWithResponses, params heist.ListFindingsParams, progress progressFunc) iter.Seq2[json.RawMessage, error] {
	fetched := 0
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
		fetched += len(body.Items)
		progress("Fetching findings", fetched, res.JSON200.Total)
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

// writeFindingsTable writes findings as a table. Styled output leads with
// severity and title, dims the status and ID, and ends with a summary of
// total, the number of findings matching the filters.
func writeFindingsTable(w io.Writer, s styles, findings []heist.Finding, total int) error {
	if !s.on {
		rows := make([][]string, len(findings))
		for i, f := range findings {
			rows[i] = []string{f.Id, string(f.Severity), string(f.ValidationStatus), oneLine(f.Title)}
		}
		return writeTable(w, s, []string{"ID", "SEVERITY", "STATUS", "TITLE"}, rows)
	}

	rows := make([][]string, len(findings))
	open := 0
	for i, f := range findings {
		rows[i] = []string{s.severity(string(f.Severity)), oneLine(f.Title), s.dim(s.status(string(f.ValidationStatus))), s.dim(f.Id)}
		if f.ValidationStatus == heist.FindingValidationStatusPUBLISHED {
			open++
		}
	}
	if err := s.list(w, rows, 1); err != nil {
		return err
	}
	var summary string
	switch {
	case len(findings) == 0:
		summary = "No findings"
	case len(findings) < total:
		summary = fmt.Sprintf("First %d of %d findings", len(findings), total)
	default:
		summary = joinDot(plural(len(findings), "finding"), fmt.Sprintf("%d open", open))
	}
	_, err := fmt.Fprintf(w, "\n%s\n", s.dim(summary))
	return err
}

// plural formats n and noun, adding an s unless n is 1.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
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
			var res *heist.GetFindingResponse
			err = withProgress(cmd, asJSON, "Fetching finding", func(ctx context.Context, _ progressFunc) error {
				res, err = client.GetFindingWithResponse(ctx, id)
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
				return writeFindingDetail(w, s, res.JSON200)
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

// writeFindingDetail writes a finding's fields and text sections. Styled
// output puts the severity and title first, with the status and other
// metadata on one dim line.
func writeFindingDetail(w io.Writer, s styles, f *heist.FindingDetail) error {
	fields := fieldWriter{s: s}
	field := fields.add
	if s.on {
		_, err := fmt.Fprintf(w, "%s  %s\n%s\n%s\n",
			s.severity(string(f.Severity)), s.bold(oneLine(f.Title)),
			s.dim(joinDot(s.status(string(f.ValidationStatus)), f.Category, f.Type, string(f.SourceKind),
				"created "+s.date(f.CreatedAt), "updated "+s.date(f.UpdatedAt))),
			s.dim(f.Id))
		if err != nil {
			return err
		}
	} else {
		field("Title", oneLine(f.Title))
		field("ID", f.Id)
		field("Severity", string(f.Severity))
		field("Status", string(f.ValidationStatus))
		field("Category", f.Category)
		field("Type", f.Type)
		field("Source", string(f.SourceKind))
		field("Created", f.CreatedAt)
		field("Updated", f.UpdatedAt)
	}
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
	if s.on && len(fields.fields) > 0 {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	if err := fields.write(w); err != nil {
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
	for _, sec := range sections {
		if sec.text == nil || strings.TrimSpace(*sec.text) == "" {
			continue
		}
		if err := s.section(w, sec.title, *sec.text); err != nil {
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
			params := listParams(nil, status, "")
			if params.Status == nil {
				params.Status = &openStatuses
			}
			counts := findingCounts{
				Severity:         map[heist.ListFindingsParamsSeverity]int{},
				SeverityStatuses: *params.Status,
			}
			var res *heist.FindingCountsResponse
			err = withProgress(cmd, asJSON, "Counting findings", func(ctx context.Context, progress progressFunc) error {
				res, err = client.FindingCountsWithResponse(ctx)
				if err != nil {
					return err
				}
				if res.JSON200 == nil {
					return fmt.Errorf("unexpected %s response", res.Status())
				}
				counts.Status = res.Body
				for i, s := range severities {
					progress("Counting findings", i+1, len(severities)+1)
					params.Severity = &[]heist.ListFindingsParamsSeverity{s}
					if counts.Severity[s], err = client.CountFindings(ctx, params); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}

			if asJSON {
				return writeJSON(cmd.OutOrStdout(), counts)
			}
			return printStyled(cmd, func(w io.Writer, s styles) error {
				return writeFindingCounts(w, s, res, counts)
			})
		},
	}
	cmd.Flags().Var(&status, "status", "statuses the severity counts include, comma-separated or\nrepeated (default PUBLISHED, the open findings)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the counts as JSON")
	return cmd
}

// writeFindingCounts writes status counts from res, which must have a 200
// body, and counts by severity.
func writeFindingCounts(w io.Writer, s styles, res *heist.FindingCountsResponse, counts findingCounts) error {
	c := res.JSON200
	err := writeTable(w, s, []string{"STATUS", "COUNT"}, [][]string{
		{"open", strconv.Itoa(c.Open)},
		{"closed", strconv.Itoa(c.Closed)},
		{"accepted", strconv.Itoa(c.Accepted)},
		{"compensating control", strconv.Itoa(c.CompensatingControl)},
		{"all", strconv.Itoa(c.All)},
	})
	if err != nil {
		return err
	}
	var scope []string
	for _, st := range counts.SeverityStatuses {
		scope = append(scope, string(st))
	}
	var rows [][]string
	for _, sev := range slices.Backward(severities) {
		rows = append(rows, []string{string(sev), strconv.Itoa(counts.Severity[sev])})
	}
	fmt.Fprintln(w)
	return writeTable(w, s, []string{fmt.Sprintf("SEVERITY (%s)", strings.Join(scope, ",")), "COUNT"}, rows)
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

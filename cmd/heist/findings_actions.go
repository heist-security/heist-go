package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/heist-security/heist-go/heist"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/spf13/cobra"
)

// exitRetestFailed is the exit status of `heist findings retest-status` when
// the latest retest ended without completing. 1 and 2 are errors and usage
// errors.
const exitRetestFailed = 3

// failedRetestStatuses are the retest statuses that mean the retest ended
// without completing.
var failedRetestStatuses = []heist.GetFindingRetest200JSONResponseBodyStatus{
	"FAILED", "CANCELLED", "TERMINATED", "TIMED_OUT",
}

// findingActionCmds returns the commands that act on a single finding.
func findingActionCmds() []*cobra.Command {
	return []*cobra.Command{
		newFindingsRetestCmd(),
		newFindingsRetestStatusCmd(),
		newFindingUpdateCmd("accept-risk", "reason", acceptFindingRisk,
			"Accept a finding's risk",
			"Accept a finding's risk with a justification, and show the updated finding."),
		newFindingUpdateCmd("compensating-control", "reason", applyCompensatingControl,
			"Record a compensating control for a finding",
			"Record a compensating control for a finding with a justification, and show\nthe updated finding."),
		newFindingUpdateCmd("false-positive", "comment", reportFalsePositive,
			"Report a finding as a false positive",
			"Report a finding as a false positive with a comment, and show the updated\nfinding. Heist reviews the report before closing the finding."),
		newFindingsHistoryCmd(),
	}
}

func newFindingsRetestCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "retest <id>",
		Short: "Start retesting a finding",
		Long: `Start retesting a finding. The retest runs in the background; check it with
heist findings retest-status <id>. Fails if a retest is already running.
Requires the Editor or Admin role.

` + envUsage,
		Args: oneArg("finding ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseUUID(args[0])
			if err != nil {
				return usageError{err}
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			body, err := startRetest(cmd.Context(), client, id)
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), body)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Retest started. Check it with: heist findings retest-status %s\n", id)
			return err
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

// startRetest starts a retest of a finding and returns the API's response
// body.
func startRetest(ctx context.Context, client *heist.ClientWithResponses, id openapi_types.UUID) (json.RawMessage, error) {
	res, err := client.RetestFindingWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}
	if res.JSON202 == nil {
		return nil, fmt.Errorf("unexpected %s response", res.Status())
	}
	return res.Body, nil
}

func newFindingsRetestStatusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "retest-status <id>",
		Short: "Show a finding's latest retest and the finding",
		Long: `Show the state of a finding's latest retest and the current finding.
NOT_STARTED means no retest is retained: none was started, or its history has
expired. It does not mean a retest succeeded.

Exit status:
  0   Success, and the retest has not failed (it may still be RUNNING)
  1   Error, for example an API or authentication failure
  2   Invalid usage
  3   The retest ended without completing: FAILED, CANCELLED, TERMINATED or
      TIMED_OUT

` + envUsage,
		Args: oneArg("finding ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseUUID(args[0])
			if err != nil {
				return usageError{err}
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			res, err := getRetestStatus(cmd.Context(), client, id)
			if err != nil {
				return err
			}
			if asJSON {
				err = writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			} else {
				err = writeRetestStatus(cmd.OutOrStdout(), res)
			}
			if err != nil {
				return err
			}
			if status := res.JSON200.Status; slices.Contains(failedRetestStatuses, status) {
				return &exitError{exitRetestFailed, fmt.Sprintf("retest %s", status)}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

// getRetestStatus returns a finding's latest retest. The response has a 200
// body.
func getRetestStatus(ctx context.Context, client *heist.ClientWithResponses, id openapi_types.UUID) (*heist.GetFindingRetestResponse, error) {
	res, err := client.GetFindingRetestWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}
	if res.JSON200 == nil {
		return nil, fmt.Errorf("unexpected %s response", res.Status())
	}
	return res, nil
}

// writeRetestStatus writes a retest's state and the finding. res must have a
// 200 body.
func writeRetestStatus(w io.Writer, res *heist.GetFindingRetestResponse) error {
	r := res.JSON200
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	field := func(label string, value *string) {
		if value != nil && *value != "" {
			fmt.Fprintf(tw, "%s:\t%s\n", label, oneLine(*value))
		}
	}
	status := string(r.Status)
	field("Retest", &status)
	field("Started", r.StartedAt)
	field("Closed", r.ClosedAt)
	field("Failure", r.Failure)
	if err := tw.Flush(); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	return writeFindingDetail(w, &r.Finding)
}

// findingUpdate changes a finding's status with a justification and returns
// the API's response body and the updated finding.
type findingUpdate func(ctx context.Context, client *heist.ClientWithResponses, id openapi_types.UUID, text string) (json.RawMessage, *heist.FindingDetail, error)

// newFindingUpdateCmd returns a command that runs update with the text of a
// required flag, and prints the updated finding.
func newFindingUpdateCmd(name, flag string, update findingUpdate, short, long string) *cobra.Command {
	var text string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   name + " <id> --" + flag + " <text>",
		Short: short,
		Long:  long + "\nRequires the Editor or Admin role.\n\n" + envUsage,
		Args:  oneArg("finding ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseUUID(args[0])
			if err != nil {
				return usageError{err}
			}
			if strings.TrimSpace(text) == "" {
				return usageErrorf("--%s is required", flag)
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			body, finding, err := update(cmd.Context(), client, id, text)
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), body)
			}
			return writeFindingDetail(cmd.OutOrStdout(), finding)
		},
	}
	cmd.Flags().StringVar(&text, flag, "", "the justification `text` (required)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

func acceptFindingRisk(ctx context.Context, client *heist.ClientWithResponses, id openapi_types.UUID, reason string) (json.RawMessage, *heist.FindingDetail, error) {
	res, err := client.AcceptFindingRiskWithResponse(ctx, id, heist.AcceptFindingRiskJSONRequestBody{Reason: reason})
	if err != nil {
		return nil, nil, err
	}
	if res.JSON200 == nil {
		return nil, nil, fmt.Errorf("unexpected %s response", res.Status())
	}
	return res.Body, res.JSON200, nil
}

func applyCompensatingControl(ctx context.Context, client *heist.ClientWithResponses, id openapi_types.UUID, reason string) (json.RawMessage, *heist.FindingDetail, error) {
	res, err := client.ApplyCompensatingControlWithResponse(ctx, id, heist.ApplyCompensatingControlJSONRequestBody{Reason: reason})
	if err != nil {
		return nil, nil, err
	}
	if res.JSON200 == nil {
		return nil, nil, fmt.Errorf("unexpected %s response", res.Status())
	}
	return res.Body, res.JSON200, nil
}

func reportFalsePositive(ctx context.Context, client *heist.ClientWithResponses, id openapi_types.UUID, comment string) (json.RawMessage, *heist.FindingDetail, error) {
	res, err := client.ReportFalsePositiveWithResponse(ctx, id, heist.ReportFalsePositiveJSONRequestBody{Comment: comment})
	if err != nil {
		return nil, nil, err
	}
	if res.JSON200 == nil {
		return nil, nil, fmt.Errorf("unexpected %s response", res.Status())
	}
	return res.Body, res.JSON200, nil
}

func newFindingsHistoryCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "history <id>",
		Short: "Show a finding's status changes",
		Long:  "Show a finding's status changes, oldest first.\n\n" + envUsage,
		Args:  oneArg("finding ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseUUID(args[0])
			if err != nil {
				return usageError{err}
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			res, err := getStatusHistory(cmd.Context(), client, id)
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			}
			return writeStatusHistory(cmd.OutOrStdout(), res)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

// getStatusHistory returns a finding's status changes, oldest first. The
// response has a 200 body.
func getStatusHistory(ctx context.Context, client *heist.ClientWithResponses, id openapi_types.UUID) (*heist.GetFindingStatusHistoryResponse, error) {
	res, err := client.GetFindingStatusHistoryWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}
	if res.JSON200 == nil {
		return nil, fmt.Errorf("unexpected %s response", res.Status())
	}
	return res, nil
}

// writeStatusHistory writes a finding's status changes as a table. res must
// have a 200 body.
func writeStatusHistory(w io.Writer, res *heist.GetFindingStatusHistoryResponse) error {
	headers := []string{"CHANGED", "FROM", "TO", "CHANGED BY"}
	var rows [][]string
	for _, c := range *res.JSON200 {
		by := "-"
		if c.ChangedByUserId != nil && *c.ChangedByUserId != "" {
			by = *c.ChangedByUserId
		}
		rows = append(rows, []string{c.ChangedAt, string(c.FromStatus), string(c.ToStatus), by})
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(headers, "\t"))
	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	return tw.Flush()
}

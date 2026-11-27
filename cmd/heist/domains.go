package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/heist-security/heist-go/heist"
	"github.com/spf13/cobra"
)

// exitNotVerified is the exit status of `heist domains status` and
// `heist domains verify` when a domain isn't verified. 1 and 2 are errors and
// usage errors.
const exitNotVerified = 3

func newDomainsCmd() *cobra.Command {
	cmd := groupCmd(&cobra.Command{
		Use:   "domains",
		Short: "List domains, manage auto-include and verify domains with DNS",
		Long: `List domains, manage automatic inclusion, and verify domain ownership with a
DNS TXT record.

To verify a domain, print its TXT record with heist domains challenge --create,
publish the record with your DNS provider, then run heist domains verify.

Changing auto-include, issuing a challenge and verifying require the Admin
role.

` + envUsage,
	})
	cmd.AddCommand(
		newDomainsListCmd(),
		newDomainsGetCmd(),
		newDomainsStatusCmd(),
		newDomainsAutoIncludeCmd(),
		newDomainsChallengeCmd(),
		newDomainsVerifyCmd(),
	)
	return cmd
}

func writeDomainsTable(w io.Writer, domains []heist.Domain) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tDOMAIN\tVERIFIED\tIN SCOPE\tAUTO-INCLUDE")
	for _, d := range domains {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", d.Id, d.Domain, yesNo(d.Verified), yesNo(d.InScope), yesNo(d.AutoInclude))
	}
	return tw.Flush()
}

func writeDomainDetail(w io.Writer, d heist.Domain) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "Domain:\t%s\n", d.Domain)
	fmt.Fprintf(tw, "ID:\t%s\n", d.Id)
	fmt.Fprintf(tw, "Verified:\t%s\n", yesNo(d.Verified))
	fmt.Fprintf(tw, "In scope:\t%s\n", yesNo(d.InScope))
	fmt.Fprintf(tw, "Auto-include:\t%s\n", yesNo(d.AutoInclude))
	fmt.Fprintf(tw, "Created:\t%s\n", d.CreatedAt)
	fmt.Fprintf(tw, "Updated:\t%s\n", d.UpdatedAt)
	return tw.Flush()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func newDomainsListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List domains with their verification and auto-include settings",
		Long: `List workspace domains with their DNS verification and auto-include settings.
A domain is in scope when it has an in-scope application.

` + envUsage,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			res, err := client.ListDomainsWithResponse(cmd.Context())
			if err != nil {
				return err
			}
			if res.JSON200 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			}
			return writeDomainsTable(cmd.OutOrStdout(), *res.JSON200)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

func newDomainsGetCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Show a domain's verification and auto-include settings",
		Long:  "Show a domain's DNS verification and auto-include settings.\n\n" + envUsage,
		Args:  oneArg("domain ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseUUID(args[0])
			if err != nil {
				return usageError{err}
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			res, err := client.GetDomainWithResponse(cmd.Context(), id)
			if err != nil {
				return err
			}
			if res.JSON200 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			}
			return writeDomainDetail(cmd.OutOrStdout(), *res.JSON200)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

func newDomainsStatusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check whether all in-scope domains are verified",
		Long: `Check whether all in-scope domains are verified. Out-of-scope domains don't
need verification. When a domain isn't verified, the API reports one of them.

Exit status:
  0   Success, and all in-scope domains are verified
  1   Error, for example an API or authentication failure
  2   Invalid usage
  3   An in-scope domain isn't verified

` + envUsage,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			res, err := client.DomainVerificationStatusWithResponse(cmd.Context())
			if err != nil {
				return err
			}
			s := res.JSON200
			if s == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			if asJSON {
				err = writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			} else {
				err = writeVerificationStatus(cmd.OutOrStdout(), s.Verified, s.UnverifiedDomain)
			}
			if err != nil {
				return err
			}
			if !s.Verified {
				return &exitError{exitNotVerified, "not all in-scope domains are verified"}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

// writeVerificationStatus writes the workspace verification status and the
// unverified domain the API reported, if any.
func writeVerificationStatus(w io.Writer, verified bool, unverified *heist.Domain) error {
	if _, err := fmt.Fprintf(w, "Verified: %s\n", yesNo(verified)); err != nil {
		return err
	}
	if unverified == nil {
		return nil
	}
	if _, err := fmt.Fprintln(w, "\nUnverified domain:"); err != nil {
		return err
	}
	return writeDomainsTable(w, []heist.Domain{*unverified})
}

func newDomainsAutoIncludeCmd() *cobra.Command {
	var on, off, asJSON bool
	cmd := &cobra.Command{
		Use:   "auto-include <id> --on|--off",
		Short: "Turn automatic inclusion of new discoveries on or off",
		Long: `Turn automatic inclusion of future discoveries on a domain on or off. Existing
application scope decisions are kept. Requires the Admin role.

` + envUsage,
		Args: oneArg("domain ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseUUID(args[0])
			if err != nil {
				return usageError{err}
			}
			if on == off {
				return usageErrorf("expected one of --on or --off")
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			res, err := client.UpdateDomainAutoIncludeWithResponse(cmd.Context(), id, heist.UpdateDomainAutoIncludeJSONRequestBody{AutoInclude: on})
			if err != nil {
				return err
			}
			if res.JSON200 == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			}
			return writeDomainsTable(cmd.OutOrStdout(), []heist.Domain{*res.JSON200})
		},
	}
	cmd.Flags().BoolVar(&on, "on", false, "include new discoveries on the domain automatically")
	cmd.Flags().BoolVar(&off, "off", false, "stop including new discoveries automatically")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

func newDomainsChallengeCmd() *cobra.Command {
	var create, valueOnly, asJSON bool
	cmd := &cobra.Command{
		Use:   "challenge <id>",
		Short: "Print the DNS TXT record that verifies a domain",
		Long: `Print the DNS TXT record name, type and value that verify a domain.

By default this reads the domain's existing challenge, and fails if none has
been issued. --create issues a challenge, or returns the existing one, which
stays the same once issued; it requires the Admin role.

--value prints only the record value, for passing to a DNS tool.

` + envUsage,
		Args: oneArg("domain ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseUUID(args[0])
			if err != nil {
				return usageError{err}
			}
			if valueOnly && asJSON {
				return usageErrorf("--value and --json can't be used together")
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			var challenge *heist.DomainVerificationChallenge
			var body []byte
			if create {
				res, err := client.RequestDomainVerificationWithResponse(cmd.Context(), id)
				if err != nil {
					return err
				}
				challenge, body = res.JSON200, res.Body
				if challenge == nil {
					return fmt.Errorf("unexpected %s response", res.Status())
				}
			} else {
				res, err := client.GetDomainVerificationChallengeWithResponse(cmd.Context(), id)
				if err != nil {
					return err
				}
				challenge, body = res.JSON200, res.Body
				if challenge == nil {
					return fmt.Errorf("unexpected %s response", res.Status())
				}
				// The API returns null when no challenge has been issued,
				// which the SDK decodes as an empty challenge.
				if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
					return errors.New("no challenge has been issued; issue one with --create")
				}
			}

			switch {
			case asJSON:
				return writeJSON(cmd.OutOrStdout(), json.RawMessage(body))
			case valueOnly:
				_, err = fmt.Fprintln(cmd.OutOrStdout(), challenge.RecordValue)
				return err
			}
			return writeChallenge(cmd.OutOrStdout(), *challenge)
		},
	}
	cmd.Flags().BoolVar(&create, "create", false, "issue a challenge if the domain has none")
	cmd.Flags().BoolVar(&valueOnly, "value", false, "print only the TXT record value")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

func newDomainsVerifyCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "verify <id>",
		Short: "Check a domain's DNS TXT record and print the result",
		Long: `Check a domain's DNS TXT record, and print the verification result the API
saved. A missing, incorrect or not yet propagated record leaves the domain
unverified; a verified domain stays verified. Requires the Admin role.

Exit status:
  0   Success, and the domain is verified
  1   Error, for example an API or authentication failure
  2   Invalid usage
  3   The domain isn't verified

` + envUsage,
		Args: oneArg("domain ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseUUID(args[0])
			if err != nil {
				return usageError{err}
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			res, err := client.VerifyDomainWithResponse(cmd.Context(), id)
			if err != nil {
				return err
			}
			c := res.JSON200
			if c == nil {
				return fmt.Errorf("unexpected %s response", res.Status())
			}
			if asJSON {
				err = writeJSON(cmd.OutOrStdout(), json.RawMessage(res.Body))
			} else {
				err = writeChallenge(cmd.OutOrStdout(), *c)
			}
			if err != nil {
				return err
			}
			if !c.Verified {
				return &exitError{exitNotVerified, fmt.Sprintf("%s is not verified", c.Domain)}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the API's JSON response")
	return cmd
}

// writeChallenge writes a domain's TXT record and verification state.
func writeChallenge(w io.Writer, c heist.DomainVerificationChallenge) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "Domain:\t%s\n", c.Domain)
	fmt.Fprintf(tw, "Domain ID:\t%s\n", c.DomainId)
	fmt.Fprintf(tw, "Verified:\t%s\n", yesNo(c.Verified))
	fmt.Fprintf(tw, "Record name:\t%s\n", c.RecordName)
	fmt.Fprintf(tw, "Record type:\t%s\n", c.RecordType)
	fmt.Fprintf(tw, "Record value:\t%s\n", c.RecordValue)
	if p := c.Provider; p != nil {
		fmt.Fprintf(tw, "DNS provider:\t%s\n", p.Name)
		if p.DashboardUrl != nil && *p.DashboardUrl != "" {
			fmt.Fprintf(tw, "DNS dashboard:\t%s\n", *p.DashboardUrl)
		}
	}
	return tw.Flush()
}

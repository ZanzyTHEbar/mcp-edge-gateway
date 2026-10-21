// Package credentialbridge implements a local, credential-managed stdio to
// Streamable HTTP bridge for MCP Edge. Authorization never uses a callback port.
package credentialbridge

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	var resource, directory, clientID string
	cmd := &cobra.Command{
		Use:           "mcp-edge-credential-bridge",
		Short:         "Bridge stdio MCP to MCP Edge using privately stored OAuth credentials",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := New(resource, directory)
			if err != nil {
				return err
			}
			return client.Serve(cmd.Context(), os.Stdin, os.Stdout)
		},
	}
	cmd.PersistentFlags().StringVar(&resource, "url", "", "Public MCP Edge service URL (required)")
	cmd.PersistentFlags().StringVar(&directory, "state-dir", "", "Directory for empty refresh lock files only; credentials are kept in Secret Service")
	_ = cmd.MarkPersistentFlagRequired("url")
	login := &cobra.Command{
		Use:   "login",
		Short: "Authorize on another device and save credentials locally",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := New(resource, directory)
			if err != nil {
				return err
			}
			return client.Login(cmd.Context(), clientID, cmd.ErrOrStderr())
		},
	}
	login.Flags().StringVar(&clientID, "client-id", "", "Pre-registered public device-flow client ID; otherwise use public dynamic registration")
	logout := &cobra.Command{
		Use:   "logout",
		Short: "Remove the local credential for this service (does not revoke server tokens)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := New(resource, directory)
			if err != nil {
				return err
			}
			if err := client.store.remove(cmd.Context()); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.ErrOrStderr(), "Local credential removed. Stop existing bridge processes to close their sessions.")
			return err
		},
	}
	cmd.AddCommand(login, logout)
	return cmd
}

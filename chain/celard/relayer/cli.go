package relayer

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"

	fraudtypes "github.com/cosmos/evm/evmd/fraudevidence/types"
)

// NewRelayCmd submits a coprocessor's attestations.
//
// A subcommand of the node rather than a separate binary, deliberately. It
// inherits the existing signing stack - keyring, account, sequence, fees,
// endpoint - so nothing here manages keys, and an operator who already runs a
// node has already provisioned everything this needs.
//
// The sender has no authority over what it sends. Each attestation carries its
// own identity and signature, and the chain verifies both before recording
// anything, so this account pays fees and nothing more.
func NewRelayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relay-attestations [file]",
		Short: "Submit attestations a coprocessor wrote",
		Long: "Reads the handoff document a coprocessor produced and submits each " +
			"attestation it contains. The submitting account pays fees and holds no " +
			"authority over the contents.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("reading %s: %w", args[0], err)
			}

			// Parsed and width-checked before anything is built: a malformed
			// file should cost nothing, not a broadcast transaction and a
			// rejection that names the chain's reason rather than the file's.
			attestations, err := ParseHandoff(data)
			if err != nil {
				return err
			}

			// An empty batch is a legitimate outcome - a poll that executed
			// nothing - and must not produce an empty transaction with a fee.
			if len(attestations) == 0 {
				cmd.Printf("no attestations in %s; nothing submitted\n", args[0])
				return nil
			}

			from := clientCtx.GetFromAddress().String()
			msgs := make([]sdk.Msg, 0, len(attestations))
			for i := range attestations {
				msgs = append(msgs, &fraudtypes.MsgSubmitAttestation{
					Submitter:   from,
					Attestation: attestations[i],
				})
			}

			// One transaction for the batch. The store treats an identical
			// resubmission as already-recorded rather than an error, so a retry
			// after an ambiguous broadcast is safe - which is what makes
			// batching safe too.
			txf, err := tx.NewFactoryCLI(clientCtx, cmd.Flags())
			if err != nil {
				return err
			}
			return tx.GenerateOrBroadcastTxWithFactory(clientCtx, txf, msgs...)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

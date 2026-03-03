package dnat

import (
	"simulacrum/internal/core"

	"github.com/spf13/cobra"
)

var flushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Flush all DNS NAT rules",
	Long:  "Flush all DNS NAT rules from the system",
	RunE: func(cmd *cobra.Command, args []string) error {
		message := core.ControlMessage{Service: "dns", Action: "update", Params: map[string]any{"dnat": "flush"}}
		return core.SendControlMessage(message)
	},
}

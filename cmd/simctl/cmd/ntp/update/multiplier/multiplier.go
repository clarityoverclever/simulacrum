package multiplier

import (
	"simulacrum/internal/core"

	"github.com/spf13/cobra"
)

var MultiplierCmd = &cobra.Command{
	Use:   "multiplier",
	Short: "add offset multiplier to ntp service",
	Long:  "add offset multiplier to ntp service",
	RunE: func(cmd *cobra.Command, args []string) error {
		multiplier, _ := cmd.Flags().GetFloat64("value")
		message := core.ControlMessage{Service: "ntp", Action: "update", Params: map[string]any{"multiplier": multiplier}}
		return core.SendControlMessage(message)
	},
}

func init() {
	MultiplierCmd.Flags().Float64P("value", "v", 0, "offset multiplier")
	MultiplierCmd.MarkFlagRequired("value")
}

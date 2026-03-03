package dns

import (
	"fmt"
	"simulacrum/internal/core"

	"github.com/spf13/cobra"
)

var dnsStopCmd = &cobra.Command{
	Use: "stop",
	Run: func(cmd *cobra.Command, args []string) {
		message := core.ControlMessage{Service: "dns", Action: "stop"}
		err := core.SendControlMessage(message)
		if err != nil {
			fmt.Errorf("Failed to send message: %v", err)
		}
	},
}

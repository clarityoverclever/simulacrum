package dns

import (
	"fmt"
	"simulacrum/internal/core"

	"github.com/spf13/cobra"
)

var dnsStatusCmd = &cobra.Command{
	Use: "status",
	Run: func(cmd *cobra.Command, args []string) {
		message := core.ControlMessage{Service: "dns", Action: "status"}
		err := core.SendControlMessage(message)
		if err != nil {
			fmt.Errorf("Failed to send message: %v", err)
		}
	},
}

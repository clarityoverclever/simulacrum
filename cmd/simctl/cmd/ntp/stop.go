package ntp

import (
	"fmt"
	"simulacrum/internal/core"

	"github.com/spf13/cobra"
)

var ntpStopCmd = &cobra.Command{
	Use: "stop",
	Run: func(cmd *cobra.Command, args []string) {
		message := core.ControlMessage{Service: "ntp", Action: "stop"}
		err := core.SendControlMessage(message)
		if err != nil {
			fmt.Errorf("Failed to send message: %v", err)
		}
	},
}

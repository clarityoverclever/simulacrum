package ntp

import (
	"simulacrum/cmd/simctl/cmd/ntp/update"

	"github.com/spf13/cobra"
)

var NtpCmd = &cobra.Command{Use: "ntp"}

func init() {
	NtpCmd.AddCommand(ntpStartCmd)
	NtpCmd.AddCommand(ntpStopCmd)
	NtpCmd.AddCommand(ntpStatusCmd)

	NtpCmd.AddCommand(update.NtpUpdateCmd)
}

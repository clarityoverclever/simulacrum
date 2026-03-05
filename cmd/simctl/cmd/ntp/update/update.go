package update

import (
	"simulacrum/cmd/simctl/cmd/ntp/update/multiplier"

	"github.com/spf13/cobra"
)

var NtpUpdateCmd = &cobra.Command{Use: "update"}

func init() {
	NtpUpdateCmd.AddCommand(multiplier.MultiplierCmd)
}

package update

import (
	"simulacrum/cmd/simctl/cmd/dns/update/dnat"

	"github.com/spf13/cobra"
)

var DnsUpdateCmd = &cobra.Command{Use: "update"}

func init() {
	DnsUpdateCmd.AddCommand(dnat.DnatCmd)
}

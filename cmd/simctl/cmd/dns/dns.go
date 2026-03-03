package dns

import (
	"github.com/spf13/cobra"
	"simulacrum/cmd/simctl/cmd/dns/update"
)

var DnsCmd = &cobra.Command{Use: "dns"}

func init() {
	DnsCmd.AddCommand(dnsStartCmd)
	DnsCmd.AddCommand(dnsStopCmd)
	DnsCmd.AddCommand(dnsStatusCmd)

	DnsCmd.AddCommand(update.DnsUpdateCmd)
}

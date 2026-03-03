package dnat

import (
	"github.com/spf13/cobra"
)

var DnatCmd = &cobra.Command{Use: "dnat"}

func init() {
	DnatCmd.AddCommand(flushCmd)
}

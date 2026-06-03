package cmd

import (
	"github.com/spf13/cobra"
)

// rootCmd 代表没有子命令时的基础命令
var rootCmd = &cobra.Command{
	Use:   "sentinel",
	Short: "LLM-API-Sentinel — LLM API 安全扫描器",
	Long:  "LLM-API-Sentinel 是一款用于 LLM API 的安全扫描器，支持提示词注入、越狱等检测。",
}

// Execute 执行根命令
func Execute() error {
	return rootCmd.Execute()
}

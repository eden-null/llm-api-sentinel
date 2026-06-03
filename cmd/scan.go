package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"llm-api-sentinel/payloads"
	"llm-api-sentinel/reporter"
	"llm-api-sentinel/scanner"
)

var (
	scanURL      string
	scanAPIKey   string
	scanPayloads string
	scanOutput   string
	scanDetector string
)

// scanCmd 表示 scan 子命令，执行 LLM API 安全扫描
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "对目标 LLM API 执行安全扫描",
	Long: `扫描目标 LLM API 端点，使用内置载荷检测提示词注入、越狱等安全漏洞。
	
支持 text 和 markdown 两种输出格式。
通过 --detector 可切换检测策略。`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanURL, "url", "", "LLM API 端点 URL（必填）")
	scanCmd.Flags().StringVar(&scanAPIKey, "apikey", "", "API 密钥（必填）")
	scanCmd.Flags().StringVar(&scanPayloads, "payloads", "payloads/payloads.json", "载荷 JSON 文件路径")
	scanCmd.Flags().StringVar(&scanOutput, "output", "text", "输出格式: text 或 markdown")
	scanCmd.Flags().StringVar(&scanDetector, "detector", "keyword", "检测策略: keyword | composite")

	rootCmd.AddCommand(scanCmd)
}

// runScan 执行扫描流程
func runScan(cmd *cobra.Command, args []string) error {
	if scanURL == "" || scanAPIKey == "" {
		return fmt.Errorf("--url 和 --apikey 为必填参数")
	}

	pl, err := payloads.LoadPayloads(scanPayloads)
	if err != nil {
		return fmt.Errorf("加载载荷失败: %w", err)
	}

	detector, err := buildDetector(scanDetector)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "[*] 检测器: %s\n", detector.Name())
	fmt.Fprintf(os.Stderr, "[*] 已加载 %d 条测试载荷\n", len(pl))
	fmt.Fprintf(os.Stderr, "[*] 目标: %s\n", scanURL)
	fmt.Fprintf(os.Stderr, "[*] 开始扫描...\n\n")

	results := scanner.Scan(scanURL, scanAPIKey, pl, detector)

	vulnCount := 0
	for _, r := range results {
		if r.Vulnerable {
			vulnCount++
		}
	}

	fmt.Fprintf(os.Stderr, "[*] 扫描完成: %d/%d 条载荷触发漏洞\n\n", vulnCount, len(pl))

	switch strings.ToLower(scanOutput) {
	case "markdown":
		fmt.Println(reporter.GenerateMarkdownReport(results, scanURL))
	default:
		printTextReport(results)
	}

	return nil
}

// buildDetector 根据名称构建对应的检测器实例。
// 当前支持 "keyword"（方案A），预留 "composite"（组合方案A+B）等扩展。
func buildDetector(name string) (scanner.Detector, error) {
	switch strings.ToLower(name) {
	case "keyword":
		return &scanner.KeywordDetector{}, nil
	case "composite":
		// 组合检测器：Keyword 快速筛查 + 未来 LLMJudge 二次确认
		// 当前仅启用 KeywordDetector，LLMJudgeDetector 待实现后取消下行注释：
		// judge := scanner.NewLLMJudgeDetector(apiURL, apiKey, "judge-model")
		// return scanner.NewCompositeDetector(&scanner.KeywordDetector{}, judge), nil
		return scanner.NewCompositeDetector(&scanner.KeywordDetector{}), nil
	default:
		return nil, fmt.Errorf("不支持的检测策略: %s（可用: keyword, composite）", name)
	}
}

// printTextReport 以纯文本表格形式打印扫描结果
func printTextReport(results []scanner.Result) {
	fmt.Println(strings.Repeat("=", 90))
	fmt.Printf("%-4s %-28s %-16s %-10s %-12s %s\n", "No.", "Payload", "Type", "Vuln", "Detector", "Evidence")
	fmt.Println(strings.Repeat("-", 90))

	for i, r := range results {
		status := "NO"
		if r.Vulnerable {
			status = "YES"
		}
		det := r.DetectedBy
		if det == "" {
			det = "-"
		}
		fmt.Printf("%-4d %-28s %-16s %-10s %-12s %s\n", i+1, r.PayloadName, r.PayloadType, status, det, r.Evidence)
	}

	fmt.Println(strings.Repeat("=", 90))
	fmt.Printf("Total: %d payloads tested at %s\n", len(results), time.Now().Format(time.RFC3339))
}

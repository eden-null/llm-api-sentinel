package reporter

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
	"time"

	"llm-api-sentinel/scanner"
)

// riskLevel 根据载荷类型返回风险等级
func riskLevel(payloadType string) string {
	switch payloadType {
	case "jailbreak":
		return "Critical"
	case "prompt_injection":
		return "High"
	case "sensitive_data":
		return "Medium"
	default:
		return "Low"
	}
}

// typeLabel 返回载荷类型的友好标签
func typeLabel(payloadType string) string {
	switch payloadType {
	case "prompt_injection":
		return "Prompt Injection"
	case "jailbreak":
		return "Jailbreak"
	case "sensitive_data":
		return "Sensitive Data Exposure"
	default:
		return payloadType
	}
}

// groupByType 按载荷类型对扫描结果进行分组
func groupByType(results []scanner.Result) map[string][]scanner.Result {
	groups := make(map[string][]scanner.Result)
	for _, r := range results {
		groups[r.PayloadType] = append(groups[r.PayloadType], r)
	}
	return groups
}

const markdownTemplate = `# LLM-API-Sentinel 安全扫描报告

---

## 扫描概况

| 项目 | 详情 |
|------|------|
| **扫描时间** | {{.ScanTime}} |
| **目标 URL** | {{.TargetURL}} |
| **检测策略** | {{.Detector}} |
| **载荷总数** | {{.TotalPayloads}} |
| **漏洞数量** | {{.VulnCount}} |
| **漏洞比例** | {{.VulnRatio}}% |

---

## 漏洞详情（按类型分组）

{{range .VulnGroups}}
### {{.TypeLabel}}（{{.Risk}}）

| # | 载荷名称 | 检测引擎 | 证据 | 风险等级 | 响应摘要 |
|---|---------|---------|------|---------|---------|
{{range $i, $r := .Results}}| {{add $i 1}} | {{$r.PayloadName}} | {{$r.DetectedBy}} | {{$r.Evidence}} | {{riskLevel $r.PayloadType}} | {{escapeMD $r.ResponseText}} |
{{end}}

{{end}}

---

## 安全建议

{{range .VulnGroups}}
- **{{.TypeLabel}}**：发现 {{len .Results}} 个问题。{{.Recommendation}}
{{end}}

---

## 附录

- 扫描器版本: LLM-API-Sentinel v0.1.0
- 检测架构: 可插拔 Detector 接口，支持 Keyword / LLM-Judge / Embedding 三种策略
- 免责声明: 本报告仅用于授权的安全测试，请勿用于非法用途

*报告由 LLM-API-Sentinel 自动生成于 {{.ScanTime}}*
`

// ReportData 报告模板数据
type ReportData struct {
	ScanTime      string
	TargetURL     string
	Detector      string
	TotalPayloads int
	VulnCount     int
	VulnRatio     float64
	VulnGroups    []GroupData
}

// GroupData 漏洞分组数据
type GroupData struct {
	TypeLabel      string
	Risk           string
	Results        []scanner.Result
	Recommendation string
}

// recommendation 根据载荷类型返回修复建议
func recommendation(payloadType string) string {
	switch payloadType {
	case "prompt_injection":
		return "建议在系统提示词中使用明确的分隔符，并对用户输入实施严格的输入验证和过滤。"
	case "jailbreak":
		return "建议加强内容安全护栏，使用多层次的审核机制检测越狱尝试。"
	case "sensitive_data":
		return "建议审计模型训练数据，确保不包含敏感信息，并在 API 层面添加输出过滤。"
	default:
		return "建议进一步分析该载荷类型，制定针对性的防护策略。"
	}
}

// escapeMD 转义 Markdown 特殊字符
func escapeMD(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	if len([]rune(s)) > 80 {
		runes := []rune(s)
		s = string(runes[:80]) + "..."
	}
	return s
}

// GenerateMarkdownReport 生成美观的 Markdown 安全扫描报告
func GenerateMarkdownReport(results []scanner.Result, targetURL string) string {
	vulnerableResults := filterVulnerable(results)

	groups := groupByType(vulnerableResults)

	var groupDataList []GroupData
	for payloadType, results := range groups {
		groupDataList = append(groupDataList, GroupData{
			TypeLabel:      typeLabel(payloadType),
			Risk:           riskLevel(payloadType),
			Results:        results,
			Recommendation: recommendation(payloadType),
		})
	}

	vulnRatio := float64(0)
	if len(results) > 0 {
		vulnRatio = float64(len(vulnerableResults)) / float64(len(results)) * 100
	}

	// 从第一个有 detector 的结果推导检测策略名
	detectorName := "KeywordDetector"
	for _, r := range results {
		if r.DetectedBy != "" {
			detectorName = r.DetectedBy
			break
		}
	}

	data := ReportData{
		ScanTime:      time.Now().Format("2006-01-02 15:04:05"),
		TargetURL:     targetURL,
		Detector:      detectorName,
		TotalPayloads: len(results),
		VulnCount:     len(vulnerableResults),
		VulnRatio:     vulnRatio,
		VulnGroups:    groupDataList,
	}

	funcMap := template.FuncMap{
		"add":       func(a, b int) int { return a + b },
		"riskLevel": riskLevel,
		"escapeMD":  escapeMD,
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(markdownTemplate)
	if err != nil {
		return fmt.Sprintf("模板解析错误: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Sprintf("模板渲染错误: %v", err)
	}

	return buf.String()
}

// filterVulnerable 筛选出存在漏洞的结果
func filterVulnerable(results []scanner.Result) []scanner.Result {
	var vuln []scanner.Result
	for _, r := range results {
		if r.Vulnerable {
			vuln = append(vuln, r)
		}
	}
	return vuln
}

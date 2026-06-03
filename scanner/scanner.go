package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"llm-api-sentinel/models"
	"llm-api-sentinel/payloads"
)

// Result 表示单次扫描结果
type Result struct {
	PayloadName  string
	PayloadType  string
	ResponseText string
	Vulnerable   bool
	Evidence     string
	DetectedBy   string // 触发漏洞的检测器名称，用于审计溯源
}

// Scan 遍历所有载荷，对目标 API 发送请求并通过指定检测器进行安全检测。
// detector 参数接受任何实现了 Detector 接口的对象，支持依赖注入和策略替换。
func Scan(apiURL, apiKey string, pl []payloads.Payload, detector Detector) []Result {
	var results []Result
	for _, p := range pl {
		result := scanSingle(apiURL, apiKey, p, detector)
		results = append(results, result)
	}
	return results
}

// scanSingle 对单个载荷发送请求并用指定检测器判定漏洞
func scanSingle(apiURL, apiKey string, p payloads.Payload, detector Detector) Result {
	respText, err := sendPayloadRequest(apiURL, apiKey, p.Content)
	if err != nil {
		return Result{
			PayloadName:  p.Name,
			PayloadType:  p.Type,
			ResponseText: fmt.Sprintf("请求错误: %v", err),
			Vulnerable:   false,
			Evidence:     "",
			DetectedBy:   "",
		}
	}

	vulnerable, evidence := detector.Detect(p.Type, respText)
	detectedBy := ""
	if vulnerable {
		detectedBy = detector.Name()
	}

	return Result{
		PayloadName:  p.Name,
		PayloadType:  p.Type,
		ResponseText: truncate(respText, 200),
		Vulnerable:   vulnerable,
		Evidence:     evidence,
		DetectedBy:   detectedBy,
	}
}

// sendPayloadRequest 向 LLM API 发送单一用户消息并返回助手回复文本
func sendPayloadRequest(apiURL, apiKey, userContent string) (string, error) {
	reqData := models.ChatRequest{
		Model: "moonshot-v1-8k",
		Messages: []models.ChatMessage{
			{Role: "user", Content: userContent},
		},
	}

	body, err := json.Marshal(reqData)
	if err != nil {
		return "", fmt.Errorf("序列化请求体失败: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("创建 HTTP 请求失败: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("发送 HTTP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应体失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API 返回状态码 %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp models.ChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", fmt.Errorf("解析响应 JSON 失败: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("响应中无有效 Choices")
	}

	return chatResp.Choices[0].Message.Content, nil
}

// truncate 截取字符串前 n 个字符，超出部分用 "..." 标记
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}

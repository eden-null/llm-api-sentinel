package payloads

import (
	"encoding/json"
	"fmt"
	"os"
)

// Payload 表示一条安全测试载荷（提示词注入、越狱等攻击向量）
type Payload struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Type    string `json:"type"`
}

// LoadPayloads 从指定 JSON 文件反序列化为载荷切片
func LoadPayloads(filepath string) ([]Payload, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("读取载荷文件失败: %w", err)
	}

	var payloads []Payload
	if err := json.Unmarshal(data, &payloads); err != nil {
		return nil, fmt.Errorf("解析载荷 JSON 失败: %w", err)
	}

	if len(payloads) == 0 {
		return nil, fmt.Errorf("载荷文件为空或格式不正确: %s", filepath)
	}

	return payloads, nil
}
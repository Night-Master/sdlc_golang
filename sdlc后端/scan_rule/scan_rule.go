// scan_rule/scan_rule.go
package scan_rule

import (
	"go/ast"
	"go/token"
	"sync"
)

// Vulnerability 表示检测到的漏洞
type Vulnerability struct {
	FilePath string `json:"file_path"` // 文件路径
	FuncName string `json:"func_name"` // 函数名称
	Line     int    `json:"line"`      // 代码行号
	Message  string `json:"message"`   // 漏洞描述
	Severity string `json:"severity"`  // 严重性等级（如 High, Medium, Low）
	CWE      string `json:"cwe"`       // CWE编号（如 CWE-79, CWE-89, CWE-77）
}

// ScanRule 接口，所有扫描规则都需要实现这个接口
type ScanRule interface {
	Name() string
	Description() string
	Scan(filePath string, fileNode *ast.File, fset *token.FileSet) []Vulnerability
}

var (
	rulesMu sync.RWMutex
	rules   []ScanRule
)

// RegisterScanRule 注册一个新的扫描规则
func RegisterScanRule(rule ScanRule) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rules = append(rules, rule)
}

// GetRegisteredRules 获取所有已注册的扫描规则
func GetRegisteredRules() []ScanRule {
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	return rules
}

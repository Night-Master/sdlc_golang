// plugins/sqlinjection.go
package plugins

import (
	"go/ast"
	"go/token"
	"log"
	"regexp"
	"strings"

	"backend/scan_rule" // 根据实际模块路径调整
	"backend/utils"     // 导入 utils 包
)

// SQLInjectionScanner 实现了 ScanRule 接口
type SQLInjectionScanner struct {
	patterns []*regexp.Regexp
}

// NewSQLInjectionScanner 创建一个新的 SQL 注入扫描器
func NewSQLInjectionScanner() *SQLInjectionScanner {
	return &SQLInjectionScanner{
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE)\b`),
		},
	}
}

// Name 返回扫描规则的名称
func (s *SQLInjectionScanner) Name() string {
	return "SQL Injection Scanner"
}

// Description 返回扫描规则的描述
func (s *SQLInjectionScanner) Description() string {
	return "检测 Go 代码中的潜在 SQL 注入漏洞。"
}

// Scan 执行扫描逻辑
func (s *SQLInjectionScanner) Scan(filePath string, fileNode *ast.File, fset *token.FileSet) []scan_rule.Vulnerability {
	var vulnerabilities []scan_rule.Vulnerability

	log.Printf("[SQLInjectionScanner] 开始扫描文件: %s", filePath)

	ast.Inspect(fileNode, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if s.isSQLExecCall(node) {
				log.Printf("[SQLInjectionScanner] 检测到 SQL 执行函数调用: %s", exprString(node.Fun))
				vuls := s.checkSQLInjection(node, filePath, fileNode, fset)
				vulnerabilities = append(vulnerabilities, vuls...)
			}
		case *ast.FuncDecl:
			vuls := s.checkFuncDecl(node, filePath, fileNode, fset)
			vulnerabilities = append(vulnerabilities, vuls...)
		}
		return true
	})

	log.Printf("[SQLInjectionScanner] 完成扫描文件: %s", filePath)
	return vulnerabilities
}

// isSQLExecCall 判断是否为 SQL 执行相关函数调用
func (s *SQLInjectionScanner) isSQLExecCall(call *ast.CallExpr) bool {
	// 识别 *sql.DB 或 *sql.Tx 的 Exec, Query, QueryRow, Prepare
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		methods := map[string]bool{
			"Exec":     true,
			"Query":    true,
			"QueryRow": true,
			"Prepare":  true,
		}
		if methods[sel.Sel.Name] {
			return true
		}
	}
	return false
}

// checkSQLInjection 检查 SQL 执行函数调用是否存在 SQL 注入风险
func (s *SQLInjectionScanner) checkSQLInjection(call *ast.CallExpr, filePath string, fileNode *ast.File, fset *token.FileSet) []scan_rule.Vulnerability {
	var vulns []scan_rule.Vulnerability

	query := findQueryArg(call)
	if query == nil {
		return vulns
	}

	if s.inspectExpr(query) {
		position := fset.Position(call.Pos())
		funcName := utils.GetEnclosingFuncName(call, fileNode)
		vulns = append(vulns, scan_rule.Vulnerability{
			FilePath: filePath,
			FuncName: funcName,
			Line:     position.Line,
			Message:  "检测到潜在的 SQL 注入漏洞。",
			Severity: "High",
			CWE:      "CWE-89", // SQL Injection
		})
	}

	return vulns
}

// checkFuncDecl 检查函数声明中是否存在 SQL 注入风险
func (s *SQLInjectionScanner) checkFuncDecl(funcDecl *ast.FuncDecl, filePath string, fileNode *ast.File, fset *token.FileSet) []scan_rule.Vulnerability {
	var vulnerabilities []scan_rule.Vulnerability

	ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			for _, expr := range stmt.Rhs {
				if s.inspectExpr(expr) {
					position := fset.Position(expr.Pos())
					vulnerabilities = append(vulnerabilities, scan_rule.Vulnerability{
						FilePath: filePath,
						FuncName: funcDecl.Name.Name,
						Line:     position.Line,
						Message:  "检测到潜在的 SQL 注入漏洞（赋值语句）。",
						Severity: "High",
						CWE:      "CWE-89", // SQL Injection
					})
				}
			}
		case *ast.DeclStmt:
			if genDecl, ok := stmt.Decl.(*ast.GenDecl); ok && genDecl.Tok == token.VAR {
				for _, spec := range genDecl.Specs {
					if valueSpec, ok := spec.(*ast.ValueSpec); ok {
						for _, value := range valueSpec.Values {
							if s.inspectExpr(value) {
								position := fset.Position(value.Pos())
								vulnerabilities = append(vulnerabilities, scan_rule.Vulnerability{
									FilePath: filePath,
									FuncName: funcDecl.Name.Name,
									Line:     position.Line,
									Message:  "检测到潜在的 SQL 注入漏洞（变量声明）。",
									Severity: "High",
									CWE:      "CWE-89", // SQL Injection
								})
							}
						}
					}
				}
			}
		}
		return true
	})

	return vulnerabilities
}

// inspectExpr 检查表达式中是否存在潜在的 SQL 注入
func (s *SQLInjectionScanner) inspectExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		operands := getBinaryExprOperands(e)
		for _, op := range operands {
			if lit, ok := op.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				str := strings.Trim(lit.Value, "\"`")
				log.Printf("[SQLInjectionScanner] 检测到的 SQL 查询语句片段: %s", str)
				if s.MatchPatterns(str) {
					return true
				}
			}
		}
	case *ast.CallExpr:
		// 检查类似 fmt.Sprintf 的函数调用
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "fmt" && (sel.Sel.Name == "Sprintf" || sel.Sel.Name == "Printf") {
				for _, arg := range e.Args {
					if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						str := strings.Trim(lit.Value, "\"`")
						log.Printf("[SQLInjectionScanner] 检测到的 SQL 查询语句片段（通过函数调用）: %s", str)
						if s.MatchPatterns(str) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// MatchPatterns 匹配 SQL 关键字模式
func (s *SQLInjectionScanner) MatchPatterns(str string) bool {
	for _, pattern := range s.patterns {
		if pattern.MatchString(str) {
			return true
		}
	}
	return false
}

// findQueryArg 查找 SQL 执行函数调用中的查询参数
func findQueryArg(call *ast.CallExpr) ast.Expr {
	// SQL 执行函数的查询参数通常是第一个参数
	if len(call.Args) == 0 {
		return nil
	}
	return call.Args[0]
}

// getBinaryExprOperands 获取二元表达式中的所有操作数
func getBinaryExprOperands(be *ast.BinaryExpr) []ast.Expr {
	var operands []ast.Expr
	operands = append(operands, be.X, be.Y)
	if left, ok := be.X.(*ast.BinaryExpr); ok {
		operands = append(operands, getBinaryExprOperands(left)...)
	}
	if right, ok := be.Y.(*ast.BinaryExpr); ok {
		operands = append(operands, getBinaryExprOperands(right)...)
	}
	return operands
}

// exprString 获取表达式的字符串表示
func exprString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprString(e.X) + "." + e.Sel.Name
	default:
		return ""
	}
}

// 在 init 函数中注册扫描规则
func init() {
	log.Println("[SQLInjectionScanner] 注册 SQL 注入扫描器")
	scan_rule.RegisterScanRule(NewSQLInjectionScanner())
}

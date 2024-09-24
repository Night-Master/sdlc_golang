// plugins/xss_detection.go
package plugins

import (
	"go/ast"
	"go/token"
	"log"
	"strings"

	"backend/scan_rule" // 根据实际模块路径调整
	"backend/utils"     // 导入 utils 包
)

// XSSScanner 实现了 ScanRule 接口
type XSSScanner struct {
	// 定义需要检测的函数列表及其所属包
	dangerousFunctions map[string]string // 函数名 -> 包路径
}

// NewXSSScanner 创建一个新的 XSS 漏洞扫描器
func NewXSSScanner() *XSSScanner {
	return &XSSScanner{
		dangerousFunctions: map[string]string{
			"HTML":     "html/template",
			"JS":       "html/template",
			"JSStr":    "html/template",
			"URL":      "html/template",
			"Srcset":   "html/template",
			"CSS":      "html/template",
			"HTMLAttr": "html/template",
		},
	}
}

// Name 返回扫描规则的名称
func (s *XSSScanner) Name() string {
	return "XSS Scanner"
}

// Description 返回扫描规则的描述
func (s *XSSScanner) Description() string {
	return "检测 Go 代码中未正确转义的模板使用，可能导致跨站脚本（XSS）漏洞。"
}

// Scan 执行扫描逻辑
func (s *XSSScanner) Scan(filePath string, fileNode *ast.File, fset *token.FileSet) []scan_rule.Vulnerability {
	var vulnerabilities []scan_rule.Vulnerability

	log.Printf("[XSSScanner] 开始扫描文件: %s", filePath)

	// 解析导入语句，建立包别名到包路径的映射
	imports := make(map[string]string) // 包别名 -> 包路径
	for _, imp := range fileNode.Imports {
		// 去除双引号
		path := strings.Trim(imp.Path.Value, "\"")
		var alias string
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			// 默认包名为路径的最后一部分
			parts := strings.Split(path, "/")
			alias = parts[len(parts)-1]
		}
		imports[alias] = path
	}

	// 收集所有可能的用户输入变量
	userInputVars := make(map[string]bool)
	ast.Inspect(fileNode, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, rhs := range node.Rhs {
				if callExpr, ok := rhs.(*ast.CallExpr); ok {
					if sel, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
						if sel.Sel.Name == "ShouldBindJSON" || sel.Sel.Name == "ShouldBind" {
							// 通常第一个参数是指向结构体的指针
							if len(callExpr.Args) > 0 {
								if unaryExpr, ok := callExpr.Args[0].(*ast.UnaryExpr); ok && unaryExpr.Op == token.AND {
									if ident, ok := unaryExpr.X.(*ast.Ident); ok {
										userInputVars[ident.Name] = true
										log.Printf("[XSSScanner] 识别到用户输入结构体变量: %s", ident.Name)
									}
								}
							}
						}
					}
				}
			}
		}
		return true
	})

	log.Printf("[XSSScanner] 识别到 %d 个用户输入结构体变量", len(userInputVars))
	for varName := range userInputVars {
		log.Printf("[XSSScanner] 用户输入结构体变量: %s", varName)
	}

	// 遍历 AST 节点，查找危险函数调用
	ast.Inspect(fileNode, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			// 检测危险函数调用
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				funcName := sel.Sel.Name
				if expectedPkg, exists := s.dangerousFunctions[funcName]; exists {
					// 获取函数调用的包别名
					if pkgIdent, ok := sel.X.(*ast.Ident); ok {
						pkgPath, pkgExists := imports[pkgIdent.Name]
						if pkgExists && pkgPath == expectedPkg {
							log.Printf("[XSSScanner] 检测到危险函数调用: %s.%s", pkgIdent.Name, funcName)
							vuls := s.checkXSS(node, filePath, fileNode, fset, userInputVars)
							vulnerabilities = append(vulnerabilities, vuls...)
						}
					}
				}
			}
		case *ast.FuncDecl:
			// 检查函数声明中的潜在漏洞
			vuls := s.checkFuncDecl(node, filePath, fileNode, fset, userInputVars)
			vulnerabilities = append(vulnerabilities, vuls...)
		}
		return true
	})

	log.Printf("[XSSScanner] 识别到 %d 个潜在 XSS 漏洞", len(vulnerabilities))
	for _, vuln := range vulnerabilities {
		log.Printf("[XSSScanner] 漏洞: %s 在函数 %s 的第 %d 行", vuln.Message, vuln.FuncName, vuln.Line)
	}

	log.Printf("[XSSScanner] 完成扫描文件: %s", filePath)
	return vulnerabilities
}

// checkXSS 检查模板函数调用是否存在 XSS 风险
func (s *XSSScanner) checkXSS(call *ast.CallExpr, filePath string, fileNode *ast.File, fset *token.FileSet, userInputVars map[string]bool) []scan_rule.Vulnerability {
	var vulns []scan_rule.Vulnerability

	// 遍历函数调用的参数，检查是否包含用户输入变量
	for _, arg := range call.Args {
		// 检查通过结构体字段使用用户输入变量，如 user.Input
		if selExpr, ok := arg.(*ast.SelectorExpr); ok {
			if ident, ok := selExpr.X.(*ast.Ident); ok {
				if userInputVars[ident.Name] {
					position := fset.Position(selExpr.Sel.Pos())
					funcName := utils.GetEnclosingFuncName(call, fileNode)
					vulns = append(vulns, scan_rule.Vulnerability{
						FilePath: filePath,
						FuncName: funcName,
						Line:     position.Line,
						Message:  "检测到潜在的 XSS 漏洞，未对用户输入进行适当转义。",
						Severity: "High",
						CWE:      "CWE-79", // Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
					})
					log.Printf("[XSSScanner] 发现 XSS 漏洞: %s 在函数 %s 的第 %d 行", selExpr.Sel.Name, funcName, position.Line)
				}
			}
		} else if ident, ok := arg.(*ast.Ident); ok {
			// 检查直接变量使用，如 input
			if userInputVars[ident.Name] {
				position := fset.Position(ident.Pos())
				funcName := utils.GetEnclosingFuncName(call, fileNode)
				vulns = append(vulns, scan_rule.Vulnerability{
					FilePath: filePath,
					FuncName: funcName,
					Line:     position.Line,
					Message:  "检测到潜在的 XSS 漏洞，未对用户输入进行适当转义。",
					Severity: "High",
					CWE:      "CWE-79", // Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
				})
				log.Printf("[XSSScanner] 发现 XSS 漏洞: %s 在函数 %s 的第 %d 行", ident.Name, funcName, position.Line)
			}
		}
	}

	return vulns
}

// checkFuncDecl 检查函数声明中是否存在 XSS 风险
func (s *XSSScanner) checkFuncDecl(funcDecl *ast.FuncDecl, filePath string, fileNode *ast.File, fset *token.FileSet, userInputVars map[string]bool) []scan_rule.Vulnerability {
	var vulnerabilities []scan_rule.Vulnerability

	ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			for _, expr := range stmt.Rhs {
				if selExpr, ok := expr.(*ast.SelectorExpr); ok {
					if ident, ok := selExpr.X.(*ast.Ident); ok {
						if userInputVars[ident.Name] {
							position := fset.Position(selExpr.Sel.Pos())
							vulnerabilities = append(vulnerabilities, scan_rule.Vulnerability{
								FilePath: filePath,
								FuncName: funcDecl.Name.Name,
								Line:     position.Line,
								Message:  "检测到潜在的 XSS 漏洞（赋值语句），未对用户输入进行适当转义。",
								Severity: "High",
								CWE:      "CWE-79", // XSS
							})
							log.Printf("[XSSScanner] 发现 XSS 漏洞: %s 在函数 %s 的第 %d 行", selExpr.Sel.Name, funcDecl.Name.Name, position.Line)
						}
					}
				} else if ident, ok := expr.(*ast.Ident); ok {
					if userInputVars[ident.Name] {
						position := fset.Position(ident.Pos())
						vulnerabilities = append(vulnerabilities, scan_rule.Vulnerability{
							FilePath: filePath,
							FuncName: funcDecl.Name.Name,
							Line:     position.Line,
							Message:  "检测到潜在的 XSS 漏洞（赋值语句），未对用户输入进行适当转义。",
							Severity: "High",
							CWE:      "CWE-79", // XSS
						})
						log.Printf("[XSSScanner] 发现 XSS 漏洞: %s 在函数 %s 的第 %d 行", ident.Name, funcDecl.Name.Name, position.Line)
					}
				}
			}
		case *ast.DeclStmt:
			if genDecl, ok := stmt.Decl.(*ast.GenDecl); ok && genDecl.Tok == token.VAR {
				for _, spec := range genDecl.Specs {
					if valueSpec, ok := spec.(*ast.ValueSpec); ok {
						for _, value := range valueSpec.Values {
							if selExpr, ok := value.(*ast.SelectorExpr); ok {
								if ident, ok := selExpr.X.(*ast.Ident); ok {
									if userInputVars[ident.Name] {
										position := fset.Position(selExpr.Sel.Pos())
										vulnerabilities = append(vulnerabilities, scan_rule.Vulnerability{
											FilePath: filePath,
											FuncName: funcDecl.Name.Name,
											Line:     position.Line,
											Message:  "检测到潜在的 XSS 漏洞（变量声明），未对用户输入进行适当转义。",
											Severity: "High",
											CWE:      "CWE-79", // XSS
										})
										log.Printf("[XSSScanner] 发现 XSS 漏洞: %s 在函数 %s 的第 %d 行", selExpr.Sel.Name, funcDecl.Name.Name, position.Line)
									}
								}
							} else if ident, ok := value.(*ast.Ident); ok {
								if userInputVars[ident.Name] {
									position := fset.Position(ident.Pos())
									vulnerabilities = append(vulnerabilities, scan_rule.Vulnerability{
										FilePath: filePath,
										FuncName: funcDecl.Name.Name,
										Line:     position.Line,
										Message:  "检测到潜在的 XSS 漏洞（变量声明），未对用户输入进行适当转义。",
										Severity: "High",
										CWE:      "CWE-79", // XSS
									})
									log.Printf("[XSSScanner] 发现 XSS 漏洞: %s 在函数 %s 的第 %d 行", ident.Name, funcDecl.Name.Name, position.Line)
								}
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

// 在 init 函数中注册扫描规则
func init() {
	log.Println("[XSSScanner] 注册 XSS 漏洞扫描器")
	scan_rule.RegisterScanRule(NewXSSScanner())
	log.Println("[XSSScanner] XSS 漏洞扫描器已注册")
}

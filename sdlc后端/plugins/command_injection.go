// plugins/command_injection.go
package plugins

import (
	"go/ast"
	"go/token"
	"log"
	"strings"

	"backend/scan_rule" // 根据实际模块路径调整
	"backend/utils"     // 导入 utils 包
)

// CommandInjectionScanner 实现了 ScanRule 接口
type CommandInjectionScanner struct{}

// NewCommandInjectionScanner 创建一个新的命令执行漏洞扫描器
func NewCommandInjectionScanner() *CommandInjectionScanner {
	return &CommandInjectionScanner{}
}

// Name 返回扫描规则的名称
func (s *CommandInjectionScanner) Name() string {
	return "Command Injection Scanner"
}

// Description 返回扫描规则的描述
func (s *CommandInjectionScanner) Description() string {
	return "检测 Go 代码中的潜在命令执行漏洞。"
}

// Scan 执行扫描逻辑
func (s *CommandInjectionScanner) Scan(filePath string, fileNode *ast.File, fset *token.FileSet) []scan_rule.Vulnerability {
	var vulnerabilities []scan_rule.Vulnerability

	log.Printf("[CommandInjectionScanner] 开始扫描文件: %s", filePath)

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
										log.Printf("[CommandInjectionScanner] 识别到用户输入结构体变量: %s", ident.Name)
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

	log.Printf("[CommandInjectionScanner] 识别到 %d 个用户输入结构体变量", len(userInputVars))
	for varName := range userInputVars {
		log.Printf("[CommandInjectionScanner] 用户输入结构体变量: %s", varName)
	}

	// 定义需要检测的危险函数列表及其所属包
	dangerousFunctions := map[string]string{
		"Command":        "os/exec",
		"CommandContext": "os/exec",
		"Exec":           "os/exec", // 注意：只检测来自 os/exec 包的 Exec
		"ForkExec":       "os/exec",
		"StartProcess":   "os/exec",
	}

	ast.Inspect(fileNode, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			// 检测危险函数调用
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				funcName := sel.Sel.Name
				if expectedPkg, exists := dangerousFunctions[funcName]; exists {
					// 获取函数调用的包别名
					if pkgIdent, ok := sel.X.(*ast.Ident); ok {
						pkgPath, pkgExists := imports[pkgIdent.Name]
						if pkgExists && pkgPath == expectedPkg {
							log.Printf("[CommandInjectionScanner] 检测到危险函数调用: %s.%s", pkgIdent.Name, funcName)
							vuls := s.checkCommandInjection(node, filePath, fileNode, fset, userInputVars)
							vulnerabilities = append(vulnerabilities, vuls...)
						}
					}
				}
			} else if ident, ok := node.Fun.(*ast.Ident); ok {
				funcName := ident.Name
				if _, exists := dangerousFunctions[funcName]; exists {
					// 无包别名的函数调用，假设是来自当前包或预先定义的包
					// 为了准确性，需要更多信息，此处可能需要扩展
					log.Printf("[CommandInjectionScanner] 检测到危险函数调用: %s", funcName)
					vuls := s.checkCommandInjection(node, filePath, fileNode, fset, userInputVars)
					vulnerabilities = append(vulnerabilities, vuls...)
				}
			}
		case *ast.FuncDecl:
			vuls := s.checkFuncDecl(node, filePath, fileNode, fset, userInputVars)
			vulnerabilities = append(vulnerabilities, vuls...)
		}
		return true
	})

	log.Printf("[CommandInjectionScanner] 识别到 %d 个潜在命令执行漏洞", len(vulnerabilities))
	for _, vuln := range vulnerabilities {
		log.Printf("[CommandInjectionScanner] 漏洞: %s 在函数 %s 的第 %d 行", vuln.Message, vuln.FuncName, vuln.Line)
	}

	log.Printf("[CommandInjectionScanner] 完成扫描文件: %s", filePath)
	return vulnerabilities
}

// checkCommandInjection 检查命令执行函数调用是否存在命令执行风险
func (s *CommandInjectionScanner) checkCommandInjection(call *ast.CallExpr, filePath string, fileNode *ast.File, fset *token.FileSet, userInputVars map[string]bool) []scan_rule.Vulnerability {
	var vulns []scan_rule.Vulnerability

	// 遍历函数调用的参数，检查是否包含用户输入变量
	for _, arg := range call.Args {
		// 检查通过结构体字段使用用户输入变量，如 cmdReq.Command
		if selExpr, ok := arg.(*ast.SelectorExpr); ok {
			if ident, ok := selExpr.X.(*ast.Ident); ok {
				if userInputVars[ident.Name] {
					position := fset.Position(selExpr.Sel.Pos())
					funcName := utils.GetEnclosingFuncName(call, fileNode)
					vulns = append(vulns, scan_rule.Vulnerability{
						FilePath: filePath,
						FuncName: funcName,
						Line:     position.Line,
						Message:  "检测到潜在的命令执行漏洞，未对用户输入进行适当处理。",
						Severity: "High",
						CWE:      "CWE-77", // Improper Neutralization of Special Elements used in an OS Command ('Command Injection')
					})
					log.Printf("[CommandInjectionScanner] 发现命令执行漏洞: %s 在函数 %s 的第 %d 行", selExpr.Sel.Name, funcName, position.Line)
				}
			}
		} else if ident, ok := arg.(*ast.Ident); ok {
			// 检查直接变量使用，如 cmd
			if userInputVars[ident.Name] {
				position := fset.Position(ident.Pos())
				funcName := utils.GetEnclosingFuncName(call, fileNode)
				vulns = append(vulns, scan_rule.Vulnerability{
					FilePath: filePath,
					FuncName: funcName,
					Line:     position.Line,
					Message:  "检测到潜在的命令执行漏洞，未对用户输入进行适当处理。",
					Severity: "High",
					CWE:      "CWE-77", // Improper Neutralization of Special Elements used in an OS Command ('Command Injection')
				})
				log.Printf("[CommandInjectionScanner] 发现命令执行漏洞: %s 在函数 %s 的第 %d 行", ident.Name, funcName, position.Line)
			}
		} else if callExpr, ok := arg.(*ast.CallExpr); ok {
			// 如果参数是函数调用，进一步检查返回值是否为用户输入
			if sel, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "Input" || sel.Sel.Name == "Get" || sel.Sel.Name == "Param" {
					position := fset.Position(arg.Pos())
					funcName := utils.GetEnclosingFuncName(call, fileNode)
					vulns = append(vulns, scan_rule.Vulnerability{
						FilePath: filePath,
						FuncName: funcName,
						Line:     position.Line,
						Message:  "检测到潜在的命令执行漏洞，用户输入通过函数调用直接传递给命令执行函数。",
						Severity: "High",
						CWE:      "CWE-77", // Improper Neutralization of Special Elements used in an OS Command ('Command Injection')
					})
					log.Printf("[CommandInjectionScanner] 发现命令执行漏洞: 用户输入通过函数调用直接传递给命令执行函数 在函数 %s 的第 %d 行", funcName, position.Line)
				}
			}
		}
	}

	return vulns
}

// checkFuncDecl 检查函数声明中是否存在命令执行风险
func (s *CommandInjectionScanner) checkFuncDecl(funcDecl *ast.FuncDecl, filePath string, fileNode *ast.File, fset *token.FileSet, userInputVars map[string]bool) []scan_rule.Vulnerability {
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
								Message:  "检测到潜在的命令执行漏洞（赋值语句）。",
								Severity: "High",
								CWE:      "CWE-77", // Command Injection
							})
							log.Printf("[CommandInjectionScanner] 发现命令执行漏洞: %s 在函数 %s 的第 %d 行", selExpr.Sel.Name, funcDecl.Name.Name, position.Line)
						}
					}
				} else if ident, ok := expr.(*ast.Ident); ok {
					if userInputVars[ident.Name] {
						position := fset.Position(ident.Pos())
						vulnerabilities = append(vulnerabilities, scan_rule.Vulnerability{
							FilePath: filePath,
							FuncName: funcDecl.Name.Name,
							Line:     position.Line,
							Message:  "检测到潜在的命令执行漏洞（赋值语句）。",
							Severity: "High",
							CWE:      "CWE-77", // Command Injection
						})
						log.Printf("[CommandInjectionScanner] 发现命令执行漏洞: %s 在函数 %s 的第 %d 行", ident.Name, funcDecl.Name.Name, position.Line)
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
											Message:  "检测到潜在的命令执行漏洞（变量声明）。",
											Severity: "High",
											CWE:      "CWE-77", // Command Injection
										})
										log.Printf("[CommandInjectionScanner] 发现命令执行漏洞: %s 在函数 %s 的第 %d 行", selExpr.Sel.Name, funcDecl.Name.Name, position.Line)
									}
								}
							} else if ident, ok := value.(*ast.Ident); ok {
								if userInputVars[ident.Name] {
									position := fset.Position(ident.Pos())
									vulnerabilities = append(vulnerabilities, scan_rule.Vulnerability{
										FilePath: filePath,
										FuncName: funcDecl.Name.Name,
										Line:     position.Line,
										Message:  "检测到潜在的命令执行漏洞（变量声明）。",
										Severity: "High",
										CWE:      "CWE-77", // Command Injection
									})
									log.Printf("[CommandInjectionScanner] 发现命令执行漏洞: %s 在函数 %s 的第 %d 行", ident.Name, funcDecl.Name.Name, position.Line)
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
	log.Println("[CommandInjectionScanner] 注册命令执行漏洞扫描器")
	scan_rule.RegisterScanRule(NewCommandInjectionScanner())
	log.Println("[CommandInjectionScanner] 命令执行漏洞扫描器已注册")
}

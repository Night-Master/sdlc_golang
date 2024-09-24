// utils/utils.go
package utils

import (
	"go/ast"
)

// GetEnclosingFuncName 获取AST节点所属的函数名称
func GetEnclosingFuncName(n ast.Node, fileNode *ast.File) string {
	var funcName string
	ast.Inspect(fileNode, func(node ast.Node) bool {
		if node == nil {
			return true
		}
		switch fn := node.(type) {
		case *ast.FuncDecl:
			if containsNode(fn.Body, n) {
				funcName = fn.Name.Name
				return false // 找到后停止遍历
			}
		}
		return true
	})
	return funcName
}

// containsNode 检查funcBody是否包含目标节点
func containsNode(funcBody *ast.BlockStmt, target ast.Node) bool {
	found := false
	ast.Inspect(funcBody, func(n ast.Node) bool {
		if n == target {
			found = true
			return false
		}
		return true
	})
	return found
}

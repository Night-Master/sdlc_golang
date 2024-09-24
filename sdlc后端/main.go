package main

import (
	_ "backend/plugins" // 引入插件
	"backend/routes"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	router := gin.Default()

	// 初始化路由
	routes.SetupRoutes(router)
	router.Run(":2333")
}

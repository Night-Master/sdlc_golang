package routes

import (
	"backend/initproject"
	"backend/middleware"
	"backend/vulnerabilities"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func SetupRoutes(router *gin.Engine) {
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization"}
	router.Use(cors.New(config))

	router.GET("/init_sqllite3", initproject.Init_sqllite3)
	router.GET("/rce", vulnerabilities.RemoteCodeExecution)
	router.POST("/sql_injection_sqlite3_safe", vulnerabilities.Sql_injection_sqlite3_safe)
	router.POST("/sql_injection_sqlite3", vulnerabilities.Sql_injection_sqlite3)
	router.POST("/reflect_xss", vulnerabilities.ReflectXss)
	router.POST("/reflect_xss_safe", vulnerabilities.ReflectXssSafe)

	// 保护需要验证的API
	auth := router.Group("/")
	auth.Use(middleware.AuthMiddleware())
	{
		auth.POST("/get_comments", vulnerabilities.Get_comments)
		auth.POST("/create_comments", vulnerabilities.Create_comments)
		auth.POST("/create_comments_safe", vulnerabilities.Create_comments_safe)
		auth.POST("/clear_comments", vulnerabilities.Clear_comments)
	}
}

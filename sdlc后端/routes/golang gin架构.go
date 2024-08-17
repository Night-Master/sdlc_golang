golang gin架构
我使用gin的jwt作为身份校验机制，可以讲讲我的creat_comment接口收到token时如何拿到username么
route.go:
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
	}
}
main.go:
package main

import (
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

jwt.go:
package utils

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwtSecret = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func GenerateToken(username string) (string, error) {
	nowTime := time.Now()
	expireTime := nowTime.Add(3 * time.Hour)

	claims := Claims{
		username,
		jwt.StandardClaims{
			ExpiresAt: expireTime.Unix(),
			Issuer:    "your_app_name",
		},
	}

	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tokenClaims.SignedString(jwtSecret)
	return token, err
}

func ParseToken(token string) (*Claims, error) {
	tokenClaims, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if tokenClaims != nil {
		if claims, ok := tokenClaims.Claims.(*Claims); ok && tokenClaims.Valid {
			return claims, nil
		}
	}
	return nil, err
}
middleware/auth.go:
package middleware

import (
	"net/http"

	"backend/utils"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusOK, gin.H{"status": 0, "message": "您未登录，请勿未授权访问！"})
			c.Abort()
			return
		}

		claims, err := utils.ParseToken(token)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": 0, "message": "登录凭证过期"})
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}
create_comments:

func Create_comments(c *gin.Context) {
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	type CommentRequest struct {
		Username string `json:"username" binding:"required"`
		Content  string `json:"content" binding:"required"`
	}

	var commentReq CommentRequest
	if err := c.ShouldBindJSON(&commentReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid request"})
		return
	}

	_, err = db.Exec("INSERT INTO comments (username, content) VALUES (?, ?)", commentReq.Username, commentReq.Content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": 1, "message": "Comment added successfully"})
}

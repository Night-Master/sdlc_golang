package vulnerabilities

import (
	"backend/utils"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

// 生成RSA密钥对
var privateKey *rsa.PrivateKey
var publicKeyBytes []byte

func init() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	publicKeyBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	})
}

// 加密函数
func Encrypt(data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, data)
}

// 解密函数
func Decrypt(ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
}

func GetPublicKey(c *gin.Context) {
	c.String(http.StatusOK, string(publicKeyBytes))
}

func Sql_injection_sqlite3(c *gin.Context) {
	type LoginRequest struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	var loginReq LoginRequest
	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid request"})
		return
	}

	username := loginReq.Username
	password := loginReq.Password
	log.Println("username:", username)
	log.Println("password:", password)

	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer db.Close()

	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)
	log.Println("query:", query)
	rows, err := db.Query(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer rows.Close()

	if rows.Next() {
		c.JSON(http.StatusOK, gin.H{"status": 1, "message": "Login successful!"})
	} else {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Login failed!"})
	}
}

func Sql_injection_sqlite3_safe(c *gin.Context) {
	type LoginRequest struct {
		Username []byte `json:"username" binding:"required"`
		Password []byte `json:"password" binding:"required"`
	}
	var loginReq LoginRequest
	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid request"})
		return
	}

	// 解密用户名和密码
	username, err := Decrypt(loginReq.Username)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid username"})
		return
	}
	password, err := Decrypt(loginReq.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid password"})
		return
	}

	log.Println("username:", string(username))
	log.Println("password:", string(password))

	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer db.Close()

	query := "SELECT * FROM users WHERE username=? AND password=?"
	log.Println("query:", query)
	rows, err := db.Query(query, string(username), string(password))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer rows.Close()

	if rows.Next() {
		token, err := utils.GenerateToken(string(username))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": 1, "message": "Login successful!", "token": token, "username": string(username)})
	} else {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Login failed!"})
	}
}

func ChangePassword_safe(c *gin.Context) {
	type ChangePasswordRequest struct {
		CurrentPassword []byte `json:"currentPassword" binding:"required"`
		NewPassword     []byte `json:"newPassword" binding:"required"`
	}
	var changePasswordReq ChangePasswordRequest
	if err := c.ShouldBindJSON(&changePasswordReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid request"})
		return
	}

	// 解密当前密码和新密码
	currentPassword, err := Decrypt(changePasswordReq.CurrentPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid current password"})
		return
	}
	newPassword, err := Decrypt(changePasswordReq.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid new password"})
		return
	}

	log.Println("currentPassword:", string(currentPassword))
	log.Println("newPassword:", string(newPassword))

	// 从上下文中获取 username
	username, exists := c.Get("username")
	// 确保 username 是 string 类型
	usernameStr, ok := username.(string)
	if !ok {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"status": 0, "message": "User not authenticated"})
		return
	}

	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer db.Close()

	// 使用事务
	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer tx.Rollback()

	// 验证当前密码
	query := "SELECT * FROM users WHERE username=? AND password=?"
	log.Println("query:", query)
	rows, err := tx.Query(query, usernameStr, string(currentPassword))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer rows.Close()

	if !rows.Next() {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Current password is incorrect"})
		return
	}

	// 更新密码
	updateQuery := "UPDATE users SET password=? WHERE username=? AND password=?"
	log.Println("updateQuery:", updateQuery)
	_, err = tx.Exec(updateQuery, string(newPassword), usernameStr, string(currentPassword))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}

	// 提交事务
	err = tx.Commit()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": 1, "message": "Password changed successfully"})
}

func ChangePassword_plaintext(c *gin.Context) {
	type ChangePasswordRequest struct {
		CurrentPassword string `json:"currentPassword" binding:"required"`
		NewPassword     string `json:"newPassword" binding:"required"`
	}
	var changePasswordReq ChangePasswordRequest
	if err := c.ShouldBindJSON(&changePasswordReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid request"})
		return
	}

	currentPassword := changePasswordReq.CurrentPassword
	newPassword := changePasswordReq.NewPassword

	log.Println("currentPassword:", currentPassword)
	log.Println("newPassword:", newPassword)

	// 从上下文中获取 username
	username, exists := c.Get("username")
	// 确保 username 是 string 类型
	usernameStr, ok := username.(string)
	if !ok {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"status": 0, "message": "User not authenticated"})
		return
	}

	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer db.Close()

	// 使用事务
	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer tx.Rollback()

	// 验证当前密码
	query := "SELECT * FROM users WHERE username=? AND password=?"
	log.Println("query:", query)
	rows, err := tx.Query(query, usernameStr, currentPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer rows.Close()

	if !rows.Next() {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Current password is incorrect"})
		return
	}

	// 更新密码
	updateQuery := "UPDATE users SET password=? WHERE username=? AND password=?"
	log.Println("updateQuery:", updateQuery)
	_, err = tx.Exec(updateQuery, newPassword, usernameStr, currentPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}

	// 提交事务
	err = tx.Commit()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": 1, "message": "Password changed successfully"})
}

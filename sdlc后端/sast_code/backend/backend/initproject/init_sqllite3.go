package initproject

import (
	"database/sql"
	"fmt"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

func Init_sqllite3(c *gin.Context) {
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		fmt.Println("Failed to connect to the database:", err)
		return
	}
	defer db.Close()

	// 创建 users 表
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		password TEXT NOT NULL
	)
	`)
	if err != nil {
		fmt.Println("Failed to create users table:", err)
		return
	}

	// 创建 products 表
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS products (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL
	)
	`)
	if err != nil {
		fmt.Println("Failed to create products table:", err)
		return
	}

	// 创建 comments 表
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            content TEXT NOT NULL
        )
	`)
	if err != nil {
		fmt.Println("Failed to create comments table:", err)
		return
	}

	// 插入一些示例数据到 users 表
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", "admin", "admin123")
	if err != nil {
		fmt.Println("Failed to insert data into users table:", err)
		return
	}
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", "user1", "password1")
	if err != nil {
		fmt.Println("Failed to insert data into users table:", err)
		return
	}

	// 插入一些示例数据到 products 表
	_, err = db.Exec("INSERT INTO products (name) VALUES (?)", "Product A")
	if err != nil {
		fmt.Println("Failed to insert data into products table:", err)
		return
	}
	_, err = db.Exec("INSERT INTO products (name) VALUES (?)", "Product B")
	if err != nil {
		fmt.Println("Failed to insert data into products table:", err)
		return
	}

	// 插入一些示例数据到 comments 表
	_, err = db.Exec("INSERT INTO comments (username, content) VALUES (?, ?)", "admin", "hello")
	if err != nil {
		fmt.Println("Failed to insert data into users table:", err)
		return
	}
	_, err = db.Exec("INSERT INTO comments (username, content) VALUES (?, ?)", "user1", "我要学渗透")
	if err != nil {
		fmt.Println("Failed to insert data into users table:", err)
		return
	}

	fmt.Println("SQLite 数据库和表已成功创建，并插入了示例数据。")
}

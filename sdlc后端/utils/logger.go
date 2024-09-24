// utils/logger.go
package utils

import (
	"log"
	"os"
)

var (
	// Logger 是全局日志记录器
	Logger *log.Logger
)

func init() {
	Logger = log.New(os.Stdout, "", log.LstdFlags)
}

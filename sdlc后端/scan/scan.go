package scan

import (
	"archive/zip"
	"backend/scan_rule"
	"backend/utils"
	"database/sql"
	"fmt"
	"go/parser"
	"go/token"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

var (
	scanMutex  sync.Mutex
	progress   = make(map[string]int)
	totalFiles = make(map[string]int)
	vulns      = make(map[string][]scan_rule.Vulnerability)
	status     = make(map[string]string)
)

// Task represents the metadata of a scan task
type Task struct {
	TaskID    string    `json:"taskID"`
	Status    string    `json:"status"`
	StartTime time.Time `json:"startTime"`
	EndTime   time.Time `json:"endTime,omitempty"`
}

// 初始化SQLite数据库，并确保tasks表存在
func initDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./report.db")
	if err != nil {
		return nil, err
	}

	// 创建tasks表
	createTasksTableSQL := `CREATE TABLE IF NOT EXISTS tasks (
		task_id TEXT PRIMARY KEY,
		status TEXT,
		start_time DATETIME,
		end_time DATETIME
	);`
	_, err = db.Exec(createTasksTableSQL)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// ScanStartDir 启动路径扫描，接受JSON参数
func ScanStartDir(c *gin.Context) {
	type ScanDirRequest struct {
		Path string `json:"path" binding:"required"`
	}

	var req ScanDirRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid request"})
		return
	}

	// 对路径进行转义
	dir := html.EscapeString(req.Path)
	if dir == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "路径不能为空"})
		return
	}

	// 检查路径是否存在且为目录
	info, err := os.Stat(dir)
	if os.IsNotExist(err) || !info.IsDir() {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "提供的路径不存在或不是目录"})
		return
	}

	taskID := uuid.New().String()

	// 插入任务记录到数据库
	db, err := initDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "无法连接数据库"})
		return
	}
	defer db.Close()

	startTime := time.Now()
	_, err = db.Exec(`INSERT INTO tasks (task_id, status, start_time) VALUES (?, ?, ?)`, taskID, "scanning", startTime)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "无法创建任务"})
		return
	}

	go startScan(dir, taskID)

	c.JSON(http.StatusOK, gin.H{
		"status":  1,
		"message": "路径扫描任务已启动",
		"taskID":  taskID,
	})
}

// ScanStartZip 启动压缩包扫描
func ScanStartZip(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "上传文件失败"})
		return
	}

	// 确保sast_code目录存在
	if err := os.MkdirAll("sast_code", 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "无法创建保存目录"})
		return
	}

	// 将zip文件保存到sast_code目录
	zipFileName := filepath.Join("sast_code", file.Filename)
	if err := c.SaveUploadedFile(file, zipFileName); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "文件保存失败"})
		return
	}

	// 解压文件
	extractedDir := filepath.Join("sast_code", strings.TrimSuffix(file.Filename, ".zip"))
	if err := unzipFile(zipFileName, extractedDir); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "解压失败"})
		return
	}

	// 删除zip文件，保留解压后的文件夹
	if err := os.Remove(zipFileName); err != nil {
		utils.Logger.Printf("删除zip文件失败: %v", err)
	}

	// 检查解压后的目录是否存在
	info, err := os.Stat(extractedDir)
	if os.IsNotExist(err) || !info.IsDir() {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "解压后的目录不存在或不是目录"})
		return
	}

	taskID := uuid.New().String()

	// 插入任务记录到数据库
	db, err := initDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "无法连接数据库"})
		return
	}
	defer db.Close()

	startTime := time.Now()
	_, err = db.Exec(`INSERT INTO tasks (task_id, status, start_time) VALUES (?, ?, ?)`, taskID, "scanning", startTime)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "无法创建任务"})
		return
	}

	go startScan(extractedDir, taskID)

	c.JSON(http.StatusOK, gin.H{
		"status":  1,
		"message": "压缩包扫描任务已启动",
		"taskID":  taskID,
	})
}

// unzipFile 解压zip文件到指定目录
func unzipFile(zipFile, destDir string) error {
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(destDir, f.Name)

		// 防止Zip路径穿越攻击
		if !strings.HasPrefix(fpath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("非法的文件路径: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, f.Mode()); err != nil {
				return err
			}
			continue
		}

		// 确保父目录存在
		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)

		// 关闭文件句柄
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
}

// startScan 扫描函数，保持原有的扫描逻辑，并更新任务状态
func startScan(dir, taskID string) {
	// 初始化文件集
	fset := token.NewFileSet()

	// 收集所有Go文件
	var goFiles []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".go" {
			goFiles = append(goFiles, path)
		}
		return nil
	})
	if err != nil {
		utils.Logger.Printf("无法遍历目录: %v", err)
		updateTaskStatus(taskID, "error", time.Now())
		return
	}

	total := len(goFiles)

	scanMutex.Lock()
	progress[taskID] = 0
	totalFiles[taskID] = total
	status[taskID] = "scanning"
	scanMutex.Unlock()

	// 并行扫描文件
	var wg sync.WaitGroup
	vulnsChan := make(chan []scan_rule.Vulnerability, total)

	for _, file := range goFiles {
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
			if err != nil {
				utils.Logger.Printf("无法解析文件 %s: %v", filePath, err)
				return
			}

			// 调用所有注册的扫描规则
			var fileVulns []scan_rule.Vulnerability
			for _, rule := range scan_rule.GetRegisteredRules() {
				vuls := rule.Scan(filePath, node, fset)
				fileVulns = append(fileVulns, vuls...)
			}
			vulnsChan <- fileVulns

			// 更新进度
			scanMutex.Lock()
			progress[taskID]++
			scanMutex.Unlock()
		}(file)
	}

	wg.Wait()
	close(vulnsChan)

	// 收集所有漏洞
	var allVulns []scan_rule.Vulnerability
	for vuls := range vulnsChan {
		allVulns = append(allVulns, vuls...)
	}

	// 保存漏洞到数据库
	err = saveToDB(taskID, allVulns)
	if err != nil {
		utils.Logger.Printf("无法保存漏洞报告到数据库: %v", err)
		updateTaskStatus(taskID, "error", time.Now())
		return
	}

	// 更新任务状态为完成，并记录完成时间
	updateTaskStatus(taskID, "completed", time.Now())

	scanMutex.Lock()
	vulns[taskID] = allVulns
	progress[taskID] = total // 扫描完成
	status[taskID] = "completed"
	scanMutex.Unlock()
}

// updateTaskStatus 更新任务状态和完成时间的辅助函数
func updateTaskStatus(taskID, newStatus string, endTime time.Time) {
	scanMutex.Lock()
	defer scanMutex.Unlock()
	status[taskID] = newStatus
	closeTaskInDB(taskID, newStatus, endTime)
}

// closeTaskInDB 更新数据库中的任务记录
func closeTaskInDB(taskID, status string, endTime time.Time) {
	db, err := initDB()
	if err != nil {
		utils.Logger.Printf("无法连接数据库以更新任务状态: %v", err)
		return
	}
	defer db.Close()

	_, err = db.Exec(`UPDATE tasks SET status = ?, end_time = ? WHERE task_id = ?`, status, endTime, taskID)
	if err != nil {
		utils.Logger.Printf("无法更新任务状态: %v", err)
	}
}

// saveToDB 将漏洞结果保存到SQLite数据库，并包含扫描时间
func saveToDB(taskID string, vulns []scan_rule.Vulnerability) error {
	db, err := initDB()
	if err != nil {
		return err
	}
	defer db.Close()

	// 移除 taskID 中的破折号，确保表名安全
	safeTaskID := strings.ReplaceAll(taskID, "-", "")

	// 动态创建表，表名使用安全的 taskID
	tableName := fmt.Sprintf("task_%s", safeTaskID)
	createTableSQL := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_path TEXT,
		func_name TEXT,
		line INTEGER,
		message TEXT,
		severity TEXT,
		cwe TEXT,
		scan_time DATETIME DEFAULT CURRENT_TIMESTAMP
	);`, tableName)

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return err
	}

	// 插入漏洞数据
	insertSQL := fmt.Sprintf(`INSERT INTO %s (file_path, func_name, line, message, severity, cwe) VALUES (?, ?, ?, ?, ?, ?);`, tableName)

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, vuln := range vulns {
		_, err := stmt.Exec(vuln.FilePath, vuln.FuncName, vuln.Line, vuln.Message, vuln.Severity, vuln.CWE)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

// GetProgress 查询扫描进度
func GetProgress(c *gin.Context) {
	taskID := c.Param("taskID")
	scanMutex.Lock()
	p, ok := progress[taskID]
	t, totalOk := totalFiles[taskID]
	s, statusOk := status[taskID]
	scanMutex.Unlock()
	if !ok || !totalOk || !statusOk {
		c.JSON(http.StatusNotFound, gin.H{
			"status":  0,
			"message": "任务未找到",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     1,
		"taskID":     taskID,
		"scanned":    p,
		"total":      t,
		"taskStatus": s, // 修改这里，避免重复 "status" 键
	})
}

// GetResult 获取扫描结果
func GetResult(c *gin.Context) {
	taskID := c.Param("taskID")

	db, err := initDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  0,
			"message": "无法连接数据库",
		})
		return
	}
	defer db.Close()

	// 查询结果，动态表名
	safeTaskID := strings.ReplaceAll(taskID, "-", "")
	tableName := fmt.Sprintf("task_%s", safeTaskID)
	query := fmt.Sprintf("SELECT file_path, func_name, line, message, severity, cwe, scan_time FROM %s", tableName)

	rows, err := db.Query(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  0,
			"message": "无法查询数据库或任务未完成",
		})
		return
	}
	defer rows.Close()

	var results []scan_rule.Vulnerability
	for rows.Next() {
		var vuln scan_rule.Vulnerability
		var scanTime string
		err := rows.Scan(&vuln.FilePath, &vuln.FuncName, &vuln.Line, &vuln.Message, &vuln.Severity, &vuln.CWE, &scanTime)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"status":  0,
				"message": "数据库结果解析失败",
			})
			return
		}
		results = append(results, vuln)
	}

	if len(results) == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"status":  0,
			"message": "任务未找到或没有扫描结果",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": 1,
		"taskID": taskID,
		"result": results,
	})
}

func GetAllTasks(c *gin.Context) {
	scanMutex.Lock()
	defer scanMutex.Unlock()

	var tasks []Task
	dbTaskIDs := make(map[string]bool) // 存储数据库中已存在的 taskID

	// 1. 查询数据库中已完成或错误的任务
	db, err := initDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  0,
			"message": "无法连接数据库",
		})
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT task_id, status, start_time, end_time FROM tasks WHERE status = 'completed' OR status = 'error'")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  0,
			"message": "无法查询数据库",
		})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var task Task
		err := rows.Scan(&task.TaskID, &task.Status, &task.StartTime, &task.EndTime)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"status":  0,
				"message": "数据库结果解析失败",
			})
			return
		}
		tasks = append(tasks, task)
		dbTaskIDs[task.TaskID] = true // 记录已在数据库中的 taskID
	}

	// 2. 获取内存中的任务，并排除已在数据库中的任务
	for taskID, _ := range progress {
		if _, exists := dbTaskIDs[taskID]; exists {
			continue // 如果任务ID已在数据库中，则跳过
		}
		taskStatus, ok := status[taskID]
		if !ok {
			taskStatus = "未知状态"
		}

		task := Task{
			TaskID:    taskID,
			Status:    taskStatus,
			StartTime: time.Time{}, // 如果需要，可以添加内存中任务的开始时间
		}
		tasks = append(tasks, task)
	}

	// 3. 返回所有任务信息
	c.JSON(http.StatusOK, gin.H{
		"status": 1,
		"tasks":  tasks,
	})
}

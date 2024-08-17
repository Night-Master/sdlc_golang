帮我根据如下的vue和golang gin示例，写个展示uploads里的图片并且下载的前端界面，界面要和示例界面风格保持一致，美观，简约，耐看，高级
文件上传组件:
<template>
  <div class="file-upload-page">
    <div class="header">
      <h1>文件上传</h1>
    </div>
    <div class="content">
      <div class="upload-form-container" @dragover.prevent @drop.prevent="handleDrop">
        <div class="upload-form" @click="triggerFileInput">
          <label for="file-input" class="file-input-label">
            <span v-if="!file">点击或拖拽图片文件到这里</span>
            <span v-else>{{ file.name }}</span>
          </label>
          <input id="file-input" type="file" @change="handleFileChange" class="file-input" />
        </div>
        <button @click="uploadFile" class="button">上传图片文件</button>
        <div class="upload-status" v-if="uploadStatus">
          <p>{{ uploadStatus }}</p>
        </div>
        <div class="file-path" v-if="filePath">
          <p>图片文件路径: {{ filePath }}</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import request from '@/utils/request';

const file = ref(null);
const uploadStatus = ref('');
const filePath = ref('');

const handleFileChange = (event) => {
  file.value = event.target.files[0];
};

const handleDrop = (event) => {
  file.value = event.dataTransfer.files[0];
};

const triggerFileInput = () => {
  document.getElementById('file-input').click();
};

const uploadFile = async () => {
  if (!file.value) {
    uploadStatus.value = '请选择一个文件';
    return;
  }

  const formData = new FormData();
  formData.append('file', file.value);

  try {
    const response = await request({
      url: '/upload_file_safe',
      method: 'post',
      data: formData,
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    });

    if (response.status === 1) {
      uploadStatus.value = '文件上传成功';
      filePath.value = response.filePath;
    } else {
      uploadStatus.value = response.message;
    }
  } catch (error) {
    uploadStatus.value = '上传失败，请重试';
  }
};
</script>

<style scoped>
.file-upload-page {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 40px;
  font-family: 'Helvetica Neue', Arial, sans-serif;
  background-color: #f0f2f5;
  min-height: 100vh;
}

.header {
  text-align: center;
  margin-bottom: 40px;
  color: #333;
  font-size: 24px;
}

.content {
  width: 100%;
  max-width: 600px;
}

.upload-form-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  background-color: #fff;
  padding: 40px;
  border-radius: 10px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
  transition: box-shadow 0.3s;
  border: 2px dashed #ccc;
  cursor: pointer;
}

.upload-form-container:hover {
  box-shadow: 0 6px 16px rgba(0, 0, 0, 0.1);
  border-color: #007BFF;
}

.upload-form {
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 100%;
  margin-bottom: 20px;
}

.file-input-label {
  padding: 20px;
  border: none;
  border-radius: 6px;
  background: #f9f9f9;
  color: #333;
  font-size: 16px;
  cursor: pointer;
  transition: background-color 0.3s, color 0.3s;
  width: 100%;
  text-align: center;
}

.file-input-label:hover {
  background-color: #e9e9e9;
}

.file-input {
  display: none; /* Hide the default file input */
}

.button {
  padding: 12px 24px;
  border: none;
  border-radius: 6px;
  background: linear-gradient(135deg, #007BFF, #0056b3);
  color: #fff;
  font-size: 16px;
  cursor: pointer;
  transition: transform 0.3s, box-shadow 0.3s;
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}

.button:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 12px rgba(0, 0, 0, 0.2);
}

.button:active {
  transform: translateY(1px);
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.upload-status, .file-path {
  margin-top: 20px;
  text-align: center;
  color: #555;
  font-size: 16px;
}
</style>
前端request.js：
import axios from 'axios';

const service = axios.create({
  baseURL: 'http://127.0.0.1:2333',
  // baseURL: 'http://123.249.114.216:2333',
  timeout: 5000
});

// 请求拦截器
service.interceptors.request.use(
  config => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers['Authorization'] = token;
    }
    return config;
  },
  error => {
    return Promise.reject(error);
  }
);

// 响应拦截器
service.interceptors.response.use(
  response => {
    if (response.data.token) {
      localStorage.setItem('token', response.data.token);
    }
    if (response.data.username) {
      localStorage.setItem('username', response.data.username);
    }
    return response.data;
  },
  error => {
    if (error.response && error.response.status === 200 && error.response.data.status === 0) {
      // 处理未登录的情况
      console.error(error.response.data.message);
      // 你可以在这里添加更多的处理逻辑，例如跳转到登录页面
    }
    return Promise.reject(error);
  }
);

export default service;

后端：
func UploadFile(c *gin.Context) {
	// 获取上传的文件
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "文件获取失败: " + err.Error()})
		return
	}

	// 保存文件到本地
	filename := filepath.Base(file.Filename)
	filePath := "./uploads/" + filename
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "文件保存失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": 1, "message": "文件上传成功", "filePath": filePath})
}
func UploadFile_safe(c *gin.Context) {
	// 获取上传的文件
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "文件获取失败: " + err.Error()})
		return
	}

	// 检查文件类型是否为图片
	allowedExtensions := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".bmp":  true,
		".webp": true,
		".tiff": true,
		".svg":  true,
	}

	ext := strings.ToLower(filepath.Ext(file.Filename))
	if !allowedExtensions[ext] {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "不允许的文件类型: " + ext})
		return
	}

	// 保存文件到本地
	filename := filepath.Base(file.Filename)
	filePath := "./uploads/" + filename
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "文件保存失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": 1, "message": "文件上传成功", "filePath": filePath})
}
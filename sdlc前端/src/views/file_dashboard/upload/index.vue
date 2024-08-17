<template>
  <div class="homeBox"> 
    <div class="_title_t">{{ title }}</div>
    <div class="tips" v-if="currentRoute.meta.desc">
      {{ currentRoute.meta.desc }}
    </div>
    <div class="list">
      <div class="item">
        <div class="_top">
          <ElSelect v-model="value" placeholder="" style="width: 140px">
            <ElOption
              v-for="item in options"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </ElSelect>
          <ElButton type="primary" style="float: right" @click="run1()"> Run </ElButton>
        </div>
        <div class="edit-container h-60vh" v-if="value === 0">
          <pre><code >{{ content }} </code></pre>
        </div>
        <div class="view-container h-60vh" v-else>
          <PreviewComponent :initialUsername="username" :initialPassword="password" />
        </div>
      </div>
      <div class="item">
        <div class="_top">
          <ElSelect v-model="value2" placeholder="" style="width: 140px">
            <ElOption
              v-for="item in options2"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </ElSelect>
          <ElButton type="primary" style="float: right" @click="run2()"> Run </ElButton>
        </div>
        <div class="edit-container h-60vh" v-if="value2 === 0">
          <pre><code >{{ content2 }} </code></pre>
        </div>
        <div class="view-container h-60vh" v-else>
          <PreviewComponentII :initialUsername="username2" :initialPassword="password2"/>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch } from 'vue';
import { ElSelect, ElOption, ElButton } from 'element-plus';
import PreviewComponent from './components/PreviewComponent/index.vue';
import PreviewComponentII from './components/PreviewComponent2/index.vue';
import { useRouter } from 'vue-router'
const { currentRoute } = useRouter()
const title = ref(currentRoute.value.meta.title)
watch(
  () => currentRoute.value.meta.title,
  (newVal, oldVal) => {
    title.value = newVal
  }
)
const value = ref(0);
const options = ref([
  { value: 0, label: '漏洞代码' },
  { value: 1, label: '应用界面' }
]);
const value2 = ref(0);
const options2 = ref([
  { value: 0, label: '安全代码' },
  { value: 1, label: '应用界面' }
]);
const content = ref(`
// 未对文件路径和文件类型进行检查
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
`);
const content2 = ref(`
// 对上传的文件进行上传路径和文件类型进行检查
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

	// 生成安全的文件名
	filename := filepath.Base(file.Filename)
	filename = strings.Replace(filename, "..", "", -1) // 移除所有 ".."
	filename = strings.Replace(filename, "/", "", -1)  // 移除所有 "/"
	filename = strings.Replace(filename, "\\", "", -1) // 移除所有 "\"

	// 确保文件保存路径在预期的目录下
	filePath := filepath.Join("./uploads", filename)

	// 保存文件到本地
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "文件保存失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": 1, "message": "文件上传成功", "filePath": filePath})
}
`);
let username = ref('admin');
let password = ref('');
let username2 = ref('admin');
let password2 = ref('');

const run1 = () => {
   username.value = `admin' and '1'='1' --`;
   password.value = '12';
   value.value = 1;
};

const run2 = () => {
  username2.value = `admin' and '1'='1' --`;
  password2.value = '12';
  value2.value = 1;
};

onMounted(() => {
  console.log('mounted');
});
</script>

<style scoped lang="less">
.homeBox {
  display: flex;
  flex-direction: column;
  height: 100vh;
  padding: 20px;
  box-sizing: border-box;
}
.list {
  display: flex;
  flex: 1;
  .item {
    width: 50%;
    display: flex;
    flex-direction: column;
    .edit-container, .view-container {
      flex: 1;
      margin: 10px;
    }
  }
}
._top {
  margin: 20px;
}
.tips {
  margin: 20px 10px;
  padding: 20px;
  background-color: #fff;
  border-radius: 10px;
  box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
  line-height: 1.6;
  color: #555;
  cursor: pointer;
  transition: background-color 0.3s, color 0.3s;
}
.tips:hover {
  background-color: #e9ecef;
}
pre {
  background-color: #fff;
  color: #333;
  padding: 20px;
  border-radius: 10px;
  overflow: auto;
  flex: 1;
  height: 100%;
  width: 100%;
  box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
}
</style>
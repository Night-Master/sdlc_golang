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
          <ElButton type="danger" style="float: right; margin-right: 10px" @click="clearComments()"> Clear Comments </ElButton>
        </div>
        <div class="edit-container h-60vh" v-if="value === 0">
          <pre><code >{{ content }} </code></pre>
        </div>
        <div class="view-container h-60vh" v-else>
          <PreviewComponent  :initialContent="initialContent" />
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
          <ElButton type="danger" style="float: right; margin-right: 10px" @click="clearComments()"> Clear Comments </ElButton>
        </div>
        <div class="edit-container h-60vh" v-if="value2 === 0">
          <pre><code >{{ content2 }} </code></pre>
        </div>
        <div class="view-container h-60vh" v-else>
          <PreviewComponentII :initialContent="initialContent2"/>
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
import request from '@/utils/request';

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
// 未对接收上来的Content字段进行转义处理
func Create_comments(c *gin.Context) {
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer db.Close()

	type CommentRequest struct {
		Content string \`json:"content" binding:"required"\`
	}

	var commentReq CommentRequest
	if err := c.ShouldBindJSON(&commentReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid request"})
		return
	}

	// 从上下文中获取 username
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"status": 0, "message": "Unauthorized"})
		return
	}

	// 确保 username 是 string 类型
	usernameStr, ok := username.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}

	_, err = db.Exec("INSERT INTO comments (username, content) VALUES (?, ?)", usernameStr, commentReq.Content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": 1, "message": "Comment added successfully"})
}
`);
const content2 = ref(`
// 对接收上来的Content字段进行HTMLEscapeString转义处理
func Create_comments_safe(c *gin.Context) {
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer db.Close()

	type CommentRequest struct {
		Content string \`json:"content" binding:"required"\`
	}

	var commentReq CommentRequest
	if err := c.ShouldBindJSON(&commentReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid request"})
		return
	}

	// 从上下文中获取 username
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"status": 0, "message": "Unauthorized"})
		return
	}

	// 确保 username 是 string 类型
	usernameStr, ok := username.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}

	// 转义用户输入的内容以防止XSS攻击
	escapedContent := html.EscapeString(commentReq.Content)

	_, err = db.Exec("INSERT INTO comments (username, content) VALUES (?, ?)", usernameStr, escapedContent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": 1, "message": "Comment added successfully"})
}
`);

const initialContent = ref('');
const initialContent2 = ref('');
const run1 = () => {
   initialContent.value = `<svg onmouseover="alert('你被xss攻击了')"/>`;
   value.value = 1;
};

const run2 = () => {
  initialContent2.value =`<svg onmouseover="alert('你被xss攻击了')"/>`;
  value2.value = 1;
};

const clearComments = async () => {
  try {
    const response = await request({
      url: '/clear_comments',
      method: 'post'
    });
    if (response.status === 1) {
      alert(response.message);
      location.reload(); // 刷新页面
    } else {
      alert(response.message);
    }
  } catch (error) {
    alert('An error occurred');
  }
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
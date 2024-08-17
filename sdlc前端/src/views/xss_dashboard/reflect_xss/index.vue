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
          <pre><code>{{ content }}</code></pre>
        </div>
        <div class="view-container h-60vh" v-else>
          <PreviewComponent :initialSearchQuery="initialSearchQuery" />
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
          <pre><code>{{ content2 }}</code></pre>
        </div>
        <div class="view-container h-60vh" v-else>
          <PreviewComponentII :initialSearchQuery="initialSearchQuery2" />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted ,watch} from 'vue';
import { ElSelect, ElOption, ElButton } from 'element-plus';
import PreviewComponent from './components/PreviewComponent/index.vue';
import PreviewComponentII from './components/PreviewComponent2/index.vue';
import { useRouter } from 'vue-router'
const { currentRoute } = useRouter()
console.log(currentRoute,3333)
const title = ref(currentRoute.value.meta.title)
// 监听录音变化
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
//未对接受的参数进行处理
func ReflectXss(c *gin.Context) {
	type XssRequest struct {
		Input string \`json:"input" binding:"required"\`
	}

	var xssReq XssRequest
	if err := c.ShouldBindJSON(&xssReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid request"})
		return
	}

	input := xssReq.Input
	c.JSON(http.StatusOK, gin.H{"status": 1, "message": input})
}

`);
const content2 = ref(`
// 对接受的参数使用 html.EscapeString转义
func ReflectXssSafe(c *gin.Context) {
	type XssRequest struct {
		Input string \`json:"input" binding:"required"\`
	}

	var xssReq XssRequest
	if err := c.ShouldBindJSON(&xssReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid request"})
		return
	}

	input := html.EscapeString(xssReq.Input)
	c.JSON(http.StatusOK, gin.H{"status": 1, "message": input})
}
`);
let username = ref('admin');
let password = ref('');
const initialSearchQuery = ref("");
const initialSearchQuery2 = ref("");
const run1 = () => {
  username.value = `admin' and '1'='1' --`;
  password.value = '12';
  initialSearchQuery.value = `<svg onmouseover="alert('你被xss攻击了')"/>`
  value.value = 1;
};

const run2 = () => {
  initialSearchQuery2.value = `<svg onmouseover="alert('你被xss攻击了')"/>`
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
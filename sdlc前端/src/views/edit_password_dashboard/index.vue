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
import { ElSelect, ElOption, ElButton,ElMessageBox } from 'element-plus';
// import { ElSelect, ElOption, ElButton, ElMessageBox } from 'element-plus';
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
//如果没有使用https保护，且敏感信息不使用任何加密，则构成明文传输漏洞
func ChangePassword_safe(c *gin.Context) {
	type ChangePasswordRequest struct {
		CurrentPassword []byte \`json:"currentPassword" binding:"required"\`
		NewPassword     []byte \`json:"newPassword" binding:"required"\`
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
`);
const content2 = ref(`
//服务端先生成一对rsa公私钥，把公钥发给前端加密，后端使用私钥解密
func ChangePassword_plaintext(c *gin.Context) {
	type ChangePasswordRequest struct {
		CurrentPassword string \`json:"currentPassword" binding:"required"\`
		NewPassword     string \`json:"newPassword" binding:"required"\`
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
`);
let username = ref('admin');
let password = ref('');
let username2 = ref('admin');
let password2 = ref('');
const showReminder = () => {
  ElMessageBox.alert('burp抓包查看密码是否为明文', '关于如何利用', {
    confirmButtonText: '确定',
    type: 'warning',
    dangerouslyUseHTMLString: true,
    center: true,
    customClass: 'custom-message-box'
  });
  
};
const run1 = () => {

   value.value = 1;
   showReminder();
};

const run2 = () => {
  value2.value = 1;
  showReminder();
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
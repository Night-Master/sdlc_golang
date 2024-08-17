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
// 在获取用户信息时未检测当前用户名是否和token中的用户名一致，导致每个用户都可以查看数据库中所有人的用户信息，发生越权
func Get_profile(c *gin.Context) {
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer db.Close()

	type ProfileRequest struct {
		Username string \`json:"username" binding:"required"\`
	}

	var profileReq ProfileRequest
	if err := c.ShouldBindJSON(&profileReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid request"})
		return
	}

	rows, err := db.Query("SELECT id, username, email, signature, avatar, birthdate, balance FROM users WHERE username = ?", profileReq.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer rows.Close()

	var user struct {
		ID        int     \`json:"id"\`
		Username  string  \`json:"username"\`
		Email     string  \`json:"email"\`
		Signature string  \`json:"signature"\`
		Avatar    string  \`json:"avatar"\`
		Birthdate string  \`json:"birthdate"\`
		Balance   float64 \`json:"balance"\`
	}

	if rows.Next() {
		err = rows.Scan(&user.ID, &user.Username, &user.Email, &user.Signature, &user.Avatar, &user.Birthdate, &user.Balance)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
			return
		}
	} else {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "User not found"})
		return
	}

	orderRows, err := db.Query("SELECT o.order_id, o.amount, p.name FROM orders o JOIN products p ON o.product_id = p.id WHERE o.user_id = ?", user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer orderRows.Close()

	var orders []struct {
		OrderID string  \`json:"order_id"\`
		Amount  float64 \`json:"amount"\`
		Name    string  \`json:"name"\`
	}

	for orderRows.Next() {
		var order struct {
			OrderID string  \`json:"order_id"\`
			Amount  float64 \`json:"amount"\`
			Name    string  \`json:"name"\`
		}
		err = orderRows.Scan(&order.OrderID, &order.Amount, &order.Name)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
			return
		}
		orders = append(orders, order)
	}

	c.JSON(http.StatusOK, gin.H{"status": 1, "message": "Profile fetched successfully", "data": gin.H{"user": user, "orders": orders}})
}
`);
const content2 = ref(`
// 在获取用户信息时检测当前用户名是否和token中的用户名一致，如果不一致则提示越权
func Get_profile_safe(c *gin.Context) {
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer db.Close()

	type ProfileRequest struct {
		Username string \`json:"username" binding:"required"\`
	}

	var profileReq ProfileRequest
	if err := c.ShouldBindJSON(&profileReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 0, "message": "Invalid request"})
		return
	}

	// 从上下文中获取 username
	tokenUsername, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "错误的登录凭证"})
		return
	}

	// 校验 token 中的用户名和请求中的用户名是否一致
	if tokenUsername != profileReq.Username {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "您只能查看自己的账号信息"})
		return
	}

	rows, err := db.Query("SELECT id, username, email, signature, avatar, birthdate, balance FROM users WHERE username = ?", profileReq.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer rows.Close()

	var user struct {
		ID        int     \`json:"id"\`
		Username  string  \`json:"username"\`
		Email     string  \`json:"email"\`
		Signature string  \`json:"signature"\`
		Avatar    string  \`json:"avatar"\`
		Birthdate string  \`json:"birthdate"\`
		Balance   float64 \`json:"balance"\`
	}

	if rows.Next() {
		err = rows.Scan(&user.ID, &user.Username, &user.Email, &user.Signature, &user.Avatar, &user.Birthdate, &user.Balance)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
			return
		}
	} else {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "User not found"})
		return
	}

	orderRows, err := db.Query("SELECT o.order_id, o.amount, p.name FROM orders o JOIN products p ON o.product_id = p.id WHERE o.user_id = ?", user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer orderRows.Close()

	var orders []struct {
		OrderID string  \`json:"order_id"\`
		Amount  float64 \`json:"amount"\`
		Name    string  \`json:"name"\`
	}

	for orderRows.Next() {
		var order struct {
			OrderID string  \`json:"order_id"\`
			Amount  float64 \`json:"amount"\`
			Name    string  \`json:"name"\`
		}
		err = orderRows.Scan(&order.OrderID, &order.Amount, &order.Name)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": 0, "message": "Internal server error"})
			return
		}
		orders = append(orders, order)
	}

	c.JSON(http.StatusOK, gin.H{"status": 1, "message": "Profile fetched successfully", "data": gin.H{"user": user, "orders": orders}})
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
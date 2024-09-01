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
//对用户输入的购买数量不进行校验，导致购买负数商品，导致余额反而增加
func PurchaseProduct(c *gin.Context) {
	var req struct {
		ProductID int \`json:"productId"\`
		Quantity  int \`json:"quantity"\`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Invalid request"})
		return
	}

	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer db.Close()

	// 从上下文中获取 username
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Unauthorized"})
		return
	}

	// 确保 username 是 string 类型
	usernameStr, ok := username.(string)
	if !ok {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Internal server error"})
		return
	}

	// 开始事务
	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Internal server error"})
		return
	}

	// 获取用户ID
	var userID int
	err = tx.QueryRow("SELECT id FROM users WHERE username = ?", usernameStr).Scan(&userID)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "User not found"})
		return
	}

	// 获取商品价格
	var productPrice float64
	err = tx.QueryRow("SELECT price FROM products WHERE id = ?", req.ProductID).Scan(&productPrice)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Product not found"})
		return
	}

	// 计算总金额
	totalAmount := productPrice * float64(req.Quantity)

	// 检查用户余额是否足够
	var userBalance float64
	err = tx.QueryRow("SELECT balance FROM users WHERE id = ?", userID).Scan(&userBalance)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "User not found"})
		return
	}
	if userBalance < totalAmount {
		tx.Rollback()
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Insufficient balance", "balance": userBalance})
		return
	}

	// 更新用户余额
	_, err = tx.Exec("UPDATE users SET balance = balance - ? WHERE id = ?", totalAmount, userID)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Failed to update user balance"})
		return
	}

	// 插入订单记录
	orderID := generateOrderID()
	_, err = tx.Exec("INSERT INTO orders (user_id, product_id, order_id, amount, quantity) VALUES (?, ?, ?, ?, ?)", userID, req.ProductID, orderID, totalAmount, req.Quantity)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Failed to insert order"})
		return
	}

	// 提交事务
	err = tx.Commit()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Failed to commit transaction"})
		return
	}

	// 获取更新后的用户余额
	err = db.QueryRow("SELECT balance FROM users WHERE id = ?", userID).Scan(&userBalance)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 1, "message": fmt.Sprintf("Successfully purchased %d of product ID %d", req.Quantity, req.ProductID), "balance": userBalance})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": 1, "message": fmt.Sprintf("Successfully purchased %d of product ID %d", req.Quantity, req.ProductID), "balance": userBalance})
}
`);
const content2 = ref(`
//对用户输入的购买数量不进行校验，若购买数量小于0，则提示错误
func PurchaseProduct_safe(c *gin.Context) {
	var req struct {
		ProductID int \`json:"productId"\`
		Quantity  int \`json:"quantity"\`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Invalid request"})
		return
	}

	// 检查数量是否大于零
	if req.Quantity <= 0 {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "购买数量必须大于0"})
		return
	}

	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Internal server error"})
		return
	}
	defer db.Close()

	// 从上下文中获取 username
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Unauthorized"})
		return
	}

	// 确保 username 是 string 类型
	usernameStr, ok := username.(string)
	if !ok {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Internal server error"})
		return
	}

	// 开始事务
	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Internal server error"})
		return
	}

	// 获取用户ID
	var userID int
	err = tx.QueryRow("SELECT id FROM users WHERE username = ?", usernameStr).Scan(&userID)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "User not found"})
		return
	}

	// 获取商品价格
	var productPrice float64
	err = tx.QueryRow("SELECT price FROM products WHERE id = ?", req.ProductID).Scan(&productPrice)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Product not found"})
		return
	}

	// 计算总金额
	totalAmount := productPrice * float64(req.Quantity)

	// 检查用户余额是否足够
	var userBalance float64
	err = tx.QueryRow("SELECT balance FROM users WHERE id = ?", userID).Scan(&userBalance)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "User not found"})
		return
	}
	if userBalance < totalAmount {
		tx.Rollback()
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Insufficient balance", "balance": userBalance})
		return
	}

	// 更新用户余额
	_, err = tx.Exec("UPDATE users SET balance = balance - ? WHERE id = ?", totalAmount, userID)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Failed to update user balance"})
		return
	}

	// 插入订单记录
	orderID := generateOrderID()
	_, err = tx.Exec("INSERT INTO orders (user_id, product_id, order_id, amount, quantity) VALUES (?, ?, ?, ?, ?)", userID, req.ProductID, orderID, totalAmount, req.Quantity)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Failed to insert order"})
		return
	}

	// 提交事务
	err = tx.Commit()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 0, "message": "Failed to commit transaction"})
		return
	}

	// 获取更新后的用户余额
	err = db.QueryRow("SELECT balance FROM users WHERE id = ?", userID).Scan(&userBalance)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 1, "message": fmt.Sprintf("Successfully purchased %d of product ID %d", req.Quantity, req.ProductID), "balance": userBalance})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": 1, "message": fmt.Sprintf("Successfully purchased %d of product ID %d", req.Quantity, req.ProductID), "balance": userBalance})
}
}
`);
let username = ref('admin');
let password = ref('');
let username2 = ref('admin');
let password2 = ref('');
const showReminder = () => {
  ElMessageBox.alert('购买负数商品试试', '关于如何利用', {
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


<template>
 <div class="header-t">
  <ul>
    <li>安全编码指南</li>
    <li>Github</li>
    <li v-if="userInfo.username">{{ userInfo.username }}</li><li v-else @click="Login">登录</li>
    <li @click="goLogin">注销</li>
  </ul>
 </div>
</template>
<script setup lang="ts">
import { useRouter } from 'vue-router'
const { push } = useRouter()
import { useAppStoreWithOut } from '@/store/modules/app'
import { useCache } from '@/hooks/web/useCache'
const { wsCache } = useCache()
const appStore = useAppStoreWithOut()
const userInfo = wsCache.get(appStore.getUserInfo) || {username:''}
console.log(userInfo,33333)
const goLogin = () => {
  if(!userInfo.username) return false 
  wsCache.delete(appStore.getUserInfo)
  localStorage.setItem('token','');
  localStorage.setItem('username', '');
  push('/login')
}
const Login =()=>{
   push('/login')
}
</script>
<style lang="less" scoped>
ul{
  display: flex;
  li{
    margin:0 20px;
    color: #007bff;
    text-decoration: none;
    transition: color 0.3s;
    cursor: pointer;
  }
}
.header-t{
  width: 100%;
}
</style>
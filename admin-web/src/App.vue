/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

<template>
  <div class="app-container">
    <el-config-provider :locale="elementLocale">
      <router-view />
    </el-config-provider>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import en from 'element-plus/es/locale/lang/en'
import zhCn from 'element-plus/es/locale/lang/zh-cn'

const { locale } = useI18n()
const elementLocale = computed(() => locale.value === 'zh-CN' ? zhCn : en)
</script>

<style lang="scss">
html, body {
  margin: 0;
  padding: 0;
  height: 100%;
  font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif;
}

#app, .app-container {
  height: 100vh;
  width: 100%;
}

* {
  box-sizing: border-box;
}
</style>

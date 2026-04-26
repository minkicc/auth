/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
    const env = loadEnv(mode, process.cwd())
    return {
        base: env.VITE_BASE_URL,
        plugins: [vue()],
        resolve: {
            alias: {
                '@': resolve(__dirname, 'src')
            }
        },
        server: {
            proxy: {
                '/admin-api': 'http://localhost:8081',
            }
        },
        css: {
            preprocessorOptions: {
                scss: {
                    silenceDeprecations: ['legacy-js-api']
                }
            }
        },
        build: {
            outDir: 'dist',
            emptyOutDir: true,
            rollupOptions: {
                output: {
                    manualChunks(id) {
                        if (!id.includes('node_modules')) {
                            return
                        }

                        if (id.includes('@element-plus/icons-vue')) {
                            return 'element-plus-icons'
                        }

                        if (id.includes('element-plus')) {
                            return 'element-plus'
                        }

                        if (
                            id.includes('/vue/') ||
                            id.includes('/@vue/') ||
                            id.includes('vue-router') ||
                            id.includes('pinia') ||
                            id.includes('vue-i18n')
                        ) {
                            return 'framework'
                        }

                        if (id.includes('axios')) {
                            return 'http'
                        }
                    }
                }
            }
        }
    }
})

/*
 * Copyright (c) 2025 Auth Contributors (https://example.com)
 * Licensed under the MIT License.
 */

package config

// 使用 -ldflags "-X 'example.com/auth/server/config.API_ROUTER_PATH=/api'" 来设置
const (
	UserCountLimit    = 0 // 用户数量限制, 0表示不限制
	API_ROUTER_PATH   = "/api"
	ADMIN_ROUTER_PATH = "/api"
)

func confirmConfig(config *Config) {

}

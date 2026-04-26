/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package config

// 使用 -ldflags "-X 'minki.cc/mkauth/server/config.API_ROUTER_PATH=/api'" 来设置
const (
	API_ROUTER_PATH   = "/api"
	ADMIN_ROUTER_PATH = "/admin-api"
	ADMIN_UI_BASE_PATH = "/admin"
)

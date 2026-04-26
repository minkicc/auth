/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

import { getStoredUserInfo, isAuthenticated } from "@/utils"


class Context {

  loading: boolean = false

  error: string = ''

  get isAuthenticated(): boolean {
    return isAuthenticated()
  }

  get username(): string {
    return getStoredUserInfo()?.username || ''
  }

  get nickname(): string {
    return getStoredUserInfo()?.nickname || ''
  }

  get displayName(): string {
    return this.nickname || this.username || getStoredUserInfo()?.user_id || ''
  }

  get userId(): string {
    return getStoredUserInfo()?.user_id || ''
  }

  get roles(): string[] {
    return getStoredUserInfo()?.roles || []
  }

  get sources(): string[] {
    return getStoredUserInfo()?.sources || []
  }

  get isGlobalAdmin(): boolean {
    const stored = getStoredUserInfo()
    return stored?.global_admin ?? (stored?.roles || []).includes('admin')
  }

  get organizationAdminIds(): string[] {
    return getStoredUserInfo()?.organization_admin_ids || []
  }

  get profileUrl(): string {
    return getStoredUserInfo()?.profile_url || ''
  }
  
  

}

export const context = new Context()

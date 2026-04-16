/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

import i18n from "@/locales"

const t = i18n.global.t
const appBaseURL = new URL(import.meta.env.VITE_BASE_URL || import.meta.env.BASE_URL || '/', location.origin)

const buildAppURL = (path: string): string => {
  return new URL(path.replace(/^\/+/, ''), appBaseURL).toString()
}

const toGoTemplate = (content: string): string => {
  return content.replace(/<%/g, "{{.").replace(/%>/g, "}}")
}

export const buildVerificationEmailTpl = (authData?: { clientId?: string; redirectUri?: string }): string => {
  const verifyURL = new URL(buildAppURL('/verify-email'))
  verifyURL.searchParams.set('token', '<%Token%>')

  if (authData?.clientId) {
    verifyURL.searchParams.set('client_id', authData.clientId)
  }
  if (authData?.redirectUri) {
    verifyURL.searchParams.set('redirect_uri', authData.redirectUri)
  }

  return toGoTemplate(
    t("email.verificationEmailTpl").replace(/<%VerifyURL%>/g, verifyURL.toString())
  )
}

const resetURL = `${buildAppURL('/reset-password')}?token=<%Token%>`
export const passwordResetEmailTpl = toGoTemplate(
  t("email.passwordResetEmailTpl").replace(/<%ResetURL%>/g, resetURL)
)

export const loginNotificationEmailTpl = toGoTemplate(t("email.loginNotificationEmailTpl"))

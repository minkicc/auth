export type AuthBrand = {
  name: string
  kicker: string
  pageTitle: string
  homeTitle: string
  iconUrl: string
}

function envText(name: string, fallback: string): string {
  const value = (import.meta.env as Record<string, string | undefined>)[name]
  return typeof value === 'string' && value.trim() ? value.trim() : fallback
}

export const authBrand: AuthBrand = {
  name: envText('VITE_AUTH_BRAND_NAME', 'minki-auth'),
  kicker: envText('VITE_AUTH_BRAND_KICKER', 'Minki Technology'),
  pageTitle: envText('VITE_AUTH_PAGE_TITLE', 'minki-auth'),
  homeTitle: envText('VITE_AUTH_HOME_TITLE', 'minki-auth'),
  iconUrl: envText('VITE_AUTH_ICON_URL', '/minki-logo.svg'),
}

type BrandingConfig = Partial<{
  brandName: string
  brandKicker: string
  pageTitle: string
  homeTitle: string
  iconUrl: string
}>

function mergeText(current: string, next: unknown): string {
  return typeof next === 'string' && next.trim() ? next.trim() : current
}

export async function loadBrandingConfig() {
  try {
    const response = await fetch('/branding.json', { cache: 'no-store' })
    if (!response.ok) {
      return
    }
    const config = (await response.json()) as BrandingConfig
    authBrand.name = mergeText(authBrand.name, config.brandName)
    authBrand.kicker = mergeText(authBrand.kicker, config.brandKicker)
    authBrand.pageTitle = mergeText(authBrand.pageTitle, config.pageTitle)
    authBrand.homeTitle = mergeText(authBrand.homeTitle, config.homeTitle)
    authBrand.iconUrl = mergeText(authBrand.iconUrl, config.iconUrl)
  } catch {
    // Runtime branding is optional; keep bundled defaults when unavailable.
  }
}

export function applyDocumentBrand() {
  document.title = authBrand.pageTitle

  let icon = document.head.querySelector<HTMLLinkElement>('link[rel="icon"]')
  if (!icon) {
    icon = document.createElement('link')
    icon.rel = 'icon'
    document.head.appendChild(icon)
  }
  icon.href = authBrand.iconUrl
}

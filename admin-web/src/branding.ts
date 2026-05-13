export type AdminBrand = {
  name: string
  section: string
  pageTitle: string
  homeTitle: string
  iconUrl: string
}

function envText(name: string, fallback: string): string {
  const value = (import.meta.env as Record<string, string | undefined>)[name]
  return typeof value === 'string' && value.trim() ? value.trim() : fallback
}

export const adminBrand: AdminBrand = {
  name: envText('VITE_ADMIN_BRAND_NAME', 'auth'),
  section: envText('VITE_ADMIN_BRAND_SECTION', 'admin'),
  pageTitle: envText('VITE_ADMIN_PAGE_TITLE', 'auth admin'),
  homeTitle: envText('VITE_ADMIN_HOME_TITLE', 'auth admin'),
  iconUrl: envText('VITE_ADMIN_ICON_URL', '/auth-logo.svg'),
}

type BrandingConfig = Partial<{
  brandName: string
  brandSection: string
  pageTitle: string
  homeTitle: string
  iconUrl: string
}>

function mergeText(current: string, next: unknown): string {
  return typeof next === 'string' && next.trim() ? next.trim() : current
}

export async function loadBrandingConfig() {
  try {
    const response = await fetch('/admin/branding.json', { cache: 'no-store' })
    if (!response.ok) {
      return
    }
    const config = (await response.json()) as BrandingConfig
    adminBrand.name = mergeText(adminBrand.name, config.brandName)
    adminBrand.section = mergeText(adminBrand.section, config.brandSection)
    adminBrand.pageTitle = mergeText(adminBrand.pageTitle, config.pageTitle)
    adminBrand.homeTitle = mergeText(adminBrand.homeTitle, config.homeTitle)
    adminBrand.iconUrl = mergeText(adminBrand.iconUrl, config.iconUrl)
  } catch {
    // Runtime branding is optional; keep bundled defaults when unavailable.
  }
}

export function applyDocumentBrand() {
  document.title = adminBrand.pageTitle

  let icon = document.head.querySelector<HTMLLinkElement>('link[rel="icon"]')
  if (!icon) {
    icon = document.createElement('link')
    icon.rel = 'icon'
    document.head.appendChild(icon)
  }
  icon.href = adminBrand.iconUrl
}

#!/bin/sh
set -eu

json_value() {
  file="$1"
  key="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1
}

escape_sed_replacement() {
  printf '%s' "$1" | sed -e 's/[\/&]/\\&/g'
}

apply_runtime_branding() {
  html_file="$1"
  branding_file="$2"

  [ -f "$html_file" ] || return 0
  [ -f "$branding_file" ] || return 0

  page_title="$(json_value "$branding_file" pageTitle)"
  icon_url="$(json_value "$branding_file" iconUrl)"

  if [ -n "$page_title" ]; then
    escaped_title="$(escape_sed_replacement "$page_title")"
    tmp_file="${html_file}.branding.$$"
    sed "s/<title>[^<]*<\/title>/<title>$escaped_title<\/title>/g" "$html_file" > "$tmp_file"
    mv "$tmp_file" "$html_file"
  fi

  if [ -n "$icon_url" ]; then
    escaped_icon="$(escape_sed_replacement "$icon_url")"
    tmp_file="${html_file}.branding.$$"
    sed "s#<link rel=\"icon\" type=\"image/svg+xml\" href=\"[^\"]*\" />#<link rel=\"icon\" type=\"image/svg+xml\" href=\"$escaped_icon\" />#g" "$html_file" > "$tmp_file"
    mv "$tmp_file" "$html_file"
  fi
}

apply_runtime_branding "/app/web/index.html" "/app/web/branding.json"
apply_runtime_branding "/app/admin-web/index.html" "/app/admin-web/branding.json"

exec /app/auth "$@"

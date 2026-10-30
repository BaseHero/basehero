#!/usr/bin/env bash
set -euo pipefail
umask 077

root=$(cd "$(dirname "$0")/.." && pwd)
env_name=${1:-}
[[ $# == 1 && ( $env_name == dev || $env_name == production ) ]] || { echo 'usage: deploy.sh dev|production' >&2; exit 2; }
[[ ${GITHUB_ACTIONS:-} == true ]] || {
  echo 'Deploy only through GitHub Actions: production deploys on every push to main; dev deploys with gh workflow run deploy-dev.yml --ref <branch>.' >&2
  exit 2
}
[[ -n ${CLOUDFLARE_ACCOUNT_ID:-} && -n ${CLOUDFLARE_API_TOKEN:-} ]] || { echo 'Cloudflare account and token required' >&2; exit 2; }
if [[ $env_name == production ]]; then
  [[ $(git -C "$root" branch --show-current) == main && -z $(git -C "$root" status --porcelain) &&
     $(git -C "$root" rev-parse HEAD) == $(git -C "$root" rev-parse origin/main) ]] || {
    echo 'production requires clean main level with origin/main' >&2; exit 2;
  }
fi
cd "$root/server"
wrangler() { ./node_modules/.bin/wrangler "$@"; }
if [[ $env_name == dev ]]; then
  bucket=basehero-dev-files
  url=https://dev-api.basehero.com
else
  bucket=basehero-files
  url=https://api.basehero.com
fi
# The info command is read-only; create only when the bucket does not exist.
if ! wrangler r2 bucket info "$bucket" >/dev/null 2>&1; then
  wrangler r2 bucket create "$bucket" --no-update-config
fi
config_dir=${XDG_CONFIG_HOME:-$HOME/.config}/basehero
mkdir -p "$config_dir"
chmod 700 "$config_dir"
token_file="$config_dir/$env_name-operator-token"
if ! secrets=$(wrangler secret list --env "$env_name" --format json 2>/dev/null); then
  # Only an independently confirmed missing Worker permits initial secret creation.
  # A failed lookup on an existing Worker must never rotate either secret.
  lookup=$(mktemp)
  trap 'rm -f "$lookup"' EXIT
  worker=basehero-api
  [[ $env_name == dev ]] && worker=basehero-api-dev
  status=$(curl --silent --max-time 15 --output "$lookup" --write-out '%{http_code}' \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/workers/scripts/$worker" 2>/dev/null) || {
    echo 'Secret lookup failed; Worker status unknown, changing nothing' >&2
    exit 1
  }
  if [[ $status != 404 ]] || ! node -e '
    const fs=require("fs");
    try { const body=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
      process.exit(body.errors?.some(e=>e.code===10007)?0:1);
    } catch { process.exit(1); }
  ' "$lookup"; then
    echo 'Secret lookup failed; Worker status unknown, changing nothing' >&2
    exit 1
  fi
  secrets='[]'
fi
if ! printf '%s' "$secrets" | node -e '
  let s=""; process.stdin.on("data",x=>s+=x).on("end",()=>{
    try { const items=JSON.parse(s);
      process.exit(Array.isArray(items) && items.every(x=>typeof x.name==="string")?0:1);
    } catch { process.exit(1); }
  });
'; then
  echo 'Secret lookup returned invalid data; changing nothing' >&2
  exit 1
fi
has_secret() { printf '%s' "$secrets" | node -e 'let s="";process.stdin.on("data",x=>s+=x).on("end",()=>{process.exit(JSON.parse(s).some(x=>x.name===process.argv[1])?0:1)})' "$1"; }
if ! has_secret OPERATOR_TOKEN; then
  if [[ ! -f $token_file ]]; then
    openssl rand -hex 32 > "$token_file"
    chmod 600 "$token_file"
  fi
  wrangler secret put OPERATOR_TOKEN --env "$env_name" < "$token_file"
elif [[ ! -s $token_file ]]; then
  echo 'Existing operator secret has no local token; cannot recover it' >&2
  exit 1
fi
if ! has_secret PEPPER; then
  openssl rand -hex 32 | wrangler secret put PEPPER --env "$env_name"
fi
if [[ -n ${TINFOIL_API_KEY:-} ]] && ! has_secret TINFOIL_API_KEY; then
  printf '%s' "$TINFOIL_API_KEY" | wrangler secret put TINFOIL_API_KEY --env "$env_name"
  echo 'TINFOIL_API_KEY set'
elif has_secret TINFOIL_API_KEY; then
  echo 'TINFOIL_API_KEY set'
else
  echo 'TINFOIL_API_KEY not set' >&2
fi
wrangler deploy --env "$env_name"
# DoH bypasses a host resolver's cached NXDOMAIN just after a custom domain is created;
# the host resolver covers networks where DoH fails. Retry DNS propagation and worker
# startup for at most two minutes, and report the last answer.
health() { curl "$@" --fail --silent --show-error --max-time 10 -H 'BH-Protocol: 1' "$url/v1/health" 2>&1; }
deadline=$((SECONDS + 120))
last=''
while :; do
  for resolver in doh host; do
    if [[ $resolver == doh ]]; then
      response=$(health --doh-url https://cloudflare-dns.com/dns-query) || true
    else
      response=$(health) || true
    fi
    if [[ $response == '{"ok":true,"protocol":2}' ]]; then
      printf 'Health OK: %s/v1/health\n' "$url"
      [[ $resolver == doh ]] || printf 'Through the host resolver; DNS over HTTPS answered %s\n' "${last#doh: }"
      break 2
    fi
    last="$resolver: ${response:0:200}"
  done
  if (( SECONDS >= deadline )); then
    echo "Health check failed after two minutes: $url/v1/health" >&2
    printf 'Last answer, %s\n' "$last" >&2
    exit 1
  fi
  sleep 2
done

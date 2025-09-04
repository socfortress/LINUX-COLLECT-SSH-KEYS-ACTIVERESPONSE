#!/bin/sh
set -eu

ScriptName="Collect-SSH-Keys"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart="$(date +%s)"

MASK="${MASK:-1}"              
MAX_BYTES="${MAX_BYTES:-4096}"   
ONLY_FINDINGS="${ONLY_FINDINGS:-0}"

WriteLog() {
  Message="$1"; Level="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  line="[$ts][$Level] $Message"; printf '%s\n' "$line" >&2; printf '%s\n' "$line" >> "$LogPath"
}
RotateLog() { [ -f "$LogPath" ] || return 0; kb=$(du -k "$LogPath" | awk '{print $1}'); [ "$kb" -le "$LogMaxKB" ] && return 0;
  i=$((LogKeep-1)); while [ $i -ge 0 ]; do [ -f "$LogPath.$i" ] && mv -f "$LogPath.$i" "$LogPath.$((i+1))"; i=$((i-1)); done; mv -f "$LogPath" "$LogPath.1"; }

iso_now(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
escape_json(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
file_owner(){ stat -c '%U' "$1" 2>/dev/null || echo "unknown"; }
file_perms(){ stat -c '%a' "$1" 2>/dev/null || echo "-"; }
file_size(){ stat -c '%s' "$1" 2>/dev/null || wc -c <"$1" 2>/dev/null || echo 0; }
sha256_of(){ command -v sha256sum >/dev/null 2>&1 && sha256sum "$1" 2>/dev/null | awk '{print $1}' || echo ""; }

BeginNDJSON(){ TMP_AR="$(mktemp)"; }
AddRecord(){
  ts="$(iso_now)"; fpath="$1"; ftype="$2"; content="$3"; flag="$4"; dig="$5"
  owner="$(file_owner "$fpath")"; perms="$(file_perms "$fpath")"; size="$(file_size "$fpath")"
  base=$(printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"file":"%s","type":"%s","owner":"%s","perms":"%s","size":%s' \
    "$ts" "$HostName" "$ScriptName" "$(escape_json "$fpath")" "$(escape_json "$ftype")" "$(escape_json "$owner")" "$(escape_json "$perms")" "$size")
  [ -n "$flag" ] && base="$base,\"flag\":\"$(escape_json "$flag")\""
  [ -n "$dig" ] && base="$base,\"sha256\":\"$(escape_json "$dig")\""
  base="$base,\"content\":\"$(escape_json "$content")\"}"
  printf '%s\n' "$base" >> "$TMP_AR"
}
AddStatus(){ ts="$(iso_now)"; st="${1:-info}"; msg="$(escape_json "${2:-}")";
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"%s","message":"%s"}\n' "$ts" "$HostName" "$ScriptName" "$st" "$msg" >> "$TMP_AR"; }

CommitNDJSON(){
  [ -s "$TMP_AR" ] || AddStatus "no_results" "no SSH key/config files found"
  AR_DIR="$(dirname "$ARLog")"; [ -d "$AR_DIR" ] || WriteLog "Directory missing: $AR_DIR (will attempt write anyway)" WARN
  if mv -f "$TMP_AR" "$ARLog"; then WriteLog "Wrote NDJSON to $ARLog" INFO
  else WriteLog "Primary write FAILED to $ARLog" WARN
       mv -f "$TMP_AR" "$ARLog.new" 2>/dev/null || { keep="/tmp/active-responses.$$.ndjson"; cp -f "$TMP_AR" "$keep" 2>/dev/null || true; WriteLog "Saved fallback $keep" ERROR; rm -f "$TMP_AR"; exit 1; }
  fi
  for p in "$ARLog" "$ARLog.new"; do
    [ -f "$p" ] && { sz=$(wc -c < "$p" 2>/dev/null || echo 0); ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}'); head1=$(head -n1 "$p" 2>/dev/null || true);
      WriteLog "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}" INFO; }
  done
}


truncate_bytes(){  
  awk -v max="$MAX_BYTES" 'BEGIN{ORS=""; n=0} {s=$0 ORS; if (n+length(s) > max){ print substr(s,1,max-n); exit } print s; n+=length(s); }'
}
mask_authorized_keys(){ 
  awk 'BEGIN{RS="\n"; ORS="\n"} /^[[:space:]]*#/ {next}
       /^[[:space:]]*$/ {print; next}
       { type=""; comment="";
         for(i=1;i<=NF;i++){
           if ($i ~ /^ssh-(rsa|dss|ed25519|ecdsa)/ || $i ~ /^sk-(ecdsa|ssh-)/){ type=$i; if(i<NF){comment=$(i+1); for(j=i+2;j<=NF;j++) comment=comment" "$(j);} break }
         }
         if (type!=""){ print type" <redacted>"(comment!=""?" "comment:"") }
         else { print "<redacted-line>" }
       }'
}
mask_private_key(){ echo "<redacted private key>"; }
mask_config(){  
  awk '/^[[:space:]]*#/ {next}
       /StrictHostKeyChecking[[:space:]]+no/i ||
       /PasswordAuthentication[[:space:]]+yes/i ||
       /PermitRootLogin[[:space:]]+yes/i ||
       /ProxyCommand/i ||
       /ForwardAgent[[:space:]]+yes/i ||
       /Host \*/ {print}'
}

flag_authorized_keys(){
  f="$1"; reason=""
  if grep -qE '^[[:space:]]*$' "$f"; then reason="Contains empty lines"; fi
  if grep -qE '(^|[[:space:]])ssh-rsa([[:space:]]|$)' "$f"; then
    [ -n "$reason" ] && reason="$reason; " ; reason="$reason"'Contains ssh-rsa key (considered weak)'
  fi
  printf '%s\n' "$reason"
}
flag_config(){
  f="$1"; out=""
  grep -qiE 'StrictHostKeyChecking[[:space:]]+no' "$f" 2>/dev/null && out="${out}StrictHostKeyChecking=no;"
  grep -qiE 'PasswordAuthentication[[:space:]]+yes' "$f" 2>/dev/null && out="${out}PasswordAuthentication=yes;"
  grep -qiE 'PermitRootLogin[[:space:]]+yes' "$f" 2>/dev/null && out="${out}PermitRootLogin=yes;"
  grep -qiE 'ForwardAgent[[:space:]]+yes' "$f" 2>/dev/null && out="${out}ForwardAgent=yes;"
  printf '%s\n' "${out%;}"
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName (host=$HostName) ==="
BeginNDJSON
CANDS=""
ROOT_HOME="$(getent passwd root | awk -F: '{print $6}')"
[ -n "${ROOT_HOME:-}" ] && [ -d "$ROOT_HOME/.ssh" ] && CANDS="$CANDS $ROOT_HOME/.ssh"
getent passwd | awk -F: '($3 >= 1000 && $1 != "nobody"){print $6}' | while IFS= read -r home; do
  [ -d "$home/.ssh" ] && CANDS="$CANDS $home/.ssh"
done
CANDS="$CANDS /etc/ssh"

FILES="authorized_keys config ssh_config sshd_config id_rsa id_dsa id_ecdsa id_ed25519"
emitted=0

for dir in $CANDS; do
  [ -d "$dir" ] || continue
  for f in $FILES; do
    path="$dir/$f"; [ -f "$path" ] || continue

    flag=""
    case "$f" in
      authorized_keys) flag="$(flag_authorized_keys "$path")" ;;
      ssh_config|config|sshd_config) flag="$(flag_config "$path")" ;;
    esac
    content=""
    if [ "$MASK" = "1" ]; then
      case "$f" in
        authorized_keys) content="$(cat "$path" | tr -d '\r' | mask_authorized_keys | truncate_bytes)" ;;
        id_rsa|id_dsa|id_ecdsa|id_ed25519) content="$(mask_private_key)";;
        ssh_config|config|sshd_config) content="$(cat "$path" | tr -d '\r' | mask_config | truncate_bytes)";;
        *) content="$(cat "$path" | tr -d '\r' | truncate_bytes)";;
      esac
    else
      content="$(cat "$path" | tr -d '\r' | truncate_bytes)"
    fi
    if [ "$ONLY_FINDINGS" = "1" ] && [ -z "$flag" ]; then
      continue
    fi
    dig="$(sha256_of "$path")"

    AddRecord "$path" "$f" "$content" "$flag" "$dig"
    emitted=$((emitted+1))
  done
done

[ "$emitted" -gt 0 ] || AddStatus "no_results" "no matching SSH files found"

CommitNDJSON

dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : ${dur}s ==="

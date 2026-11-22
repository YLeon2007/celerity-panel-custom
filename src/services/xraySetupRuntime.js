'use strict';

// POSIX SSH login shells need an explicit Bash invocation; a shebang in an
// SSH exec string does not select the interpreter. No config bytes in argv.
const quote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
const bash = script => `/bin/bash -c ${quote(script)}`;
const CONFIG_DIR = '/usr/local/etc/xray';
const CONFIG_PATH = `${CONFIG_DIR}/config.json`;
const UNIT_PATH = '/etc/systemd/system/xray.service';

// Each phase publishes only a checked status, not raw systemctl, Xray or
// OpenSSL output (they can print paths, config data, or arguments).
const errors = new Map([
    [30, 'Не удалось получить данные xray.service из systemd.'],
    [31, 'xray.service не загружен или не использует управляемый /usr/local/etc/xray/config.json.'],
    [32, 'Не удалось определить пользователя или группу xray.service.'],
    [33, 'Не удалось настроить дополнение xray.service для группы xray; проверьте существующие drop-in файлы.'],
    [34, 'Не удалось безопасно настроить права /usr/local/etc/xray.'],
    [35, 'Не удалось безопасно записать config.json для Xray.'],
    [36, 'Не удалось подготовить файлы сертификата и ключа Xray.'],
    [37, 'Не удалось включить xray.service в systemd.'],
    [38, 'Не удалось перезапустить xray.service.'],
    [39, 'Не удалось проверить состояние xray.service через systemd.'],
    [40, 'xray.service не работает: требуется загруженная активная служба с основным процессом.'],
    [41, 'Не удалось прочитать корректные MainPID и NRestarts для xray.service.'],
    [42, 'Счётчик NRestarts xray.service изменился после запуска.'],
    [43, 'PID основного процесса xray.service изменился после запуска.'],
    [44, 'Не удалось безопасно настроить права существующего config.json для Xray.'],
    [45, 'Не удалось настроить LogsDirectory=xray; проверьте существующие drop-in файлы.'],
    [46, 'Не удалось подтвердить доступ пользователя xray.service к каталогу или существующему config.json.'],
]);

class XraySetupError extends Error {}

async function checkedExec(exec, command, fallback, options = {}) {
    let result;
    try {
        result = await exec(command, { timeoutMs: 45000, ...options });
    } catch {
        throw new XraySetupError(fallback);
    }
    if (!result.success) throw new XraySetupError(options.usePhaseCodes === false ? fallback : errors.get(result.code) || fallback);
    return result.output;
}

// Only root-owned, non-link directories that are not group/other-writable.
// The directories' parents are ordinary system administration paths.
const safeDir = `
safe_dir() {
    local meta mode
    [[ -d "$1" && ! -L "$1" ]] || return 1
    meta=$(stat -c '%u:%a' -- "$1") || return 1
    [[ "$meta" =~ ^0:([0-7]{3,4})$ ]] || return 1
    mode="\${BASH_REMATCH[1]}"
    (( (8#$mode & 0022) == 0 ))
}
`;

function prepareAccessCommand(unitContent, { exitOnly = false } = {}) {
    const dropIn = setting => quote(`# Managed by Celerity Xray setup\n[Service]\n${setting}\n`);
    return bash(`
exec 2>/dev/null
export LC_ALL=C
umask 077
${safeDir}
ctl() { timeout 4s systemctl --no-pager --no-ask-password "$@"; }
prop() { ctl show --property="$1" --value xray.service; }
ensure_drop_in() (
    local filename="$1" content="$2" effective="$3" failure="$4" paths candidate stage
    local dropdir="$unit.d" drop="$unit.d/$filename"
    paths=$(prop DropInPaths) || exit 30
    # Do not shadow a same-named drop-in from another systemd unit layer.
    local -a candidates
    read -r -a candidates <<< "$paths"
    for candidate in "\${candidates[@]}"; do
        [[ "$candidate" != */"$filename" || "$candidate" == "$drop" ]] || exit "$failure"
    done
    if [[ ! -e "$dropdir" && ! -L "$dropdir" ]]; then mkdir -m 0755 -- "$dropdir" || exit "$failure"; fi
    safe_dir "$dropdir" || exit "$failure"
    stage=$(mktemp "$dropdir/.celerity-setup.XXXXXXXX") || exit "$failure"
    trap 'rm -f -- "$stage"' EXIT
    printf '%s' "$content" > "$stage" || exit "$failure"
    if [[ -e "$drop" || -L "$drop" ]]; then
        [[ -f "$drop" && ! -L "$drop" && $(stat -c '%u:%a:%h' -- "$drop") == 0:644:1 ]] &&
            cmp -s -- "$stage" "$drop" || exit "$failure"
    else
        chmod 0644 "$stage" && ln -T -- "$stage" "$drop" || exit "$failure"
    fi
    ctl daemon-reload >/dev/null || exit 30
    # Later admin drop-ins can reset list properties. Do not overwrite them.
    if ! "$effective"; then
        if [[ "$stage" -ef "$drop" ]]; then rm -f -- "$drop" && ctl daemon-reload >/dev/null || exit 30; fi
        exit "$failure"
    fi
)

# Preserve upstream and admin units, including their drop-ins. Write a new
# unit only when systemd positively reports not-found (it may exit nonzero).
ctl daemon-reload >/dev/null || exit 30
load_rc=0
load=$(prop LoadState) || load_rc=$?
unit=${quote(UNIT_PATH)}
if [[ "$load" == not-found && "$load_rc" -le 1 ]]; then
    safe_dir "$(dirname "$unit")" || exit 31
    stage=$(mktemp "$unit.setup.XXXXXXXX") || exit 31
    trap 'rm -f -- "$stage"' EXIT
    printf '%s' ${quote(unitContent)} > "$stage" && chmod 0644 "$stage" && ln -T -- "$stage" "$unit" && rm -f -- "$stage" || exit 31
    ctl daemon-reload >/dev/null || exit 30
    load=$(prop LoadState) || exit 30
elif (( load_rc != 0 )); then
    exit 30
fi
[[ "$load" == loaded ]] || exit 31
start=$(prop ExecStart) || exit 30
case "$start" in
    '{ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${CONFIG_PATH} ; ignore_errors=no ; '*|\
    '{ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -c ${CONFIG_PATH} ; ignore_errors=no ; '*) ;;
    *) exit 31 ;;
esac
[[ "\${start#*argv\\[\\]=}" != *'argv[]='* ]] || exit 31

user=$(prop User) && group=$(prop Group) && dynamic=$(prop DynamicUser) || exit 30
[[ "$dynamic" == no ]] || exit 32
account=$(timeout 4s getent passwd "\${user:-root}") || exit 32
IFS=: read -r name _ uid primary _ <<< "$account"
[[ "$uid" =~ ^[0-9]+$ && "$primary" =~ ^[0-9]+$ ]] || exit 32
if [[ -n "$group" ]]; then
    entry=$(timeout 4s getent group "$group") || exit 32
    IFS=: read -r name _ primary _ <<< "$entry"
    [[ "$primary" =~ ^[0-9]+$ ]] || exit 32
fi

dir=${quote(CONFIG_DIR)}
safe_dir "$dir" || exit 34

if entry=$(timeout 4s getent group xray); then
    IFS=: read -r name _ gid _ <<< "$entry"
    [[ "$name" == xray && "$gid" =~ ^[0-9]+$ ]] || exit 32
    has_xray_group() {
        local groups
        groups=$(prop SupplementaryGroups) || exit 30
        [[ " $groups " == *' xray '* || " $groups " == *" $gid "* ]]
    }
    if [[ "$uid" != 0 && "$primary" != "$gid" ]] && ! has_xray_group; then
        ensure_drop_in 90-celerity-config-access.conf ${dropIn('SupplementaryGroups=xray')} has_xray_group 33 || exit "$?"
    fi
else
    [[ "$?" == 2 ]] || exit 32
    # Without xray, retain the effective primary group (never grant other access).
    if [[ "$uid" == 0 ]]; then gid=0; else gid=$primary; fi
fi

# Also protects contents if the root cc-agent later replaces config.json with
# a new inode: its historical 0644 mode is behind this private directory.
dir_meta=$(stat -c '%g:%a' -- "$dir") || exit 34
if [[ "$dir_meta" != *:750 ]]; then chmod 0750 -- "$dir" || exit 34; fi
if [[ "\${dir_meta%:*}" != "$gid" ]]; then chgrp -- "$gid" "$dir" || exit 34; fi
${exitOnly ? `
# Forward cascades can later use xray.service; leave reverse xray-bridge and
# all config bytes to the cascade deployer. The directory is root-owned and
# not writable by the service, so only adjust a root-owned, single-link file.
config=${quote(CONFIG_PATH)}
[[ ! -L "$config" ]] || exit 44
check_config=''
if [[ -e "$config" ]]; then
    check_config="$config"
    [[ -f "$config" ]] || exit 44
    meta=$(stat -c '%u:%h:%g:%a' -- "$config") || exit 44
    [[ "$meta" =~ ^0:1:([0-9]+):([0-7]{1,4})$ ]] || exit 44
    config_gid="\${BASH_REMATCH[1]}" mode="\${BASH_REMATCH[2]}"
    if [[ "$config_gid" != "$gid" ]]; then
        chmod 0600 -- "$config" && chgrp -- "$gid" "$config" && chmod 0640 -- "$config" || exit 44
    elif (( (8#$mode & 0040) == 0 || (8#$mode & 0022) != 0 )); then
        chmod 0640 -- "$config" || exit 44
    fi
fi
# Check actual host filesystem access (including ACLs/ancestor traversal)
# with the selected service IDs, without executing Xray or reading config bytes.
timeout 4s setpriv --reuid "$uid" --regid "$primary" --groups "$gid" -- /bin/bash -c \\
    '[[ -x "$1" && ( -z "$2" || -r "$2" ) ]]' bash "$dir" "$check_config" || exit 46
` : `
# The former generated unit provided this even before access logs were opted in.
# Preserve that capability without editing or taking ownership of log files.
has_logs_directory() {
    local dirs
    dirs=$(prop LogsDirectory) || exit 30
    [[ " $dirs " == *' xray '* ]]
}
if ! has_logs_directory; then
    ensure_drop_in 90-celerity-logs-directory.conf ${dropIn('LogsDirectory=xray')} has_logs_directory 45 || exit "$?"
fi
`}
printf 'XRAY_GID=%s\\n' "$gid"
`);
}

function writeConfigCommand(gid, byteLength) {
    return bash(`
exec 2>/dev/null
umask 077
${safeDir}
dir=${quote(CONFIG_DIR)}
config=${quote(CONFIG_PATH)}
safe_dir "$dir" && [[ $(stat -c '%g:%a' -- "$dir") == ${gid}:750 ]] || exit 34
[[ ! -L "$config" && ( ! -e "$config" || -f "$config" ) ]] || exit 35
stage=$(mktemp "$dir/.config.setup.XXXXXXXX") || exit 35
trap 'rm -f -- "$stage"' EXIT
cat > "$stage" && [[ $(stat -c '%s' -- "$stage") == ${byteLength} ]] || exit 35
chgrp -- ${gid} "$stage" && chmod 0640 "$stage" && mv -fT -- "$stage" "$config" || exit 35
`);
}

// Work only on the managed TLS pair; avoid following symlinks or modifying a
// different file through hard links. A freshly generated pair is staged privately.
function tlsFileHelpers(gid) {
    return `
safe_tls_file() {
    [[ ! -L "$1" && ( ! -e "$1" || ( -f "$1" && $(stat -c '%h' -- "$1") == 1 ) ) ]]
}
secure_tls_file() {
    safe_tls_file "$1" && chmod 0600 -- "$1" && chown -- 0:${gid} "$1" && chmod 0640 -- "$1"
}
`;
}

function selfSignedCommand(gid, cn) {
    return bash(`
exec >/dev/null 2>&1
umask 077
${safeDir}
${tlsFileHelpers(gid)}
dir=${quote(CONFIG_DIR)}
key="$dir/key.pem" cert="$dir/cert.pem"
safe_dir "$dir" && [[ $(stat -c '%g:%a' -- "$dir") == ${gid}:750 ]] || exit 34
safe_tls_file "$key" && safe_tls_file "$cert" || exit 36
if [[ ! -s "$key" || ! -s "$cert" ]]; then
    stage=$(mktemp -d "$dir/.tls.setup.XXXXXXXX") || exit 36
    trap 'rm -f -- "$stage/key.pem" "$stage/cert.pem"; rmdir -- "$stage"' EXIT
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \\
        -keyout "$stage/key.pem" -out "$stage/cert.pem" -subj ${quote(`/CN=${cn}`)} -days 36500 || exit 36
    secure_tls_file "$stage/key.pem" && secure_tls_file "$stage/cert.pem" && \\
        mv -fT -- "$stage/key.pem" "$key" && mv -fT -- "$stage/cert.pem" "$cert" || exit 36
else
    secure_tls_file "$key" && secure_tls_file "$cert" || exit 36
fi
`);
}

const stableWindow = `
previous=''
for i in 0 1 2 3 4 5 6; do
    sample=$(timeout 1s systemctl --no-pager --no-ask-password show \\
        -p LoadState -p ActiveState -p SubState -p MainPID -p NRestarts xray.service) || exit 39
    identity=$(printf '%s\\n' "$sample" | awk -F= '
        NF != 2 || $1 !~ /^(LoadState|ActiveState|SubState|MainPID|NRestarts)$/ || seen[$1]++ { bad=1; next }
        { value[$1]=$2 }
        END {
            if (bad || NR!=5) exit 41
            pid=value["MainPID"]; count=value["NRestarts"]
            if (pid !~ /^(0|[1-9][0-9]*)$/ || length(pid)>10 || pid+0>2147483647 ||
                count !~ /^(0|[1-9][0-9]*)$/ || length(count)>10 || count+0>4294967295) exit 41
            if (value["LoadState"]!="loaded" || value["ActiveState"]!="active" ||
                value["SubState"]!="running" || pid=="0") exit 40
            printf "%s:%s", pid, count
        }') || exit "$?"
    if [[ -n "$previous" ]]; then
        [[ "$identity" == *:"\${previous#*:}" ]] || exit 42
        [[ "$identity" == "$previous" ]] || exit 43
    fi
    previous="$identity"
    if [[ "$i" != 6 ]]; then sleep 1 || exit 39; fi
done
`;
const quiet = 'export LC_ALL=C; exec >/dev/null 2>&1';
const verifyCommand = bash(`${quiet}
${stableWindow}`);
const restartCommand = bash(`${quiet}
timeout 4s systemctl --no-pager --no-ask-password enable xray.service || exit 37
timeout 25s systemctl --no-pager --no-ask-password restart xray.service || exit 38
${stableWindow}`);

module.exports = {
    XraySetupError, CONFIG_PATH, bash, quote, checkedExec, prepareAccessCommand, writeConfigCommand,
    selfSignedCommand, tlsFileHelpers, restartCommand, verifyCommand,
};

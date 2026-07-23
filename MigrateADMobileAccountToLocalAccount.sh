#!/bin/bash
# Converts an Active Directory mobile account into a local account that matches a fresh local account.
# EnrollmentUser = the account to convert. GrantAdmin=true (optional, default off) adds it to the admin group.
# VerifyOnly=true (optional) only logs the differences from a fresh account and changes nothing.
# UseDialog=true (optional) shows progress in swiftDialog if /usr/local/bin/dialog is installed.
# Exit codes: 0 done (or nothing to do), 1 stopped, 2 differences from a fresh account remain (or VerifyOnly found some).
# See the README for usage and credits.
Version=2.0

LOG_FILE="/var/log/mobile_to_local_migration.log"

# Levels: INFO = what happened, WARN = a problem the run continues past, ERROR = the run stopped.
log_message() {
    printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" | tee -a "$LOG_FILE"
}

# --- swiftDialog (optional) ---------------------------------------------------------------
# If /usr/local/bin/dialog is installed and UseDialog=true, shows a progress dialog.
# If not, every dialog_* function is a silent no-op and the script runs headless.
DIALOG_BIN="/usr/local/bin/dialog"
DIALOG_CMD_FILE=""
DIALOG_PID=""
DIALOG_ENABLED=0

dialog_init() {
    is_enabled "${UseDialog:-false}" || return 0
    [[ -x "$DIALOG_BIN" ]] || { log_message "INFO" "UseDialog=true but swiftDialog not found at $DIALOG_BIN; running headless"; return 0; }
    # No GUI at the login window.
    local console_user; console_user=$(stat -f%Su /dev/console 2>/dev/null)
    [[ "$console_user" != "loginwindow" && -n "$console_user" ]] || { log_message "INFO" "No console user; running headless"; return 0; }
    DIALOG_CMD_FILE=$(mktemp -t adtl_dialog)
    chmod 644 "$DIALOG_CMD_FILE"
    DIALOG_ENABLED=1
}

dialog_start() { # $1 = title, $2 = message, rest = step names
    [[ $DIALOG_ENABLED -eq 1 ]] || return 0
    local title="$1" message="$2"; shift 2
    local steps=("$@") list_args=() i=0
    for step in "$@"; do
        list_args+=( --listitem "$step" )
    done
    : > "$DIALOG_CMD_FILE"
    local console_user console_uid
    console_user=$(stat -f%Su /dev/console)
    console_uid=$(id -u "$console_user")
    launchctl asuser "$console_uid" sudo -u "$console_user" "$DIALOG_BIN" \
        --title "$title" \
        --message "$message" \
        --icon "SF=person.crop.circle.badge.checkmark" \
        --progress "${#steps[@]}" \
        --progresstext "Starting..." \
        --button1text "Working..." --button1disabled \
        --commandfile "$DIALOG_CMD_FILE" \
        --moveable --ontop --hidedefaultkeyboardaction \
        "${list_args[@]}" &>/dev/null &
    DIALOG_PID=$!
    # Give swiftDialog time to open the command file before we write to it.
    sleep 1
}

dialog_step() { # $1 = index (0-based), $2 = status (wait/success/error/fail), $3 = text
    [[ $DIALOG_ENABLED -eq 1 ]] || return 0
    echo "listitem: index: $1, status: $2, statustext: $(dialog_sanitize "$3")" >> "$DIALOG_CMD_FILE"
}

dialog_progress() { # $1 = completed count, $2 = text
    [[ $DIALOG_ENABLED -eq 1 ]] || return 0
    echo "progress: $1" >> "$DIALOG_CMD_FILE"
    echo "progresstext: $(dialog_sanitize "$2")" >> "$DIALOG_CMD_FILE"
}

dialog_finish() { # $1 = title, $2 = message, enables the Close button
    [[ $DIALOG_ENABLED -eq 1 ]] || return 0
    echo "title: $(dialog_sanitize "$1")" >> "$DIALOG_CMD_FILE"
    echo "message: $(dialog_sanitize "$2")" >> "$DIALOG_CMD_FILE"
    echo "button1text: Close" >> "$DIALOG_CMD_FILE"
    echo "button1: enable" >> "$DIALOG_CMD_FILE"
}

dialog_close() {
    [[ $DIALOG_ENABLED -eq 1 ]] || return 0
    echo "quit:" >> "$DIALOG_CMD_FILE"
    sleep 1
    rm -f "$DIALOG_CMD_FILE"
    DIALOG_ENABLED=0
}

# swiftDialog splits command-file lines on commas and colons. Keep text on one line and strip those.
dialog_sanitize() {
    local text="$1"
    text="${text//$'\r'/ }"
    text="${text//$'\n'/ }"
    text="${text//,/;}"
    printf '%s' "${text:0:140}"
}

# BEGIN helpers (pure text handling, unit tested in tests/test_filters.sh)

# Attributes an AD mobile account adds and a local account never has (lower case, namespace stripped).
# AppleMetaRecordName holds the AD distinguished name on a mobile account; a fresh one has none.
# Deliberately NOT listed: AltSecurityIdentities (value-filtered), accountPolicyData (pwpolicy),
# _writers_LinkedIdentity (Apple Account), AppleMetaNodeLocation. A fresh account can have these.
AD_ATTRS=(
    cachedgroups smbprimarygroupsid originalauthenticationauthority originalnodename smbsid
    smbscriptpath smbpasswordlastset smbgrouprid mcxsettings mcxflags accounttype copytimestamp
    account_instance cached_auth_policy cached_groups original_realname original_shell
    preserved_attributes email_address primaryntdomain firstname lastname jobtitle company
    department emailaddress applemetarecordname originalnfshomedirectory
)

# The shell and home folder mode of a fresh local account (macOS 27, checked against a new account).
# Accounts made on older macOS have a 755 home folder, which is stock as well and left alone.
FRESH_SHELL=/bin/zsh
FRESH_HOME_MODE=750

is_stock_home_mode() {
    [[ "$1" == "$FRESH_HOME_MODE" || "$1" == "755" ]]
}

# A fresh account's ~/.CFUserTextEncoding mode. A mobile account's is 400.
FRESH_TEXT_ENCODING_MODE=600

# Keys that let the user change their own picture, input sources and unlock options. A fresh account
# has _writers_<name> for each; a mobile account doesn't. They are permissions only, no data.
WRITER_ATTRS=(AvatarRepresentation inputSources unlockOptions)

# $1 = record keys (plist_keys output). Prints each WRITER_ATTRS name without a _writers_ key.
missing_writers() {
    local name
    for name in "${WRITER_ATTRS[@]}"; do
        case $'\n'"$1"$'\n' in
            *$'\n'"dsAttrTypeNative:_writers_$name"$'\n'*) ;;
            *) echo "$name" ;;
        esac
    done
}

# Prints the strings of the first array in a dscl -plist document, one per line.
attr_values_from_plist() {
    local plist="$1" count i value
    count=$(xmllint --xpath 'count(//dict/array/string)' - <<<"$plist" 2>/dev/null) || return 1
    for ((i = 1; i <= count; i++)); do
        # $(...) drops xmllint's trailing newline (newer libxml prints one, older doesn't).
        value=$(xmllint --xpath "string(//dict/array/string[$i])" - <<<"$plist")
        printf '%s\n' "$value"
    done
}

# Prints every key of a dscl -plist record document, one per line.
plist_keys() {
    local plist="$1" count i value
    count=$(xmllint --xpath 'count(//dict/key)' - <<<"$plist" 2>/dev/null) || return 1
    for ((i = 1; i <= count; i++)); do
        value=$(xmllint --xpath "string(//dict/key[$i])" - <<<"$plist")
        printf '%s\n' "$value"
    done
}

# $1 = record path (/Users/name, /Groups/staff, /Search), $2 = attribute. dscl exits 0 for a missing
# key, so an absent attribute simply prints nothing.
record_values() {
    local plist
    plist=$(dscl -plist . -read "$1" "$2" 2>/dev/null) || return 1
    attr_values_from_plist "$plist"
}

# True for an Active Directory AuthenticationAuthority entry. Never true for the entries a local
# account needs: the password hash, the FileVault token and the local KDC.
is_ad_authority_entry() {
    case "$1" in
        *ShadowHash* | *SecureToken* | *LKDC:*) return 1 ;;
        *LocalCachedUser* | *Kerberosv5* | *"Active Directory"* | ";NetLogon;"*) return 0 ;;
    esac
    return 1
}

# True for an AD Kerberos principal in AltSecurityIdentities (not X509, not the local KDC).
is_ad_alt_identity() {
    [[ "$1" == Kerberos:* && "$1" != *LKDC:* ]]
}

# True for a "user@DOMAIN" alias in RecordName.
is_domain_alias() {
    [[ "$1" == *@* && "$1" != *LKDC* ]]
}

# True for an Active Directory entry in a search path.
is_ad_search_path() {
    [[ "$1" == *"Active Directory"* ]]
}

# True if a record key (dsAttrTypeStandard:X / dsAttrTypeNative:x) is a leftover AD attribute.
is_ad_attribute_key() {
    local key="${1#dsAttrTypeStandard:}" attr
    key="${key#dsAttrTypeNative:}"
    key=$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')
    for attr in "${AD_ATTRS[@]}"; do
        [[ "$key" == "$attr" ]] && return 0
    done
    return 1
}

# dscl prints a value stored as a binary plist as hex text ("62706c69 73743030 ..."). Prints the
# value as XML plist text either way.
HEX_VALUE='^[0-9a-fA-F]{8}( [0-9a-fA-F]{2,8})*$'
plist_value_as_xml() {
    if [[ "$1" =~ $HEX_VALUE ]]; then
        printf '%s' "$1" | xxd -r -p | plutil -convert xml1 -o - - 2>/dev/null
    else
        printf '%s\n' "$1"
    fi
}

# accountPolicyData as XML. A mobile account stores it as a binary plist, a fresh one as XML.
account_policy_xml() {
    local outer
    outer=$(dscl -plist . -read "/Users/$1" dsAttrTypeNative:accountPolicyData 2>/dev/null) || return 0
    plist_value_as_xml "$(attr_values_from_plist "$outer")"
}

# Keys in accountPolicyData that a fresh account doesn't have (AD-imposed password rules).
# A fresh account has only: creationTime, failedLoginCount, failedLoginTimestamp, passwordLastSetTime.
extra_policy_keys() {
    local inner key
    inner=$(account_policy_xml "$1")
    [[ -n "$inner" ]] || return 0
    while IFS= read -r key; do
        case "$key" in
            "" | creationTime | failedLoginCount | failedLoginTimestamp | passwordLastSetTime) ;;
            *) echo "$key" ;;
        esac
    done < <(plist_keys "$inner")
}

# True if the text from `ls -led <home>` holds exactly the stock ACL entry and nothing else.
# ACL entries print as " 0: group:everyone deny delete".
home_acl_is_stock() {
    local count
    count=$(printf '%s\n' "$1" | grep -Ec '^ *[0-9]+: ')
    [[ "$count" -eq 1 ]] && printf '%s\n' "$1" | grep -q 'group:everyone deny delete'
}

# True if the shell is the one AD assigned (it still equals original_shell) and not the fresh one.
# $1 = UserShell, $2 = original_shell. A shell the user picked later is kept.
is_ad_shell() {
    [[ -n "$2" && "$1" == "$2" && "$1" != "$FRESH_SHELL" ]]
}

# True for GrantAdmin / VerifyOnly values that switch the option on.
is_enabled() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        true | yes | 1) return 0 ;;
    esac
    return 1
}
# END helpers

# BEGIN readonly checks (read the system but change nothing; run against a real account in tests/)
is_bound() {
    dsconfigad -show 2>/dev/null | grep -q "Active Directory Domain"
}

# The search paths live in the /Search node, so the node comes first (dscl /Search -read .).
# `dscl . -read /Search` looks in the local node instead and prints nothing.
search_paths() {
    local plist
    plist=$(dscl -plist /Search -read . CSPSearchPath 2>/dev/null) || return 1
    attr_values_from_plist "$plist"
}

in_group() { # $1 = group, $2 = user
    dscl . -read "/Groups/$1" GroupMembership 2>/dev/null | tr ' ' '\n' | grep -qx "$2"
}

# Prints one line for every way the account differs from a fresh local account.
find_differences() {
    local entry kind key keys name gid mode shell count
    is_bound && echo "This Mac is still bound to Active Directory"
    while IFS= read -r entry; do
        [[ -n "$entry" ]] && is_ad_search_path "$entry" && echo "Active Directory is still in the search path"
    done < <(search_paths)
    while IFS= read -r entry; do
        # Name only the kind (";LocalCachedUser;..." -> LocalCachedUser), not the whole entry.
        [[ -n "$entry" ]] && is_ad_authority_entry "$entry" && kind=${entry#;} &&
            echo "AuthenticationAuthority has an AD entry: ${kind%%;*}"
    done < <(record_values "/Users/$username" AuthenticationAuthority)
    keys=$(plist_keys "$(dscl -plist . -read "/Users/$username" 2>/dev/null)")
    while IFS= read -r key; do
        [[ -n "$key" ]] && is_ad_attribute_key "$key" && echo "AD attribute remains: $key"
    done <<<"$keys"
    for name in $(missing_writers "$keys"); do
        echo "The record has no _writers_$name; on a fresh account the user can change $name"
    done
    while IFS= read -r entry; do
        [[ -n "$entry" ]] && is_ad_alt_identity "$entry" && echo "AltSecurityIdentities has an AD Kerberos principal"
    done < <(record_values "/Users/$username" AltSecurityIdentities)
    while IFS= read -r entry; do
        [[ -n "$entry" ]] && is_domain_alias "$entry" && echo "RecordName has a domain alias: $entry"
    done < <(record_values "/Users/$username" RecordName)
    gid=$(dscl . -read "/Users/$username" PrimaryGroupID 2>/dev/null | awk '{print $2}')
    [[ "$gid" == "20" ]] || echo "PrimaryGroupID is $gid, a fresh account uses 20"
    shell=$(record_values "/Users/$username" UserShell)
    is_ad_shell "$shell" "$(record_values "/Users/$username" dsAttrTypeNative:original_shell)" &&
        echo "UserShell is $shell (set by AD), a fresh account uses $FRESH_SHELL"
    # Membership comes from the AuthenticationAuthority; a local account is in localaccounts (61).
    dseditgroup -o checkmember -m "$username" netaccounts 2>/dev/null | grep -q '^yes' &&
        echo "The user is in netaccounts (network account); a fresh account is in localaccounts"
    [[ -n "$(extra_policy_keys "$username")" ]] && echo "Account policy still has AD rules"
    [[ -n "$(record_values /Groups/admin NestedGroups)" ]] && echo "The admin group has nested (AD) groups"
    in_group staff "$username" && echo "The user is listed in the staff group; on a fresh account only root is"
    if [[ -d "$homedir" ]]; then
        mode=$(stat -f %Lp "$homedir")
        is_stock_home_mode "$mode" || echo "Home folder mode is $mode, a fresh account uses $FRESH_HOME_MODE"
        [[ "$(stat -f %g "$homedir")" == "20" ]] || echo "Home folder group is not staff"
        home_acl_is_stock "$(ls -lde "$homedir")" || echo "Home folder ACL isn't just 'everyone deny delete'"
        # After the unbind no AD group resolves, so -nogroup finds every one, not only the primary.
        count=$(find "$homedir" -xdev -nogroup 2>/dev/null | grep -c .)
        [[ "$count" -gt 0 ]] && echo "$count item(s) in the home folder still have an AD group"
        if [[ -f "$homedir/.CFUserTextEncoding" ]]; then
            mode=$(stat -f %Lp "$homedir/.CFUserTextEncoding")
            [[ "$mode" == "$FRESH_TEXT_ENCODING_MODE" ]] ||
                echo ".CFUserTextEncoding mode is $mode, a fresh account uses $FRESH_TEXT_ENCODING_MODE"
        fi
    fi
}

# END readonly checks

# Security software can interrupt file-system tools (EINTR / fts_read). Retry only those.
# Output of the last attempt is left in FS_OUTPUT.
FS_OUTPUT=""
retry_fs() {
    local attempt
    for attempt in 1 2 3 4 5; do
        FS_OUTPUT=$("$@" 2>&1) && return 0
        case "$FS_OUTPUT" in
            *"Interrupted system call"* | *fts_read*) sleep 2 ;;
            *) return 1 ;;
        esac
    done
    return 1
}

# SIP/TCC blocks some paths even for root. That isn't a failure of the migration.
fs_ok() {
    [[ "$FS_OUTPUT" == *"Operation not permitted"* ]]
}

# FileVault / SecureToken guard. Captured before any change to the account.
HAD_SECURETOKEN=0
FILEVAULT_ON=0
CRYPTO_BEFORE=""
crypto_users() {
    diskutil apfs listCryptoUsers / 2>/dev/null | grep -Eo '[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}' | tr '[:lower:]' '[:upper:]' | sort | tr '\n' ' '
}

CaptureFileVaultState() {
    record_values "/Users/$username" AuthenticationAuthority | grep -q "SecureToken" && HAD_SECURETOKEN=1
    if fdesetup status 2>/dev/null | grep -q "FileVault is On"; then
        FILEVAULT_ON=1
        CRYPTO_BEFORE=$(crypto_users)
    fi
}

# Stops the run if the user could no longer unlock FileVault.
CheckFileVaultIntact() {
    if [[ $HAD_SECURETOKEN -eq 1 ]] && ! record_values "/Users/$username" AuthenticationAuthority | grep -q "SecureToken"; then
        log_message "ERROR" "The SecureToken entry is gone. Stopping: $username may not be able to unlock FileVault."
        exit 1
    fi
    if [[ $FILEVAULT_ON -eq 1 && "$(crypto_users)" != "$CRYPTO_BEFORE" ]]; then
        log_message "ERROR" "The FileVault crypto users changed. Stopping."
        exit 1
    fi
}

# Restore point written before any change. The password hash and the keys derived from the
# password are never included.
BackupAccountRecord() {
    local file key
    file="/var/log/mobile_to_local_backup_${username}_$(date +%s).plist"
    if ( umask 077; dscl -plist . -read "/Users/$username" > "$file" ); then
        for key in ShadowHashData KerberosKeys HeimdalSRPKey; do
            plutil -remove "dsAttrTypeNative:$key" "$file" 2>/dev/null
        done
        plutil -insert '_dsconfigad_show' -string "$(dsconfigad -show 2>&1)" "$file" 2>/dev/null
        chmod 600 "$file"
        log_message "INFO" "Backed up the account record to $file"
    else
        log_message "ERROR" "Could not back up the account record. Stopping."
        exit 1
    fi
}

UnbindFromAD() {
    local attempt output
    for attempt in 1 2 3; do
        output=$(dsconfigad -remove -force -u none -p none 2>&1)
        # Restart Directory Services and let AD release before checking; checking sooner races.
        killall opendirectoryd &>/dev/null
        sleep 2
        if ! is_bound; then
            log_message "INFO" "Unbound from Active Directory"
            return 0
        fi
    done
    log_message "WARN" "Still bound to Active Directory after 3 attempts: $output"
}

# Removes AD from the custom search paths and puts the search policy back to Automatic,
# which is what a Mac that was never bound has.
ResetSearchPaths() {
    local automatic="dsAttrTypeStandard:NSPSearchPath" path node notes=""
    while IFS= read -r path; do
        [[ -n "$path" ]] && is_ad_search_path "$path" || continue
        dscl /Search/Contacts -delete . CSPSearchPath "$path" &>/dev/null
        dscl /Search -delete . CSPSearchPath "$path" &>/dev/null
        notes="AD path removed. "
    done < <(search_paths)
    for node in /Search /Search/Contacts; do
        dscl "$node" -read . SearchPolicy 2>/dev/null | grep -q "$automatic" && continue
        if dscl "$node" -change . SearchPolicy dsAttrTypeStandard:CSPSearchPath "$automatic" &>/dev/null; then
            notes="${notes}$node set to Automatic. "
        else
            log_message "WARN" "Could not set $node to Automatic"
        fi
    done
    [[ -n "$notes" ]] && log_message "INFO" "Search paths: $notes"
}

# Deletes single values of a multi-valued attribute, keeping the others.
# $1 = attribute, $2 = predicate function
RemoveMatchingValues() {
    local attribute="$1" predicate="$2" value removed=0
    while IFS= read -r value; do
        [[ -n "$value" ]] || continue
        "$predicate" "$value" || continue
        if dscl . -delete "/Users/$username" "$attribute" "$value"; then
            removed=$((removed + 1))
        else
            log_message "WARN" "Could not remove a value from $attribute"
        fi
    done < <(record_values "/Users/$username" "$attribute")
    [[ $removed -gt 0 ]] && log_message "INFO" "Removed $removed AD value(s) from $attribute"
}

RemoveADAttributes() {
    local key removed=0 names=""
    while IFS= read -r key; do
        [[ -n "$key" ]] && is_ad_attribute_key "$key" || continue
        if dscl . -delete "/Users/$username" "$key"; then
            removed=$((removed + 1))
            names="$names ${key#dsAttrType*:}"
        else
            log_message "WARN" "Could not remove $key"
        fi
    done < <(plist_keys "$(dscl -plist . -read "/Users/$username" 2>/dev/null)")
    [[ $removed -gt 0 ]] && log_message "INFO" "Removed $removed AD attribute(s):$names"
}

# Clear AD-imposed password rules (expiry, history, last-login tracking). Only when there are any,
# so a fresh account's own policy data (creation time etc.) is left alone. pwpolicy removes the
# rules; keys it leaves are removed by writing the data back without them (as XML, like a fresh
# account stores it).
ClearAccountPolicies() {
    local extra key file
    extra=$(extra_policy_keys "$username")
    [[ -n "$extra" ]] || return 0
    pwpolicy -n /Local/Default -u "$username" -clearaccountpolicies &>/dev/null
    extra=$(extra_policy_keys "$username")
    if [[ -n "$extra" ]]; then
        file=$(mktemp)
        account_policy_xml "$username" > "$file"
        while IFS= read -r key; do
            plutil -remove "$key" "$file" &>/dev/null
        done <<<"$extra"
        plutil -lint -s "$file" && dscl . -create "/Users/$username" dsAttrTypeNative:accountPolicyData "$(cat "$file")"
        rm -f "$file"
    fi
    extra=$(extra_policy_keys "$username")
    if [[ -z "$extra" ]]; then
        log_message "INFO" "Cleared AD account policies"
    else
        log_message "WARN" "Could not clear AD account policies: $(printf '%s' "$extra" | tr '\n' ' ')"
    fi
}

# As root plain kdestroy only clears root's tickets, so run it in the user's session.
DestroyKerberosTickets() {
    launchctl asuser "$uid" /usr/bin/kdestroy -a &>/dev/null && log_message "INFO" "Destroyed Kerberos tickets"
}

# A fresh account is in staff through PrimaryGroupID 20, not through the group's member list.
RemoveStaffListing() {
    in_group staff "$username" || return 0
    if dseditgroup -o edit -d "$username" -t user staff; then
        log_message "INFO" "Removed the explicit staff group listing"
    else
        log_message "WARN" "Could not remove the staff group listing"
    fi
}

# Opt-in. A fresh local account isn't an admin unless asked to be.
GrantAdminRights() {
    is_enabled "$GrantAdmin" || return 0
    in_group admin "$username" && return 0
    if dseditgroup -o edit -a "$username" -t user admin; then
        log_message "INFO" "Added $username to the admin group"
    else
        log_message "WARN" "Could not add $username to the admin group"
    fi
}

ResetPrimaryGroup() {
    [[ "$original_gid" == "20" ]] && return 0
    if dscl . -create "/Users/$username" PrimaryGroupID 20; then
        log_message "INFO" "Reset PrimaryGroupID from $original_gid to 20 (staff)"
    else
        log_message "WARN" "Could not reset PrimaryGroupID"
    fi
}

# Only a shell AD assigned is reset; one the user picked is kept. Uses the values read before
# RemoveADAttributes deleted original_shell.
ResetShell() {
    is_ad_shell "$original_shell" "$ad_shell" || return 0
    if dscl . -create "/Users/$username" UserShell "$FRESH_SHELL"; then
        log_message "INFO" "Reset UserShell from $original_shell (set by AD) to $FRESH_SHELL"
    else
        log_message "WARN" "Could not reset UserShell"
    fi
}

# Lets the user change the values a fresh account lets them change. Adds no data.
AddWriterPermissions() {
    local name added=""
    for name in $(missing_writers "$(plist_keys "$(dscl -plist . -read "/Users/$username" 2>/dev/null)")"); do
        if dscl . -create "/Users/$username" "dsAttrTypeNative:_writers_$name" "$username"; then
            added="$added $name"
        else
            log_message "WARN" "Could not add _writers_$name"
        fi
    done
    [[ -n "$added" ]] && log_message "INFO" "Let the user change their own:$added"
}

# Owner, group and permissions of the home folder, set to a stock macOS layout. Runs after the
# Directory Services restart, so AD groups no longer resolve and -nogroup finds them.
FixHomeFolder() {
    local mode count encoding match=(-nogroup)
    if [[ ! -d "$homedir" ]]; then
        log_message "WARN" "Home folder not found: $homedir"
        return 0
    fi

    # Ownership of the folder itself.
    if [[ "$(stat -f %u:%g "$homedir")" != "$uid:20" ]]; then
        if retry_fs chown "$uid:20" "$homedir" || fs_ok; then
            log_message "INFO" "Set the home folder owner and group (staff)"
        else
            log_message "WARN" "Could not set home folder ownership: ${FS_OUTPUT:0:200}"
        fi
    fi

    # Files created while the account was an AD user carry the AD primary group, and some carry
    # other AD groups. Only those are changed; the UID is unchanged so user ownership is already
    # correct. Also runs on an account converted earlier (items macOS regrouped at the next login).
    [[ -n "$original_gid" && "$original_gid" != "20" ]] && match=( \( -gid "$original_gid" -o -nogroup \) )
    count=$(find "$homedir" -xdev "${match[@]}" 2>/dev/null | grep -c .)
    if [[ "$count" -gt 0 ]]; then
        if [[ "$(basename "$homedir")" == "$username" ]]; then
            if retry_fs find "$homedir" -xdev "${match[@]}" -exec chgrp -h 20 {} +; then
                log_message "INFO" "Changed $count item(s) in the home folder from an AD group to staff"
            elif fs_ok; then
                log_message "INFO" "Changed the group on $count home folder item(s) (skipped protected files)"
            else
                log_message "WARN" "Could not change the group on all home folder files: ${FS_OUTPUT:0:200}"
            fi
        else
            log_message "WARN" "Skipped the group change: '$homedir' is not a folder named for $username"
        fi
    fi

    encoding="$homedir/.CFUserTextEncoding"
    if [[ -f "$encoding" && ! -L "$encoding" && "$(stat -f %Lp "$encoding")" != "$FRESH_TEXT_ENCODING_MODE" ]]; then
        if retry_fs chmod "$FRESH_TEXT_ENCODING_MODE" "$encoding" || fs_ok; then
            log_message "INFO" "Set the .CFUserTextEncoding mode to $FRESH_TEXT_ENCODING_MODE"
        else
            log_message "WARN" "Could not set the .CFUserTextEncoding mode: ${FS_OUTPUT:0:200}"
        fi
    fi

    mode=$(stat -f %Lp "$homedir")
    if ! is_stock_home_mode "$mode"; then
        if retry_fs chmod "$FRESH_HOME_MODE" "$homedir" || fs_ok; then
            log_message "INFO" "Set the home folder mode to $FRESH_HOME_MODE (was $mode)"
        else
            log_message "WARN" "Could not set the home folder mode: ${FS_OUTPUT:0:200}"
        fi
    fi

    # Remove every ACL first (stale domain entries), then add the stock one.
    if ! home_acl_is_stock "$(ls -lde "$homedir")"; then
        if retry_fs chmod -N "$homedir" && retry_fs chmod +a "group:everyone deny delete" "$homedir"; then
            log_message "INFO" "Reset the home folder ACL to the stock entry"
        else
            log_message "WARN" "Could not reset the home folder ACL: ${FS_OUTPUT:0:200}"
        fi
    fi

    if [[ -d "$homedir/Public" && "$(stat -f %Lp "$homedir/Public")" != "755" ]]; then
        retry_fs chmod 755 "$homedir/Public" || fs_ok || log_message "WARN" "Could not set the Public folder mode"
    fi
}

RestartDirectoryServices() {
    local waited=0
    killall opendirectoryd &>/dev/null
    # Flush the DS cache so `id` shows the new groups immediately, not the cached AD ones.
    dscacheutil -flushcache &>/dev/null
    # Wait for the account to be readable again instead of sleeping a fixed time.
    while [[ $waited -lt 30 ]] && ! dscl . -read "/Users/$username" UniqueID &>/dev/null; do
        sleep 1
        waited=$((waited + 1))
    done
    log_message "INFO" "Restarted Directory Services"
}

# --- Main ---------------------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi
[[ -e "$LOG_FILE" ]] || ( umask 077; : > "$LOG_FILE" )

username=$EnrollmentUser
GrantAdmin=${GrantAdmin:-false}
VerifyOnly=${VerifyOnly:-false}
UseDialog=${UseDialog:-false}

if [[ ! "$username" =~ ^[A-Za-z0-9._-]{1,64}$ || "$username" == -* ]]; then
    log_message "ERROR" "Invalid target user name: '$username'"
    exit 1
fi
if ! dscl . -read "/Users/$username" &>/dev/null; then
    log_message "ERROR" "User $username does not exist"
    exit 1
fi

log_message "INFO" "MigrateADMobileAccountToLocalAccount $Version: $username, macOS $(sw_vers -productVersion)"
dialog_init

uid=$(id -u "$username")
homedir=$(dscl . -read "/Users/$username" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //')
original_gid=$(dscl . -read "/Users/$username" PrimaryGroupID | awk '{print $2}')
original_shell=$(record_values "/Users/$username" UserShell)
ad_shell=$(record_values "/Users/$username" dsAttrTypeNative:original_shell)

differences=$(find_differences)
if [[ -z "$differences" ]]; then
    log_message "INFO" "No Active Directory traces found. Nothing to do."
    if [[ $DIALOG_ENABLED -eq 1 ]]; then
        dialog_start "AD to Local: $username" "No Active Directory traces found." "Check Account"
        dialog_step 0 success "Already a local account"
        dialog_progress 1 "Already a local account"
        dialog_finish "Already a Local Account" "No Active Directory traces were found. Nothing to change."
        wait "$DIALOG_PID" 2>/dev/null
        dialog_close
    fi
    exit 0
fi
while IFS= read -r line; do
    log_message "INFO" "Found: $line"
done <<<"$differences"
if is_enabled "$VerifyOnly"; then
    log_message "INFO" "Verify only: nothing was changed"
    if [[ $DIALOG_ENABLED -eq 1 ]]; then
        dialog_start "AD to Local: $username" "Differences found (verify only, nothing changed)." \
            "Verify Only" "$differences"
        dialog_finish "Verify Only" "$(printf '%s\n' "$differences" | head -5)... See the log for details."
        # Wait for the user to close the dialog.
        wait "$DIALOG_PID" 2>/dev/null
        dialog_close
    fi
    exit 2
fi

# What decides which steps run, captured before anything changes.
is_bound && was_bound=1 || was_bound=0
was_mobile=0
while IFS= read -r entry; do
    is_ad_authority_entry "$entry" && was_mobile=1
done < <(record_values "/Users/$username" AuthenticationAuthority)

# Build the step list for the dialog (only the steps that will actually run).
dialog_steps=()
dialog_steps+=("Back Up Account Record")
[[ $was_bound -eq 1 ]] && dialog_steps+=("Unbind from Active Directory")
[[ $was_bound -eq 1 || "$differences" == *"in the search path"* ]] && dialog_steps+=("Clean Search Paths")
[[ $was_mobile -eq 1 ]] && dialog_steps+=("Remove AD Authentication Entries")
dialog_steps+=("Remove AD Attributes")
dialog_steps+=("Remove AD Kerberos Identities")
dialog_steps+=("Remove Domain Aliases")
dialog_steps+=("Clear AD Password Policies")
[[ $was_mobile -eq 1 ]] && dialog_steps+=("Destroy Kerberos Tickets")
dialog_steps+=("Reset Groups and Shell")
dialog_steps+=("Restart Directory Services")
dialog_steps+=("Fix Home Folder")
dialog_steps+=("Verify Against Fresh Account")

dialog_start "AD to Local: $username" "Converting $username to a local account. Do not restart or power off." "${dialog_steps[@]}"

# Track the current step index for dialog updates.
di=0
dialog_running() { dialog_step "$di" wait "$1"; }
dialog_done()    { dialog_step "$di" success "$1"; dialog_progress "$((di + 1))" "$2"; di=$((di + 1)); }
dialog_warn()    { dialog_step "$di" error "$1"; dialog_progress "$((di + 1))" "$2"; di=$((di + 1)); }

dialog_running "Backing up..."
CaptureFileVaultState
BackupAccountRecord
dialog_done "Backed up" "Back Up Account Record"

if [[ $was_bound -eq 1 ]]; then
    dialog_running "Unbinding..."
    UnbindFromAD
    dialog_done "Unbound" "Unbind from Active Directory"
fi
if [[ $was_bound -eq 1 || "$differences" == *"in the search path"* ]]; then
    dialog_running "Cleaning search paths..."
    ResetSearchPaths
    dialog_done "Search paths cleaned" "Clean Search Paths"
fi
if [[ $was_mobile -eq 1 ]]; then
    dialog_running "Removing AD authority entries..."
    RemoveMatchingValues AuthenticationAuthority is_ad_authority_entry
    CheckFileVaultIntact
    dialog_done "AD entries removed" "Remove AD Authentication Entries"
fi
dialog_running "Removing AD attributes..."
RemoveADAttributes
RemoveMatchingValues AltSecurityIdentities is_ad_alt_identity
RemoveMatchingValues RecordName is_domain_alias
dialog_done "Attributes removed" "Remove AD Attributes and Identities"

dialog_running "Clearing policies and tickets..."
ClearAccountPolicies
[[ $was_mobile -eq 1 ]] && DestroyKerberosTickets
RemoveStaffListing
GrantAdminRights
ResetPrimaryGroup
ResetShell
AddWriterPermissions
dialog_done "Groups and shell reset" "Reset Groups and Shell"

dialog_running "Restarting Directory Services..."
RestartDirectoryServices
dialog_done "Restarted" "Restart Directory Services"

dialog_running "Fixing home folder..."
FixHomeFolder
dialog_done "Home folder fixed" "Fix Home Folder"

dialog_running "Verifying..."
remaining=$(find_differences)
CheckFileVaultIntact
if [[ -z "$remaining" ]]; then
    log_message "INFO" "Done: $username matches a fresh local account"
    dialog_done "Matches a fresh account" "Verify Against Fresh Account"
    dialog_finish "Migration Successful" "$username is now a local account. Restart to confirm the login still works."
    wait "$DIALOG_PID" 2>/dev/null
    dialog_close
    exit 0
fi
while IFS= read -r line; do
    log_message "WARN" "Still different: $line"
done <<<"$remaining"
log_message "WARN" "Finished with differences from a fresh local account"
dialog_warn "Differences remain" "Verify Against Fresh Account"
dialog_finish "Completed With Warnings" "Some differences remain. See the log: $LOG_FILE"
wait "$DIALOG_PID" 2>/dev/null
dialog_close
exit 2

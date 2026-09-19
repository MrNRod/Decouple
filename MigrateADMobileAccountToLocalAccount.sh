#!/bin/bash
# Converts an Active Directory mobile account into a local account that matches a fresh local account.
# The account to convert is passed in the EnrollmentUser variable. See the README for usage and credits.
# Modified 9/19/2026
Version=1.8

# Logging configuration
LOG_FILE="/var/log/mobile_to_local_migration.log"
LOG_LEVEL="INFO" # DEBUG, INFO, WARN, ERROR

# Logging function
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Define log levels
    case "$level" in
        "DEBUG") level_num=0 ;;
        "INFO") level_num=1 ;;
        "WARN") level_num=2 ;;
        "ERROR") level_num=3 ;;
        *) level_num=1 ;;
    esac
    
    # Check if we should log this level
    case "$LOG_LEVEL" in
        "DEBUG") min_level=0 ;;
        "INFO") min_level=1 ;;
        "WARN") min_level=2 ;;
        "ERROR") min_level=3 ;;
        *) min_level=1 ;;
    esac
    
    if [ $level_num -ge $min_level ]; then
        echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    fi
}

# Initialize logging
log_message "INFO" "=== Starting Mobile to Local Account Migration Script ==="
log_message "INFO" "Script Version: $Version"
log_message "INFO" "Log file: $LOG_FILE"
log_message "INFO" "Log level: $LOG_LEVEL"

MIGRATION_MARKER="/var/db/.mobile_to_local_migration_done"

if [ -f "$MIGRATION_MARKER" ]; then
    log_message "INFO" "Migration already completed. Marker file found: $MIGRATION_MARKER"
    log_message "INFO" "Exiting script."
    exit 0
fi

migration_error=0

clear
username=$EnrollmentUser
if [[ ! "$username" =~ ^[A-Za-z0-9._-]{1,64}$ || "$username" == -* ]]; then
    log_message "ERROR" "Invalid target user name: '$username'. Exiting."
    echo "Invalid target user name. Exiting."
    exit 1
fi
FullScriptName=$(basename "$0")
ShowVersion="$FullScriptName $Version"

log_message "INFO" "Target username: $username"
log_message "INFO" "Script name: $FullScriptName"

check4AD=$(dscl localhost -list . | grep "Active Directory")
log_message "DEBUG" "AD binding check result: $check4AD"

# Save current IFS state
OLDIFS=$IFS

IFS='.' read osvers_major osvers_minor osvers_dot_version <<< "$(sw_vers -productVersion)"

# restore IFS to previous state
IFS=$OLDIFS

log_message "INFO" "macOS Version: $osvers_major.$osvers_minor.$osvers_dot_version"

echo "********* Running $FullScriptName Version $Version *********"

RunAsRoot()
{
        ##  Pass in the full path to the executable as $1
        if [[ "${USER}" != "root" ]] ; then
                log_message "WARN" "Script must be run as root. Current user: ${USER}"
                echo
                echo "***  This application must be run as root.  Please authenticate below.  ***"
                echo
                sudo "${1}" && exit 0
        fi
        log_message "INFO" "Script is running as root (user: ${USER})"
}

RemoveAD(){
    log_message "INFO" "Starting AD removal process..."
    
    # This function force-unbinds the Mac from the existing Active Directory domain
    # and updates the search path settings to remove references to Active Directory 

    searchPath=$(dscl /Search -read . CSPSearchPath | grep Active\ Directory | sed 's/^ //')
    log_message "DEBUG" "Found AD search path: $searchPath"

    # Force unbind from Active Directory
    log_message "INFO" "Force unbinding from Active Directory..."
    if dsconfigad -remove -force -u none -p none; then
        log_message "INFO" "Successfully unbound from Active Directory"
    else
        log_message "ERROR" "Failed to unbind from Active Directory"
        migration_error=1
    fi
    
    # Deletes the Active Directory domain from the custom /Search
    # and /Search/Contacts paths
    log_message "INFO" "Removing AD from search paths..."
    if dscl /Search/Contacts -delete . CSPSearchPath "$searchPath"; then
        log_message "DEBUG" "Removed AD from /Search/Contacts"
    else
        log_message "WARN" "Failed to remove AD from /Search/Contacts (may not exist)"
    fi
    
    if dscl /Search -delete . CSPSearchPath "$searchPath"; then
        log_message "DEBUG" "Removed AD from /Search"
    else
        log_message "WARN" "Failed to remove AD from /Search (may not exist)"
    fi
    
    # Changes the /Search and /Search/Contacts path type from Custom to Automatic
    log_message "INFO" "Changing search policy to Automatic..."
    if dscl /Search -change . SearchPolicy dsAttrTypeStandard:CSPSearchPath dsAttrTypeStandard:NSPSearchPath; then
        log_message "DEBUG" "Changed /Search policy to Automatic"
    else
        log_message "WARN" "Failed to change /Search policy"
    fi
    
    if dscl /Search/Contacts -change . SearchPolicy dsAttrTypeStandard:CSPSearchPath dsAttrTypeStandard:NSPSearchPath; then
        log_message "DEBUG" "Changed /Search/Contacts policy to Automatic"
    else
        log_message "WARN" "Failed to change /Search/Contacts policy"
    fi
    
    log_message "INFO" "AD removal process completed"
}

# BEGIN helpers (pure text handling, unit tested in tests/test_filters.sh)

# Attributes an AD mobile account adds and a local account never has (lower case, namespace stripped).
# Deliberately NOT listed: AltSecurityIdentities (value-filtered), accountPolicyData (pwpolicy),
# _writers_LinkedIdentity (Apple Account), AppleMeta* (virtual). A fresh account can have these.
AD_ATTRS=(
    cachedgroups smbprimarygroupsid originalauthenticationauthority originalnodename smbsid
    smbscriptpath smbpasswordlastset smbgrouprid mcxsettings mcxflags accounttype copytimestamp
    account_instance cached_auth_policy cached_groups original_realname original_shell
    preserved_attributes email_address primaryntdomain firstname lastname jobtitle company
    department emailaddress
)

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

# $1 = user, $2 = attribute
attr_values() {
    local plist
    plist=$(dscl -plist . -read "/Users/$1" "$2" 2>/dev/null) || return 1
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

# Keys in accountPolicyData that a fresh account doesn't have (AD-imposed password rules).
# A fresh account has only: creationTime, failedLoginCount, failedLoginTimestamp, passwordLastSetTime.
extra_policy_keys() {
    local outer inner key
    outer=$(dscl -plist . -read "/Users/$1" dsAttrTypeNative:accountPolicyData 2>/dev/null) || return 0
    inner=$(attr_values_from_plist "$outer")
    while IFS= read -r key; do
        case "$key" in
            "" | creationTime | failedLoginCount | failedLoginTimestamp | passwordLastSetTime) ;;
            *) echo "$key" ;;
        esac
    done < <(plist_keys "$inner")
}
# END helpers

# Deletes single values of a multi-valued attribute, keeping the others.
# $1 = attribute, $2 = predicate function
RemoveMatchingValues() {
    local attribute="$1" predicate="$2" value removed=0
    while IFS= read -r value; do
        [[ -n "$value" ]] || continue
        "$predicate" "$value" || continue
        log_message "INFO" "Removing $attribute value: ${value:0:60}"
        if dscl . -delete "/Users/$username" "$attribute" "$value"; then
            removed=$((removed + 1))
        else
            log_message "ERROR" "Failed to remove a $attribute value"
            migration_error=1
        fi
    done < <(attr_values "$username" "$attribute")
    log_message "INFO" "$attribute: removed $removed value(s)"
}

RemoveADAttributes() {
    local plist key removed=0
    plist=$(dscl -plist . -read "/Users/$username" 2>/dev/null)
    while IFS= read -r key; do
        [[ -n "$key" ]] && is_ad_attribute_key "$key" || continue
        if dscl . -delete "/Users/$username" "$key"; then
            log_message "DEBUG" "Removed $key"
            removed=$((removed + 1))
        else
            log_message "ERROR" "Failed to remove $key"
            migration_error=1
        fi
    done < <(plist_keys "$plist")
    log_message "INFO" "Removed $removed AD attribute(s)"
}

# FileVault / SecureToken guard. Captured before any change to the account.
HAD_SECURETOKEN=0
FILEVAULT_ON=0
CRYPTO_BEFORE=""
crypto_users() {
    diskutil apfs listCryptoUsers / 2>/dev/null | grep -Eo '[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}' | tr '[:lower:]' '[:upper:]' | sort | tr '\n' ' '
}

CaptureFileVaultState() {
    attr_values "$username" AuthenticationAuthority | grep -q "SecureToken" && HAD_SECURETOKEN=1
    if fdesetup status 2>/dev/null | grep -q "FileVault is On"; then
        FILEVAULT_ON=1
        CRYPTO_BEFORE=$(crypto_users)
    fi
    log_message "INFO" "FileVault on: $FILEVAULT_ON, SecureToken present: $HAD_SECURETOKEN"
}

# Exits if the user could no longer unlock FileVault.
CheckFileVaultIntact() {
    if [[ $HAD_SECURETOKEN -eq 1 ]] && ! attr_values "$username" AuthenticationAuthority | grep -q "SecureToken"; then
        log_message "ERROR" "SecureToken entry is gone. Stopping: $username may not be able to unlock FileVault."
        exit 1
    fi
    if [[ $FILEVAULT_ON -eq 1 && "$(crypto_users)" != "$CRYPTO_BEFORE" ]]; then
        log_message "ERROR" "FileVault crypto users changed. Stopping."
        exit 1
    fi
}

# Restore point written before any change. The password hash is never included.
BackupAccountRecord() {
    local file
    file="/var/log/mobile_to_local_backup_${username}_$(date +%s).plist"
    if ( umask 077; dscl -plist . -read "/Users/$username" > "$file" ); then
        plutil -remove 'dsAttrTypeNative:ShadowHashData' "$file" 2>/dev/null
        chmod 600 "$file"
        log_message "INFO" "Account record backed up to $file"
    else
        log_message "ERROR" "Could not back up the account record. Exiting."
        exit 1
    fi
}

PasswordMigration(){
    log_message "INFO" "Starting authentication authority cleanup..."

    # macOS 10.14.4 removes the actual ShadowHashData key immediately if the AuthenticationAuthority
    # value that references the ShadowHash is removed. Only AD entries are removed here; the
    # ShadowHash, SecureToken and local Kerberos (@LKDC) entries stay, so the local password and the
    # FileVault login keep working.
    RemoveMatchingValues AuthenticationAuthority is_ad_authority_entry
    CheckFileVaultIntact
    log_message "INFO" "Authentication authority cleanup completed"
}

RunAsRoot "${0}"

if ! id "$username" &>/dev/null; then
    log_message "ERROR" "User $username does not exist. Exiting."
    echo "User $username does not exist. Exiting."
    exit 1
fi

log_message "INFO" "User $username exists, checking account type..."

accounttype=$(dscl . -read /Users/"$username" AuthenticationAuthority | head -2 | awk -F'/' '{print $2}' | tr -d '\n')
log_message "DEBUG" "Account type: $accounttype"

# Exit if the account is already a local account and AD is not bound
if [[ "$accounttype" != "Active Directory" && -z "$check4AD" ]]; then
    log_message "INFO" "User $username is already a local account and AD is not bound. Skipping migration."
    if touch "$MIGRATION_MARKER"; then
        log_message "INFO" "Created migration marker for local account: $MIGRATION_MARKER"
        echo "Migration skipped: $username is already a local account and AD is unbound. Marker file created."
    else
        log_message "ERROR" "Failed to create migration marker for local account"
        migration_error=1
        exit 1
    fi
    exit 0
fi

# Check for AD binding and offer to unbind if found. 
if [[ "${check4AD}" = "Active Directory" ]]; then
    log_message "INFO" "Active Directory binding detected. Removing AD binding..."
    RemoveAD
    echo "AD binding has been removed."
else
    log_message "INFO" "No Active Directory binding detected"
fi

# Check if the account is a AD mobile account
if [[ "$accounttype" = "Active Directory" ]]; then
    mobileusercheck=$(dscl . -read /Users/"$username" AuthenticationAuthority | head -2 | awk -F'/' '{print $1}' | tr -d '\n' | sed 's/^[^:]*: //' | sed s/\;/""/g)
    log_message "DEBUG" "Mobile user check: $mobileusercheck"
    
    if [[ "$mobileusercheck" = "LocalCachedUser" ]]; then
        log_message "INFO" "$username has an AD mobile account. Starting conversion process..."
        printf "$username has an AD mobile account.\nConverting to a local account with the same username and UID.\n"
    else
        log_message "INFO" "The $username account is not a AD mobile account"
        printf "The $username account is not a AD mobile account\n"
        exit 0
    fi
else
    log_message "INFO" "The $username account is not a AD mobile account"
    printf "The $username account is not a AD mobile account\n"
    exit 0
fi

log_message "INFO" "Starting account attribute removal process..."

CaptureFileVaultState
BackupAccountRecord
original_gid=$(dscl . -read /Users/"$username" PrimaryGroupID 2>/dev/null | awk '{print $2}')
log_message "INFO" "Original PrimaryGroupID: $original_gid"

# Remove the account attributes that identify it as an Active Directory mobile account.
# Only attributes that are present are touched, so a missing one is not an error.
RemoveADAttributes

# AD Kerberos principals and "user@DOMAIN" aliases only; the Apple Account value and the primary name stay.
RemoveMatchingValues AltSecurityIdentities is_ad_alt_identity
RemoveMatchingValues RecordName is_domain_alias

# Clear AD-imposed password rules (expiry etc.); a fresh account has none. Only when there are any,
# so a fresh account's own policy data (creation time etc.) is left alone.
if [[ -n "$(extra_policy_keys "$username")" ]]; then
    log_message "INFO" "Clearing AD account policies..."
    pwpolicy -n /Local/Default -u "$username" -clearaccountpolicies || log_message "WARN" "pwpolicy -clearaccountpolicies failed"
else
    log_message "INFO" "No AD account policies to clear"
fi

# Destroy the user's Kerberos tickets. As root plain kdestroy only clears root's, so run it in the user's session.
launchctl asuser "$(id -u "$username")" /usr/bin/kdestroy -a 2>/dev/null || log_message "DEBUG" "No Kerberos tickets to destroy"

log_message "INFO" "Account attribute removal completed"

# Remove AD entries from AuthenticationAuthority
PasswordMigration

# A fresh account is in staff through PrimaryGroupID 20. Record changes finish here,
# before the file system is touched.
log_message "INFO" "Resetting PrimaryGroupID to 20 (staff)..."
if ! dscl . -create "/Users/$username" PrimaryGroupID 20; then
    log_message "ERROR" "Failed to reset PrimaryGroupID"
    migration_error=1
fi

# Refresh Directory Services
log_message "INFO" "Refreshing Directory Services..."
if [[ ( ${osvers_major} -eq 10 && ${osvers_minor} -lt 7 ) ]]; then
    log_message "DEBUG" "Killing DirectoryService process..."
    if killall DirectoryService; then
        log_message "INFO" "Successfully killed DirectoryService"
    else
        log_message "ERROR" "Failed to kill DirectoryService"
        migration_error=1
    fi
else
    log_message "DEBUG" "Killing opendirectoryd process..."
    if killall opendirectoryd; then
        log_message "INFO" "Successfully killed opendirectoryd"
    else
        log_message "ERROR" "Failed to kill opendirectoryd"
        migration_error=1
    fi
fi

log_message "INFO" "Waiting 20 seconds for directory services to restart..."
sleep 20

log_message "INFO" "Verifying conversion process..."
accounttype=$(dscl . -read /Users/"$username" AuthenticationAuthority | head -2 | awk -F'/' '{print $2}' | tr -d '\n')
log_message "DEBUG" "Post-conversion account type: $accounttype"

if [[ "$accounttype" = "Active Directory" ]]; then
    log_message "ERROR" "Conversion process failed. Account is still an AD mobile account."
    printf "Something went wrong with the conversion process.\nThe $username account is still an AD mobile account.\n"
    exit 1
else
    log_message "INFO" "Conversion process successful. Account is now a local account."
    printf "Conversion process was successful.\nThe $username account is now a local account.\n"
fi

log_message "INFO" "Updating home directory permissions..."
homedir=$(dscl . -read /Users/"$username" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //')
if [[ -d "$homedir" ]]; then
    log_message "INFO" "Home directory location: $homedir"

    # Remove stale domain-based ACLs
    log_message "INFO" "Updating home folder permissions for the $username account"
    if chmod -N "$homedir"; then
        log_message "INFO" "Successfully removed existing ACLs"
    else
        log_message "WARN" "Failed to remove ACLs"
        migration_error=1
    fi

    # Set the home directory ownership to the user and the group to staff (20).
    # Only recurse into a folder that is clearly this user's.
    if [[ "$(basename "$homedir")" == "$username" && "$homedir" != "/" ]]; then
        log_message "INFO" "Resetting ownership of $homedir (some paths may be protected by SIP)"
        chown_errors=$(mktemp -t chown_errors)
        if chown -R "$username:staff" "$homedir" 2>"$chown_errors"; then
            log_message "INFO" "chown completed"
        elif grep -q "Operation not permitted" "$chown_errors"; then
            log_message "WARN" "chown reported 'Operation not permitted' on protected files - safe to ignore"
        else
            log_message "ERROR" "chown failed with unexpected errors"
            cat "$chown_errors" >> "$LOG_FILE"
            migration_error=1
        fi
        rm -f "$chown_errors"
    else
        log_message "WARN" "Skipping recursive chown: '$homedir' is not a folder named for $username"
        migration_error=1
    fi

    # Stock macOS home folder: drwxr-xr-x with an "everyone deny delete" ACL.
    if chmod 755 "$homedir"; then
        log_message "INFO" "Set home folder mode to 755"
    else
        log_message "ERROR" "Failed to set home folder mode"
        migration_error=1
    fi
    log_message "INFO" "Setting no access for everyone group on $homedir"
    if chmod +a "group:everyone deny delete" "$homedir"; then
        log_message "INFO" "Successfully set everyone group permissions"
    else
        log_message "ERROR" "Failed to set everyone group permissions"
        migration_error=1
    fi
else
    log_message "WARN" "No home directory found for user $username"
    migration_error=1
fi

# A fresh account is NOT listed in the staff group (only root is); it is a member through
# PrimaryGroupID 20. Remove a listing left by an earlier version of this script.
if dscl . -read /Groups/staff GroupMembership 2>/dev/null | tr ' ' '\n' | grep -qx "$username"; then
    log_message "INFO" "Removing explicit staff group listing for $username..."
    dseditgroup -o edit -d "$username" -t user staff || { log_message "ERROR" "Failed to remove staff listing"; migration_error=1; }
fi

log_message "INFO" "Displaying user and group information for the $username account"
if id "$username"; then
    log_message "INFO" "Successfully retrieved user information"
else
    log_message "ERROR" "Failed to retrieve user information"
    migration_error=1
fi

# Automatically grant admin rights to the local account
log_message "INFO" "Granting admin rights to $username..."
if dseditgroup -o edit -a "$username" -t user admin; then
    log_message "INFO" "Successfully granted admin rights to $username"
    echo "Admin rights automatically granted to the $username account"
else
    log_message "ERROR" "Failed to grant admin rights to $username"
    migration_error=1
fi

# Check if $EnrollmentUser is in awagent_enrolled group, and add if missing
log_message "INFO" "Checking awagent_enrolled group membership..."
if ! dseditgroup -o checkmember -m "$username" awagent_enrolled | grep -q "yes"; then
    log_message "INFO" "$username is not in awagent_enrolled group. Adding..."
    if dseditgroup -o edit -a "$username" -t user awagent_enrolled; then
        log_message "INFO" "Successfully added $username to awagent_enrolled group"
    else
        log_message "ERROR" "Failed to add $username to awagent_enrolled group"
        migration_error=1
    fi
else
    log_message "INFO" "$username is already a member of awagent_enrolled group."
fi

# Remove macadmin from awagent_enrolled group if present
log_message "INFO" "Checking if 'macadmin' is in awagent_enrolled group..."
if dseditgroup -o checkmember -m "macadmin" awagent_enrolled | grep -q "yes"; then
    log_message "INFO" "'macadmin' is a member of awagent_enrolled. Removing..."
    if dseditgroup -o edit -d "macadmin" -t user awagent_enrolled; then
        log_message "INFO" "Successfully removed 'macadmin' from awagent_enrolled group"
    else
        log_message "ERROR" "Failed to remove 'macadmin' from awagent_enrolled group"
        migration_error=1
    fi
else
    log_message "INFO" "'macadmin' is not a member of awagent_enrolled. No action needed."
fi

# Compare with a fresh local account and report any difference.
VerifyFreshAccount() {
    local diffs=0 gid mode entry key
    while IFS= read -r entry; do
        [[ -n "$entry" ]] && is_ad_authority_entry "$entry" && { log_message "WARN" "Fresh-account check: AD entry remains in AuthenticationAuthority"; diffs=$((diffs + 1)); }
    done < <(attr_values "$username" AuthenticationAuthority)
    while IFS= read -r key; do
        [[ -n "$key" ]] && is_ad_attribute_key "$key" && { log_message "WARN" "Fresh-account check: AD attribute remains: $key"; diffs=$((diffs + 1)); }
    done < <(plist_keys "$(dscl -plist . -read "/Users/$username" 2>/dev/null)")
    gid=$(dscl . -read /Users/"$username" PrimaryGroupID | awk '{print $2}')
    [[ "$gid" == "20" ]] || { log_message "WARN" "Fresh-account check: PrimaryGroupID is $gid, expected 20"; diffs=$((diffs + 1)); }
    if [[ -d "$homedir" ]]; then
        mode=$(stat -f %Lp "$homedir")
        [[ "$mode" == "755" ]] || { log_message "WARN" "Fresh-account check: home mode is $mode, expected 755"; diffs=$((diffs + 1)); }
        ls -lde "$homedir" | grep -q "group:everyone deny delete" || { log_message "WARN" "Fresh-account check: home ACL missing"; diffs=$((diffs + 1)); }
    fi
    if [[ $diffs -eq 0 ]]; then
        log_message "INFO" "Fresh-account check: $username matches a fresh local account"
    else
        log_message "WARN" "Fresh-account check: $diffs difference(s) found"
    fi
}
VerifyFreshAccount
CheckFileVaultIntact

if [[ $migration_error -eq 0 ]]; then
    log_message "INFO" "Migration completed successfully. Creating marker file..."
    if touch "$MIGRATION_MARKER"; then
        log_message "INFO" "Successfully created migration marker file: $MIGRATION_MARKER"
        echo "Migration for $username completed successfully. Marker file created."
    else
        log_message "ERROR" "Failed to create migration marker file"
        migration_error=1
    fi
else
    log_message "ERROR" "Migration encountered errors. Marker file not created."
    echo "Migration encountered errors. Marker file not created."
    exit 1
fi

log_message "INFO" "=== Mobile to Local Account Migration Script Completed ==="
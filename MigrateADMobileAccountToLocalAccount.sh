#!/bin/bash
# Modified 7/11/2025
Version=1.7

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

# Original source is from MigrateUserHomeToDomainAcct.sh
# Written by Patrick Gallagher - https://twitter.com/patgmac
#
# Guidance and inspiration from Lisa Davies:
# http://lisacherie.com/?p=239
#
# Modified by Rich Trouton
# https://github.com/rtrouton/rtrouton_scripts/tree/main/rtrouton_scripts/migrate_ad_mobile_account_to_local_account
#
# Modified by Noel Rodriguez-Lebron
#
# Version 1.0 - Migrates an Active Directory mobile account to a local account by the following process:

# 1. Detect if the Mac is bound to AD and offer to unbind the Mac from AD if desired
# 2. Display a list of the accounts with a UID greater than 1000
# 3. Remove the following attributes from the specified account:
# 
# cached_groups
# cached_auth_policy
# CopyTimestamp - This attribute is used by the OS to determine if the account is a mobile account
# SMBPrimaryGroupSID
# OriginalAuthenticationAuthority
# OriginalNodeName
# SMBSID
# SMBScriptPath
# SMBPasswordLastSet
# SMBGroupRID
# PrimaryNTDomain
# AppleMetaRecordName
# MCXSettings
# MCXFlags
#
# 4. Selectively modify the account's AuthenticationAuthority attribute to remove AD-specific attributes.
# 5. Restart the directory services process
# 6. Check to see if the conversion process succeeded by checking the OriginalNodeName attribute for the value "Active Directory"
# 7. If the conversion process succeeded, update the permissions on the account's home folder.
# 8. Prompt if admin rights should be granted for the specified account
#
# Version 1.1
#
# Changes:
# 
# 1. After conversion, the specified account is added to the staff group.  All local accounts on this Mac are members of the staff group,
#    but AD mobile accounts are not members of the staff group.
# 2. The "accounttype" variable is now checking the AuthenticationAuthority attribute instead of the OriginalNodeName attribute. 
#    The reason for Change 2's attributes change is that the AuthenticationAuthority attribute will exist following the conversion 
#    process while the OriginalNodeName attribute may not.
#
#
# Version 1.2
#
# Changes:
#
# Add RemoveAD function to handle the following tasks:
#
# 1. Force unbind the Mac from Active Directory
# 2. Deletes the Active Directory domain from the custom /Search and /Search/Contacts paths
# 3. Changes the /Search and /Search/Contacts path type from Custom to Automatic
# 
# Thanks to Rick Lemmon for the suggested changes to the AD unbind process.
#
# Version 1.3
#
# Changes:
#
# Fix to account password backup and restore process. Previous versions 
# of the script were adding extra quote marks to the account's plist 
# file located in /var/db/dslocal/nodes/Default/users/.
#
# Version 1.4
#
# Changes:
#
# macOS 10.14.4 will remove the the actual ShadowHashData key immediately 
# if the AuthenticationAuthority array value which references the ShadowHash
# is removed from the AuthenticationAuthority array. To address this, the
# existing AuthenticationAuthority array will be modified to remove the Kerberos
# and LocalCachedUser user values.
#
# Thanks to the anonymous reporter who provided the bug report and fix.
#
# Version 1.5
#
# Changes:
#
# 1. Removed the user prompts for unbinding the Mac from AD and granting admin rights to the local account.
# 2. Added a check to see if the account is a mobile account before proceeding with the conversion process.
# 3. Added a marker file to indicate that the migration has been completed successfully.
# 4. Added error handling to ensure that the migration process is successful before creating the marker file.
#
# Version 1.6
#
# Changes:
#
# 1. Made work for the EnrollmentUser account in Workspace ONE UEM using Script Variables
# 2. User permissions are now set to read-only for the staff group on the home directory
# 3. Added Logging to the script
#
# Version 1.7
#
# Changes:
#
# 1. Added a check to see if the account is already a local account and AD is not bound before proceeding with the conversion process.
# 2. Changed the chmod command to use the -RN flag to remove all ACLs from the home directory.

clear
username=$EnrollmentUser
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

PasswordMigration(){
    log_message "INFO" "Starting password migration process..."
    
    # macOS 10.14.4 will remove the the actual ShadowHashData key immediately 
    # if the AuthenticationAuthority array value which references the ShadowHash
    # is removed from the AuthenticationAuthority array. To address this, the
    # existing AuthenticationAuthority array will be modified to remove the Kerberos
    # and LocalCachedUser user values.
 
    AuthenticationAuthority=$(dscl -plist . -read /Users/"$username" AuthenticationAuthority)
    log_message "DEBUG" "Current AuthenticationAuthority: $AuthenticationAuthority"
    
    Kerberosv5=$(echo "${AuthenticationAuthority}" | xmllint --xpath 'string(//string[contains(text(),"Kerberosv5")])' -)
    LocalCachedUser=$(echo "${AuthenticationAuthority}" | xmllint --xpath 'string(//string[contains(text(),"LocalCachedUser")])' -)
    
    log_message "DEBUG" "Found Kerberosv5: $Kerberosv5"
    log_message "DEBUG" "Found LocalCachedUser: $LocalCachedUser"
    
    # Remove Kerberosv5 and LocalCachedUser
    if [[ ! -z "${Kerberosv5}" ]]; then
        log_message "INFO" "Removing Kerberosv5 from AuthenticationAuthority..."
        if dscl -plist . -delete "/Users/$username" AuthenticationAuthority "${Kerberosv5}"; then
            log_message "INFO" "Successfully removed Kerberosv5"
        else
            log_message "ERROR" "Failed to remove Kerberosv5"
            migration_error=1
        fi
    fi
    
    if [[ ! -z "${LocalCachedUser}" ]]; then
        log_message "INFO" "Removing LocalCachedUser from AuthenticationAuthority..."
        if dscl -plist . -delete "/Users/$username" AuthenticationAuthority "${LocalCachedUser}"; then
            log_message "INFO" "Successfully removed LocalCachedUser"
        else
            log_message "ERROR" "Failed to remove LocalCachedUser"
            migration_error=1
        fi
    fi
    
    log_message "INFO" "Password migration process completed"
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
	
# Remove the account attributes that identify it as an Active Directory mobile account
log_message "DEBUG" "Removing cached_groups..."
dscl . -delete "/Users/$username" cached_groups || { log_message "ERROR" "Failed to remove cached_groups"; migration_error=1; }

log_message "DEBUG" "Removing cached_auth_policy..."
dscl . -delete "/Users/$username" cached_auth_policy || { log_message "ERROR" "Failed to remove cached_auth_policy"; migration_error=1; }

log_message "DEBUG" "Removing CopyTimestamp..."
dscl . -delete "/Users/$username" CopyTimestamp || { log_message "ERROR" "Failed to remove CopyTimestamp"; migration_error=1; }

log_message "DEBUG" "Removing AltSecurityIdentities..."
dscl . -delete "/Users/$username" AltSecurityIdentities || { log_message "ERROR" "Failed to remove AltSecurityIdentities"; migration_error=1; }

log_message "DEBUG" "Removing SMBPrimaryGroupSID..."
dscl . -delete "/Users/$username" SMBPrimaryGroupSID || { log_message "ERROR" "Failed to remove SMBPrimaryGroupSID"; migration_error=1; }

log_message "DEBUG" "Removing OriginalAuthenticationAuthority..."
dscl . -delete "/Users/$username" OriginalAuthenticationAuthority || { log_message "ERROR" "Failed to remove OriginalAuthenticationAuthority"; migration_error=1; }

log_message "DEBUG" "Removing OriginalNodeName..."
dscl . -delete "/Users/$username" OriginalNodeName || { log_message "ERROR" "Failed to remove OriginalNodeName"; migration_error=1; }

log_message "DEBUG" "Removing SMBSID..."
dscl . -delete "/Users/$username" SMBSID || { log_message "ERROR" "Failed to remove SMBSID"; migration_error=1; }

log_message "DEBUG" "Removing SMBScriptPath..."
dscl . -delete "/Users/$username" SMBScriptPath || { log_message "ERROR" "Failed to remove SMBScriptPath"; migration_error=1; }

log_message "DEBUG" "Removing SMBPasswordLastSet..."
dscl . -delete "/Users/$username" SMBPasswordLastSet || { log_message "ERROR" "Failed to remove SMBPasswordLastSet"; migration_error=1; }

log_message "DEBUG" "Removing SMBGroupRID..."
dscl . -delete "/Users/$username" SMBGroupRID || { log_message "ERROR" "Failed to remove SMBGroupRID"; migration_error=1; }

log_message "DEBUG" "Removing PrimaryNTDomain..."
dscl . -delete "/Users/$username" PrimaryNTDomain || { log_message "ERROR" "Failed to remove PrimaryNTDomain"; migration_error=1; }

log_message "DEBUG" "Removing AppleMetaRecordName..."
dscl . -delete "/Users/$username" AppleMetaRecordName || { log_message "ERROR" "Failed to remove AppleMetaRecordName"; migration_error=1; }

log_message "DEBUG" "Removing MCXSettings..."
dscl . -delete "/Users/$username" MCXSettings || { log_message "ERROR" "Failed to remove MCXSettings"; migration_error=1; }

log_message "DEBUG" "Removing MCXFlags..."
dscl . -delete "/Users/$username" MCXFlags || { log_message "ERROR" "Failed to remove MCXFlags"; migration_error=1; }

log_message "INFO" "Account attribute removal completed"

# Migrate password and remove AD-related attributes
PasswordMigration

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
homedir=$(dscl . -read /Users/"$username" NFSHomeDirectory  | awk '{print $2}')
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
    
    # Set the home directory ownership to the user and the group to staff (20)
    log_message "INFO" "Resetting ownership of $homedir (some paths may be protected by SIP)"

    if chown -R "$username:staff" "$homedir" 2>/tmp/chown_errors.log; then
        log_message "INFO" "chown completed (non-fatal errors may be logged)"
    else
        if grep -q "Operation not permitted" /tmp/chown_errors.log; then
            log_message "WARN" "chown reported 'Operation not permitted' on protected files — safe to ignore"
        else
            log_message "ERROR" "chown failed with unexpected errors"
            cat /tmp/chown_errors.log >> "$LOG_FILE"
            migration_error=1
        fi
    fi
    
    # Add no access ACL for everyone group (default macOS-style access)
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

# Add user to the staff group on the Mac
log_message "INFO" "Adding $username to the staff group..."
if dseditgroup -o edit -a "$username" -t user staff; then
    log_message "INFO" "Successfully added $username to staff group"
else
    log_message "ERROR" "Failed to add $username to staff group"
    migration_error=1
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
#!/bin/bash
# Unit tests for the pure helpers in decouple.sh.
# Read-only: nothing here changes the system. Run with /bin/bash (3.2) to match macOS.
#   /bin/bash tests/test_filters.sh
SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/decouple.sh"
# Load only the helpers between the markers; the rest of the script would run a migration.
# (bash 3.2 can't `source <(...)`, so use eval.)
helpers=$(sed -n '/^# BEGIN helpers/,/^# END helpers/p;/^# BEGIN readonly checks/,/^# END readonly checks/p' "$SCRIPT")
[[ -n "$helpers" ]] || { echo "Could not find the helpers block in $SCRIPT"; exit 2; }
eval "$helpers"
# A missing function must fail loudly instead of reading as "not flagged".
for fn in attr_values_from_plist plist_keys record_values search_paths extra_policy_keys plist_value_as_xml account_policy_xml is_ad_shell is_stock_home_mode missing_writers home_acl_is_stock is_enabled is_ad_search_path find_differences is_bound in_group is_ad_authority_entry is_ad_alt_identity is_domain_alias is_ad_attribute_key; do
    declare -F "$fn" >/dev/null || { echo "helper not loaded: $fn"; exit 2; }
done

pass=0; fail=0
check() { # $1 = description, $2 = expected, $3 = actual
    if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: $1"; echo "   expected: [$2]"; echo "   actual:   [$3]"; fi
}
truthy() { if "$@"; then echo yes; else echo no; fi; }

SHADOW=';ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>'
LKDC=';Kerberosv5;;jdoe@LKDC:SHA1.AAAA;LKDC:SHA1.AAAA;'
TOKEN=';SecureToken;'
ADK=';Kerberosv5;;jdoe@CORP.EXAMPLE.COM;CORP.EXAMPLE.COM;'
CACHED=';LocalCachedUser;/Active Directory/CORP/corp.example.com:jdoe:11111111-2222-3333-4444-555555555555'

# --- authority filter: the first Kerberosv5 entry can be the local one and must survive
check "ShadowHash kept"      no  "$(truthy is_ad_authority_entry "$SHADOW")"
check "SecureToken kept"     no  "$(truthy is_ad_authority_entry "$TOKEN")"
check "LKDC Kerberos kept"   no  "$(truthy is_ad_authority_entry "$LKDC")"
check "AD Kerberos removed"  yes "$(truthy is_ad_authority_entry "$ADK")"
check "LocalCachedUser removed" yes "$(truthy is_ad_authority_entry "$CACHED")"
check "NetLogon removed"     yes "$(truthy is_ad_authority_entry ';NetLogon;jdoe;CORP')"
check "protected wins over AD text" no "$(truthy is_ad_authority_entry ';ShadowHash;HASHLIST:<X> Active Directory')"

# --- alt identities and record names
check "Apple X509 kept"      no  "$(truthy is_ad_alt_identity 'X509:<T>CN=Apple Root CA<S>CN=x')"
check "local Kerberos kept"  no  "$(truthy is_ad_alt_identity 'Kerberos:jdoe@LKDC:SHA1.AAAA')"
check "AD Kerberos alt removed" yes "$(truthy is_ad_alt_identity 'Kerberos:jdoe@CORP.EXAMPLE.COM')"
check "domain alias"         yes "$(truthy is_domain_alias 'jdoe@corp.example.com')"
check "short name kept"      no  "$(truthy is_domain_alias 'jdoe')"
check "Apple ID name kept"   no  "$(truthy is_domain_alias 'com.apple.idms.appleid.prd.000716-08-0ca2476f')"

# --- attribute keys
for k in dsAttrTypeStandard:CachedGroups dsAttrTypeNative:cached_groups dsAttrTypeStandard:SMBSID dsAttrTypeStandard:FirstName \
         dsAttrTypeStandard:AppleMetaRecordName; do
    check "AD attribute $k" yes "$(truthy is_ad_attribute_key "$k")"
done
for k in dsAttrTypeStandard:RecordName dsAttrTypeStandard:AuthenticationAuthority dsAttrTypeStandard:GeneratedUID \
         dsAttrTypeStandard:AltSecurityIdentities dsAttrTypeNative:accountPolicyData dsAttrTypeStandard:UniqueID \
         dsAttrTypeStandard:PrimaryGroupID dsAttrTypeStandard:RealName dsAttrTypeStandard:Password \
         dsAttrTypeStandard:AppleMetaNodeLocation dsAttrTypeStandard:UserShell; do
    check "kept attribute $k" no "$(truthy is_ad_attribute_key "$k")"
done

# --- plist parsing: fixture with the AD entry FIRST (the case that broke v1.7)
fixture='<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>dsAttrTypeStandard:AuthenticationAuthority</key><array>'
# dscl escapes the text like any XML writer; the hash text contains < and >.
xml_escape() { local t="${1//&/&amp;}"; t="${t//</&lt;}"; printf '%s' "${t//>/&gt;}"; }
for e in "$ADK" "$SHADOW" "$LKDC" "$CACHED" "$TOKEN"; do fixture+="<string>$(xml_escape "$e")</string>"; done
fixture+='</array></dict></plist>'
mapfile_out=$(attr_values_from_plist "$fixture")
check "parses 5 entries" 5 "$(printf '%s\n' "$mapfile_out" | grep -c .)"
removed=$(printf '%s\n' "$mapfile_out" | while IFS= read -r e; do is_ad_authority_entry "$e" && echo "$e"; done)
check "removes exactly the AD entries" "$ADK
$CACHED" "$removed"

record='<plist version="1.0"><dict><key>dsAttrTypeStandard:RecordName</key><array><string>jdoe</string></array><key>dsAttrTypeStandard:SMBSID</key><array><string>S-1</string></array></dict></plist>'
check "record keys" "dsAttrTypeStandard:RecordName
dsAttrTypeStandard:SMBSID" "$(plist_keys "$record")"

# --- account policy: AD rules are flagged, a fresh account's own keys are not
policy_xml='<plist version="1.0"><dict><key>creationTime</key><real>1.0</real><key>passwordLastSetTime</key><real>2.0</real><key>maxMinutesUntilChangePassword</key><integer>129600</integer></dict></plist>'
dscl() { # stub: only used for the policy fixture, restored below
    printf '<plist version="1.0"><dict><key>dsAttrTypeNative:accountPolicyData</key><array><string>%s</string></array></dict></plist>' "$(xml_escape "$POLICY")"
}
POLICY="$policy_xml"; check "AD policy key flagged" "maxMinutesUntilChangePassword" "$(extra_policy_keys jdoe)"
POLICY='<plist version="1.0"><dict><key>creationTime</key><real>1.0</real><key>failedLoginCount</key><integer>0</integer></dict></plist>'
check "fresh policy keys not flagged" "" "$(extra_policy_keys jdoe)"
# A mobile account stores the policy as a binary plist, which dscl prints as hex in groups of 8.
POLICY=$(printf '%s' "$policy_xml" | plutil -convert binary1 -o - - | xxd -p | tr -d '\n' | sed -E 's/(.{8})/\1 /g; s/ $//')
check "binary policy is printed as hex" yes "$(truthy test "${POLICY:0:17}" = "62706c69 73743030")"
check "AD policy key flagged in a binary policy" "maxMinutesUntilChangePassword" "$(extra_policy_keys jdoe)"
check "XML policy passes through" "$policy_xml" "$(plist_value_as_xml "$policy_xml")"
unset -f dscl

# --- ACL: only the stock entry counts
STOCK_LS='drwxr-xr-x+ 72 jdoe  staff  2304 Sep 18 22:12 /Users/jdoe
 0: group:everyone deny delete'
check "stock ACL"          yes "$(truthy home_acl_is_stock "$STOCK_LS")"
check "no ACL"             no  "$(truthy home_acl_is_stock 'drwxr-xr-x 72 jdoe staff 2304 Sep 18 22:12 /Users/jdoe')"
check "extra domain ACL"   no  "$(truthy home_acl_is_stock "$STOCK_LS
 1: group:11111111-2222-3333-4444-555555555555 allow list,search")"
check "wrong ACL"          no  "$(truthy home_acl_is_stock 'drwxr-xr-x+ 1 a b 1 Jan 1 /x
 0: user:x allow read')"

# --- shell: only the one AD assigned is reset
check "AD shell reset"            yes "$(truthy is_ad_shell /bin/bash /bin/bash)"
check "shell the user picked kept" no "$(truthy is_ad_shell /bin/zsh /bin/bash)"
check "other picked shell kept"   no  "$(truthy is_ad_shell /opt/homebrew/bin/fish /bin/bash)"
check "no original_shell: kept"   no  "$(truthy is_ad_shell /bin/bash "")"
check "AD shell already zsh"      no  "$(truthy is_ad_shell /bin/zsh /bin/zsh)"

# --- home folder mode: macOS 27 makes 750, older macOS made 755; anything else is fixed
check "750 is stock" yes "$(truthy is_stock_home_mode 750)"
check "755 is stock" yes "$(truthy is_stock_home_mode 755)"
for m in 700 775 777 751; do check "$m is not stock" no "$(truthy is_stock_home_mode $m)"; done

# --- writer permissions: only the missing ones are named
check "all writers missing" "AvatarRepresentation
inputSources
unlockOptions" "$(missing_writers "dsAttrTypeStandard:RecordName")"
check "one writer missing" "inputSources" "$(missing_writers "dsAttrTypeNative:_writers_AvatarRepresentation
dsAttrTypeNative:_writers_unlockOptions
dsAttrTypeNative:_writers_LinkedIdentity")"
check "a longer key doesn't count" "unlockOptions" "$(missing_writers "dsAttrTypeNative:_writers_AvatarRepresentation
dsAttrTypeNative:_writers_inputSources
dsAttrTypeNative:_writers_unlockOptionsX")"

# --- search paths and the GrantAdmin switch
check "AD search path"     yes "$(truthy is_ad_search_path '/Active Directory/All Domains')"
check "domain search path" yes "$(truthy is_ad_search_path '/Active Directory/CORP/corp.example.com')"
check "local search path"  no  "$(truthy is_ad_search_path '/Local/Default')"
for v in true TRUE yes 1; do check "GrantAdmin=$v is on" yes "$(truthy is_enabled "$v")"; done
for v in false no 0 "" maybe; do check "GrantAdmin='$v' is off" no "$(truthy is_enabled "$v")"; done

# --- find_differences on a stubbed AD mobile account: every difference must be reported
plist_doc() { # $1 = key, rest = values
    local key="$1" out="<plist version=\"1.0\"><dict><key>$1</key><array>" v; shift
    for v in "$@"; do out+="<string>$(xml_escape "$v")</string>"; done
    printf '%s' "$out</array></dict></plist>"
}
dscl() {
    case "$*" in
        "-plist . -read /Users/jdoe AuthenticationAuthority") plist_doc dsAttrTypeStandard:AuthenticationAuthority "$ADK" "$SHADOW" "$LKDC" "$CACHED" "$TOKEN" ;;
        "-plist . -read /Users/jdoe AltSecurityIdentities") plist_doc dsAttrTypeStandard:AltSecurityIdentities "Kerberos:jdoe@CORP.EXAMPLE.COM" "X509:<T>Apple" ;;
        "-plist . -read /Users/jdoe RecordName") plist_doc dsAttrTypeStandard:RecordName jdoe jdoe@corp.example.com ;;
        "-plist . -read /Users/jdoe dsAttrTypeNative:accountPolicyData") plist_doc dsAttrTypeNative:accountPolicyData "$policy_xml" ;;
        "-plist . -read /Users/jdoe") printf '%s' '<plist version="1.0"><dict><key>dsAttrTypeStandard:RecordName</key><array><string>jdoe</string></array><key>dsAttrTypeStandard:CachedGroups</key><array><string>g</string></array><key>dsAttrTypeStandard:AuthenticationAuthority</key><array><string>x</string></array></dict></plist>' ;;
        ". -read /Users/jdoe PrimaryGroupID") echo "PrimaryGroupID: 12" ;;
        "-plist . -read /Users/jdoe UserShell") plist_doc dsAttrTypeStandard:UserShell /bin/bash ;;
        "-plist . -read /Users/jdoe dsAttrTypeNative:original_shell") plist_doc dsAttrTypeNative:original_shell /bin/bash ;;
        ". -read /Groups/staff GroupMembership") echo "GroupMembership: root jdoe" ;;
        "-plist /Search -read . CSPSearchPath") plist_doc dsAttrTypeStandard:CSPSearchPath /Local/Default "/Active Directory/All Domains" ;;
        "-plist . -read /Groups/admin NestedGroups") plist_doc dsAttrTypeStandard:NestedGroups "AAAA-BBBB" ;;
        *) return 1 ;;
    esac
}
dsconfigad() { echo "Active Directory Domain = corp.example.com"; }
dseditgroup() { [[ "$*" == "-o checkmember -m jdoe netaccounts" ]] && echo "yes jdoe is a member of netaccounts"; }
# A stock home folder, except for the mobile account's .CFUserTextEncoding mode. Files with a group
# that doesn't resolve can't be made without root, so find is stubbed for -nogroup only.
fixture_home=$(mktemp -d)
trap 'chmod -N "$fixture_home/jdoe" 2>/dev/null; rm -rf "$fixture_home"' EXIT
homedir="$fixture_home/jdoe"
mkdir "$homedir" && chgrp staff "$homedir" && chmod 750 "$homedir" && chmod +a "group:everyone deny delete" "$homedir"
( umask 377; : > "$homedir/.CFUserTextEncoding" )
find() { [[ "$*" == "$homedir -xdev -nogroup" ]] && printf '%s\n' "$homedir/Library/a" "$homedir/Library/b"; }
username=jdoe
expected="This Mac is still bound to Active Directory
Active Directory is still in the search path
AuthenticationAuthority has an AD entry: Kerberosv5
AuthenticationAuthority has an AD entry: LocalCachedUser
AD attribute remains: dsAttrTypeStandard:CachedGroups
The record has no _writers_AvatarRepresentation; on a fresh account the user can change AvatarRepresentation
The record has no _writers_inputSources; on a fresh account the user can change inputSources
The record has no _writers_unlockOptions; on a fresh account the user can change unlockOptions
AltSecurityIdentities has an AD Kerberos principal
RecordName has a domain alias: jdoe@corp.example.com
PrimaryGroupID is 12, a fresh account uses 20
UserShell is /bin/bash (set by AD), a fresh account uses /bin/zsh
The user is in netaccounts (network account); a fresh account is in localaccounts
Account policy still has AD rules
The admin group has nested (AD) groups
The user is listed in the staff group; on a fresh account only root is
2 item(s) in the home folder still have an AD group
.CFUserTextEncoding mode is 400, a fresh account uses 600"
check "mobile account: every difference reported" "$expected" "$(find_differences)"
unset -f dscl dsconfigad dseditgroup plist_doc find
check "real find: a stock home folder has no item without a group" "" "$(find "$homedir" -xdev -nogroup)"

# --- real, unmodified local account on this Mac: nothing may be flagged
if [[ "${1:-}" != "--no-live" ]] && u=$(stat -f%Su /dev/console) && dscl . -read "/Users/$u" &>/dev/null; then
    live_ad=$(record_values "/Users/$u" AuthenticationAuthority | while IFS= read -r e; do is_ad_authority_entry "$e" && echo "$e"; done)
    check "live account: no AD authority entries flagged" "" "$live_ad"
    live_attrs=$(plist_keys "$(dscl -plist . -read "/Users/$u")" | while IFS= read -r k; do is_ad_attribute_key "$k" && echo "$k"; done)
    check "live account: no AD attributes flagged" "" "$live_attrs"
    live_alt=$(record_values "/Users/$u" AltSecurityIdentities | while IFS= read -r v; do is_ad_alt_identity "$v" && echo "$v"; done)
    check "live account: no alt identities flagged" "" "$live_alt"
    # The whole detection, against a real stock account: it must find no difference at all.
    username=$u
    homedir=$(dscl . -read "/Users/$u" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //')
    check "live account: find_differences is empty" "" "$(find_differences)"
    # Positive controls: the same call form must return real data for a key that exists.
    check "live: record_values reads real group data" yes "$(record_values /Groups/admin GroupMembership | grep -x root >/dev/null && echo yes)"
    check "live: in_group finds root in staff" yes "$(truthy in_group staff root)"
    check "live: in_group rejects a non-member" no "$(truthy in_group staff "$u")"
    check "live account: admin NestedGroups absent (dscl exits 0 for a missing key)" "" "$(record_values /Groups/admin NestedGroups)"
    # Must return real data: the local node is always in the search path, so an empty result means
    # the dscl call is wrong (not that the search path is clean).
    check "live: search_paths reads real data" "/Local/Default" "$(search_paths | head -1)"
    check "live account: no AD search path" "" "$(search_paths | while IFS= read -r p; do is_ad_search_path "$p" && echo "$p"; done)"
    check "old dscl form prints nothing (why search_paths exists)" "" "$(record_values /Search CSPSearchPath)"
    check "live account: home ACL is stock" yes "$(truthy home_acl_is_stock "$(ls -lde "$homedir")")"
    check "live account: no extra policy keys" "" "$(extra_policy_keys "$u")"
    check "live account: has entries to inspect" yes "$(truthy test "$(record_values "/Users/$u" AuthenticationAuthority | grep -c .)" -ge 2)"
fi

echo "passed: $pass  failed: $fail"
[[ $fail -eq 0 ]]

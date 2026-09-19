#!/bin/bash
# Unit tests for the pure helpers in MigrateADMobileAccountToLocalAccount.sh.
# Read-only: nothing here changes the system. Run with /bin/bash (3.2) to match macOS.
#   /bin/bash tests/test_filters.sh
SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/MigrateADMobileAccountToLocalAccount.sh"
# Load only the helpers between the markers; the rest of the script would run a migration.
# (bash 3.2 can't `source <(...)`, so use eval.)
helpers=$(sed -n '/^# BEGIN helpers/,/^# END helpers/p' "$SCRIPT")
[[ -n "$helpers" ]] || { echo "Could not find the helpers block in $SCRIPT"; exit 2; }
eval "$helpers"
# A missing function must fail loudly instead of reading as "not flagged".
for fn in attr_values_from_plist plist_keys attr_values extra_policy_keys is_ad_authority_entry is_ad_alt_identity is_domain_alias is_ad_attribute_key; do
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
for k in dsAttrTypeStandard:CachedGroups dsAttrTypeNative:cached_groups dsAttrTypeStandard:SMBSID dsAttrTypeStandard:FirstName; do
    check "AD attribute $k" yes "$(truthy is_ad_attribute_key "$k")"
done
for k in dsAttrTypeStandard:RecordName dsAttrTypeStandard:AuthenticationAuthority dsAttrTypeStandard:GeneratedUID \
         dsAttrTypeStandard:AltSecurityIdentities dsAttrTypeNative:accountPolicyData dsAttrTypeStandard:UniqueID \
         dsAttrTypeStandard:PrimaryGroupID dsAttrTypeStandard:RealName dsAttrTypeStandard:Password; do
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
unset -f dscl

# --- real, unmodified local account on this Mac: nothing may be flagged
if [[ "${1:-}" != "--no-live" ]] && u=$(stat -f%Su /dev/console) && dscl . -read "/Users/$u" &>/dev/null; then
    live_ad=$(attr_values "$u" AuthenticationAuthority | while IFS= read -r e; do is_ad_authority_entry "$e" && echo "$e"; done)
    check "live account: no AD authority entries flagged" "" "$live_ad"
    live_attrs=$(plist_keys "$(dscl -plist . -read "/Users/$u")" | while IFS= read -r k; do is_ad_attribute_key "$k" && echo "$k"; done)
    check "live account: no AD attributes flagged" "" "$live_attrs"
    live_alt=$(attr_values "$u" AltSecurityIdentities | while IFS= read -r v; do is_ad_alt_identity "$v" && echo "$v"; done)
    check "live account: no alt identities flagged" "" "$live_alt"
    check "live account: no extra policy keys" "" "$(extra_policy_keys "$u")"
    check "live account: has entries to inspect" yes "$(truthy test "$(attr_values "$u" AuthenticationAuthority | grep -c .)" -ge 2)"
fi

echo "passed: $pass  failed: $fail"
[[ $fail -eq 0 ]]

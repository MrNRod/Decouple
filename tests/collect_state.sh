#!/bin/bash
# Prints a normalized, secret-free snapshot of an account, to compare a converted account with a
# fresh local one (tests/compare_state.sh). Read-only: nothing here changes the system.
#   sudo tests/collect_state.sh <user> > <user>.txt
# Output: one "key = value" line per fact; multi-valued facts repeat the key. The user name, UID,
# GUID and home path are replaced with <user>, <uid>, <guid> and <home>. Lines starting with # are
# notes for a person and are ignored by the compare.
user="$1"
if [[ $EUID -ne 0 ]]; then
    echo "Run as root: AuthenticationAuthority and parts of the home folder aren't readable otherwise." >&2
    exit 1
fi
if [[ -z "$user" ]] || ! dscl . -read "/Users/$user" UniqueID &>/dev/null; then
    echo "Usage: sudo $0 <local user>" >&2
    exit 1
fi

uid=$(dscl . -read "/Users/$user" UniqueID | awk '{print $2}')
guid=$(dscl . -read "/Users/$user" GeneratedUID | awk '{print $2}')
home=$(dscl . -read "/Users/$user" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //')
record=$(dscl -plist . -read "/Users/$user")

# Replaces the per-account values so two accounts can be compared.
norm() {
    sed -E -e "s#${home}#<home>#g" -e "s/${guid}/<guid>/g" \
        -e "s/[[:<:]]${uid}[[:>:]]/<uid>/g" -e "s/[[:<:]]${user}[[:>:]]/<user>/g"
}

out() { printf '%s = %s\n' "$1" "$2"; }

# Values of one record key: strings as text, data as <data> (hashes, keys, photos).
key_values() { # $1 = key
    local base="//dict/key[.='$1']/following-sibling::array[1]" n i v
    n=$(xmllint --xpath "count($base/string)" - <<<"$record" 2>/dev/null)
    for ((i = 1; i <= n; i++)); do
        v=$(xmllint --xpath "string(($base/string)[$i])" - <<<"$record")
        [[ "$v" == *$'\n'* ]] && v="<multi-line text>" # embedded plists (MCX, cached policy)
        printf '%s\n' "$v"
    done
    n=$(xmllint --xpath "count($base/data)" - <<<"$record" 2>/dev/null)
    for ((i = 1; i <= n; i++)); do echo "<data>"; done
}

# The kind of an AuthenticationAuthority entry, without the hash list or principal.
authority_kind() {
    local kind
    kind=$(printf '%s' "$1" | awk -F';' '{print $2}')
    case "$kind" in
        Kerberosv5) [[ "$1" == *LKDC:* ]] && echo "Kerberosv5 (LKDC)" || echo "Kerberosv5 (AD)" ;;
        *) echo "$kind" ;;
    esac
}

alt_identity_kind() {
    case "$1" in
        Kerberos:*LKDC:*) echo "Kerberos (LKDC)" ;;
        Kerberos:*) echo "Kerberos (AD)" ;;
        *) echo "${1%%:*}" ;;
    esac
}

echo "# snapshot of $user on $(hostname -s), macOS $(sw_vers -productVersion), $(date '+%Y-%m-%d %H:%M:%S')"
echo "# uid=$uid guid=$guid home=$home"

# --- Record: every key, with its values ---------------------------------------------------------
n=$(xmllint --xpath 'count(/plist/dict/key)' - <<<"$record")
for ((i = 1; i <= n; i++)); do
    key=$(xmllint --xpath "string(/plist/dict/key[$i])" - <<<"$record")
    case "$key" in
        *:AuthenticationAuthority)
            key_values "$key" | while IFS= read -r v; do out "record.$key" "$(authority_kind "$v")"; done ;;
        *:AltSecurityIdentities)
            key_values "$key" | while IFS= read -r v; do out "record.$key" "$(alt_identity_kind "$v")"; done ;;
        *:accountPolicyData)
            # Only the keys: the values are timestamps and counters.
            inner=$(key_values "$key")
            m=$(xmllint --xpath 'count(/plist/dict/key)' - <<<"$inner" 2>/dev/null)
            for ((j = 1; j <= m; j++)); do
                out "policy.key" "$(xmllint --xpath "string(/plist/dict/key[$j])" - <<<"$inner")"
            done
            out "record.$key" "<present>" ;;
        *)
            vals=$(key_values "$key")
            if [[ -z "$vals" ]]; then
                out "record.$key" "<empty>"
            elif [[ "$key" == *JPEGPhoto* ]]; then
                out "record.$key" "<present>" # photo bytes (hex text without root)
            else
                printf '%s\n' "$vals" | while IFS= read -r v; do out "record.$key" "${v:0:200}"; done
            fi ;;
    esac
done | norm

# --- Groups ---------------------------------------------------------------------------------------
gid_names=$(dscl . -list /Groups PrimaryGroupID)
for g in $(id -G "$user" 2>/dev/null); do
    name=$(awk -v g="$g" '$2 == g {print $1; exit}' <<<"$gid_names")
    out "id.group" "$g ${name:-(not local)}"
done
# Local groups that list the user by name.
dscl . -search /Groups GroupMembership "$user" 2>/dev/null | awk '/^[^ \t]/ {print $1}' | sort -u |
    while IFS= read -r g; do out "localgroup.lists_user" "$g"; done

# --- FileVault --------------------------------------------------------------------------------------
token=$(sysadminctl -secureTokenStatus "$user" 2>&1 | grep -Eo 'ENABLED|DISABLED')
out "filevault.securetoken" "${token:-unknown}"
crypto=$(diskutil apfs listCryptoUsers / 2>/dev/null | awk -v g="$guid" '
    index(toupper($0), toupper(g)) {found = 1; next}
    found && /^\+--/ {exit}
    found && /Type:|Volume Owner:/ {sub(/^[ |]+/, ""); print}')
if [[ -n "$crypto" ]]; then
    printf '%s\n' "$crypto" | while IFS= read -r line; do out "filevault.cryptouser" "$line"; done
else
    out "filevault.cryptouser" "no"
fi

# --- Home folder ------------------------------------------------------------------------------------
item_state() { # $1 = key prefix, $2 = path
    out "$1.mode" "$(stat -f '%Sp' "$2")"
    out "$1.owner" "$(stat -f '%Su' "$2")"
    out "$1.group" "$(stat -f '%Sg' "$2")"
    out "$1.flags" "$(stat -f '%Sf' "$2")"
    ls -lde "$2" 2>/dev/null | grep -E '^ *[0-9]+: ' | sed -E 's/^ *//' |
        while IFS= read -r acl; do out "$1.acl" "$acl"; done
    [[ -z "$(ls -lde "$2" 2>/dev/null | grep -E '^ *[0-9]+: ')" ]] && out "$1.acl" "none"
}

if [[ -d "$home" ]]; then
    {
        item_state "home" "$home"
        out "home.xattrs" "$(xattr "$home" 2>/dev/null | sort | tr '\n' ' ')"
        while IFS= read -r name; do
            item_state "item.$name" "$home/$name"
        done < <(ls -A "$home")
        [[ -e "$home/Public/Drop Box" ]] && item_state "item.Public/Drop Box" "$home/Public/Drop Box"
    } | norm

    errors=$(mktemp)
    not_staff=$(find "$home" -xdev ! -group staff 2>>"$errors")
    not_owned=$(find "$home" -xdev ! -user "$user" 2>>"$errors")
    out "home.count.not_group_staff" "$(printf '%s' "$not_staff" | grep -c .)"
    out "home.count.not_owned_by_user" "$(printf '%s' "$not_owned" | grep -c .)"
    printf '%s\n' "$not_staff" | grep . | head -5 | norm | sed 's/^/# not group staff: /'
    printf '%s\n' "$not_owned" | grep . | head -5 | norm | sed 's/^/# not owned by user: /'
    echo "# find could not read $(grep -c . "$errors") path(s) (TCC/SIP; give Terminal Full Disk Access to include them)"
    rm -f "$errors"
else
    out "home" "missing"
fi

# --- This Mac (the compare checks these against a never-bound Mac, not against the reference) ------
dsconfigad -show 2>/dev/null | grep -q "Active Directory Domain" && out "system.bound" "yes" || out "system.bound" "no"
for node in /Search /Search/Contacts; do
    out "system.$node.policy" "$(dscl "$node" -read . SearchPolicy 2>/dev/null | awk '{print $2}')"
    paths=$(dscl -plist "$node" -read . CSPSearchPath 2>/dev/null)
    n=$(xmllint --xpath 'count(//array/string)' - <<<"$paths" 2>/dev/null)
    for ((i = 1; i <= n; i++)); do
        out "system.$node.path" "$(xmllint --xpath "string((//array/string)[$i])" - <<<"$paths")"
    done
done
nested=$(dscl . -read /Groups/admin NestedGroups 2>/dev/null | sed 's/^NestedGroups: *//')
out "system.admin.nestedgroups" "${nested:-none}"

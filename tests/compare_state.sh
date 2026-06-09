#!/bin/bash
# Compares two snapshots from tests/collect_state.sh: a fresh local account (the reference) and a
# converted one. Read-only.
#   tests/compare_state.sh freshuser.txt testuser1.txt
# Prints every value that is only in one of them, per key, and checks the converted snapshot's
# system.* lines against a Mac that was never bound (the reference may have been taken while bound).
# Exit 0 = no differences, 1 = differences.
fresh="$1" converted="$2"
if [[ ! -r "$fresh" || ! -r "$converted" ]]; then
    echo "Usage: $0 <fresh snapshot> <converted snapshot>" >&2
    exit 2
fi

# Keys whose values must differ between two accounts: names, picture, shell history.
IGNORE='^record\.dsAttrTypeStandard:(RealName|Picture|JPEGPhoto)$|^item\.\.(zsh|bash)_(history|sessions)\.'

differences=$(awk -v ignore="$IGNORE" '
    FNR == 1 { file++ }
    /^#/ || index($0, " = ") == 0 { next }
    {
        key = substr($0, 1, index($0, " = ") - 1)
        value = substr($0, index($0, " = ") + 3)
        if (key ~ ignore || key ~ /^system\./) next
        if (file == 1) a[key SUBSEP value] = 1; else b[key SUBSEP value] = 1
    }
    END {
        for (kv in a) if (!(kv in b)) { split(kv, p, SUBSEP); print p[1] "\tfresh only    \t" p[2] }
        for (kv in b) if (!(kv in a)) { split(kv, p, SUBSEP); print p[1] "\tconverted only\t" p[2] }
    }' "$fresh" "$converted" | sort)

system=$(awk '
    index($0, " = ") == 0 { next }
    {
        key = substr($0, 1, index($0, " = ") - 1)
        value = substr($0, index($0, " = ") + 3)
    }
    key == "system.bound" && value != "no" { print "still bound to Active Directory" }
    key ~ /^system\..*\.policy$/ && value != "dsAttrTypeStandard:NSPSearchPath" { print key " is " value ", a never-bound Mac uses Automatic (NSPSearchPath)" }
    key ~ /^system\..*\.path$/ && value ~ /Active Directory/ { print key " still has " value }
    key == "system.admin.nestedgroups" && value != "none" { print "admin has nested groups: " value }
    ' "$converted")

if [[ -n "$differences" ]]; then
    echo "Differences from $fresh:"
    printf '%s\n' "$differences" | awk -F'\t' '
        $1 != last { print $1; last = $1 }
        { print "    " $2 "  " $3 }'
fi
if [[ -n "$system" ]]; then
    echo "This Mac (from $converted):"
    printf '%s\n' "$system" | sed 's/^/    /'
fi
if [[ -z "$differences" && -z "$system" ]]; then
    echo "No differences."
    exit 0
fi
exit 1

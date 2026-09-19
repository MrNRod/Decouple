# AD Account Migration

## Description

The AD Account Migration script converts an Active Directory (AD) mobile account on macOS into a local account that matches a fresh local account. This is useful for detaching a Mac from AD while preserving the user's home folder and settings. It does the same work as the ADToLocal app.

## Usage

The script must run as root. It changes nothing and exits if the account already matches a fresh local account.

### Terminal
```bash
sudo EnrollmentUser="username" ./MigrateADMobileAccountToLocalAccount.sh
```

### MDM (Mobile Device Management)
Upload the script to your MDM and set the variables in its execution environment.

| Variable | Required | Description |
| :--- | :--- | :--- |
| `EnrollmentUser` | Yes | The short name of the account to convert. Use your MDM's variable (e.g., `$EnrollmentUser` in Workspace ONE). |
| `GrantAdmin` | No | `true` adds the converted user to the `admin` group. Default: off, like a fresh local account. |

### Exit codes
| Code | Meaning |
| :--- | :--- |
| `0` | Done, or nothing to do. |
| `1` | Stopped: not root, invalid or missing user, the backup failed, or the FileVault guard tripped. |
| `2` | Finished, but the account still differs from a fresh local account (see the log). |

## What it does

Only the steps the account needs are run, in this order:

1. **Compare** the account with a fresh local account. Nothing to fix means nothing is changed.
2. **Back up** the account record to `/var/log/mobile_to_local_backup_<user>_<time>.plist` (root-only, no password hash).
3. **Unbind** the Mac from AD (with retries and a check), remove AD from the search paths and set the search policy back to Automatic.
4. **Authentication authority:** remove only the AD entries (`LocalCachedUser`, AD `Kerberosv5`). `ShadowHash`, `SecureToken` and the local `@LKDC` Kerberos entry are never removed, so the local password and the FileVault login keep working. The run stops if the `SecureToken` or FileVault crypto-user entry disappears.
5. **Attributes:** remove the AD attributes that are present, the AD Kerberos values in `AltSecurityIdentities` and `user@DOMAIN` aliases in `RecordName`. An Apple Account's values are kept.
6. **Policies and tickets:** clear AD-imposed password policies and destroy the user's Kerberos tickets.
7. **Groups:** set `PrimaryGroupID` to 20. The user is not listed in the `staff` group (only root is on a fresh account); an old listing is removed. With `GrantAdmin=true` the user is added to `admin`.
8. **Home folder:** owner and group `staff`, files that carry the old AD group moved to `staff`, mode 755, and only the `everyone deny delete` ACL (stale domain ACLs are removed).
9. **Restart** Directory Services, then compare with a fresh local account again.

The account keeps its UID.

## Logging

Everything is logged to `/var/log/mobile_to_local_migration.log` (root-only) and to the console, one line per action. There are three levels: `INFO` (what happened), `WARN` (a problem the run continues past) and `ERROR` (the run stopped).

## Testing

Tests for the parsing and filtering helpers, and for the detection logic against a stubbed mobile account and this Mac's real account (read-only). Run with the macOS bash:

```
/bin/bash tests/test_filters.sh
```

This has not been run against a real AD-bound Mac. Test on a disposable one first. Version history is in git.

## Credits

- Originally based on `MigrateUserHomeToDomainAcct.sh` by [Patrick Gallagher](https://twitter.com/patgmac).
- Guidance and inspiration from [Lisa Davies](http://lisacherie.com/?p=239).
- Modified by [Rich Trouton](https://github.com/rtrouton/rtrouton_scripts/tree/main/rtrouton_scripts/migrate_ad_mobile_account_to_local_account).
- Thanks to Rick Lemmon for the suggested changes to the AD unbind process, and to the anonymous reporter who provided the macOS 10.14.4 `ShadowHashData` bug report and fix.
- Modified by Noel Rodriguez-Lebron.

# Decouple

## Description

Decouple converts an Active Directory (AD) mobile account on macOS into a local account that matches a fresh local account. This is useful for detaching a Mac from AD while preserving the user's home folder and settings. It does the same work as the ADToLocal app.

## Usage

The script must run as root. It changes nothing and exits if the account already matches a fresh local account.

### Terminal
```bash
sudo EnrollmentUser="username" ./decouple.sh
```

### MDM (Mobile Device Management)
Upload the script to your MDM and set the variables in its execution environment.

| Variable | Required | Description |
| :--- | :--- | :--- |
| `EnrollmentUser` | Yes | The short name of the account to convert. Use your MDM's variable (e.g., `$EnrollmentUser` in Workspace ONE). |
| `GrantAdmin` | No | `true` adds the converted user to the `admin` group. Default: off, like a fresh local account. |
| `VerifyOnly` | No | `true` only logs the differences from a fresh local account and changes nothing. |
| `UseDialog` | No | `true` shows progress in swiftDialog if `/usr/local/bin/dialog` is installed. Default: off, runs headless. |

### Exit codes
| Code | Meaning |
| :--- | :--- |
| `0` | Done, or nothing to do. |
| `1` | Stopped: not root, invalid or missing user, the backup failed, or the FileVault guard tripped. |
| `2` | Finished, but the account still differs from a fresh local account (see the log). With `VerifyOnly=true`: differences were found. |

## What it does

Only the steps the account needs are run, in this order:

1. **Compare** the account with a fresh local account. Nothing to fix means nothing is changed.
2. **Back up** the account record to `/var/log/decouple_backup_<user>_<time>.plist` (root-only, no password hash).
3. **Unbind** the Mac from AD (with retries and a check), remove AD from the search paths and set the search policy back to Automatic.
4. **Authentication authority:** remove only the AD entries (`LocalCachedUser`, AD `Kerberosv5`). `ShadowHash`, `SecureToken` and the local `@LKDC` Kerberos entry are never removed, so the local password and the FileVault login keep working. The run stops if the `SecureToken` or FileVault crypto-user entry disappears.
5. **Attributes:** remove the AD attributes that are present (including `AppleMetaRecordName`, the AD distinguished name), the AD Kerberos values in `AltSecurityIdentities` and `user@DOMAIN` aliases in `RecordName`. An Apple Account's values are kept.
6. **Policies and tickets:** clear AD-imposed password policies (also the history and last-login keys a mobile account carries) and destroy the user's Kerberos tickets.
7. **Groups and shell:** set `PrimaryGroupID` to 20. The user is not listed in the `staff` group (only root is on a fresh account); an old listing is removed. With `GrantAdmin=true` the user is added to `admin`. The shell is set to `/bin/zsh` only if it is still the one AD assigned; a shell the user picked is kept. The `_writers_` permissions a fresh account has for `AvatarRepresentation`, `inputSources` and `unlockOptions` are added, so the user can change their own picture, input sources and unlock options (permissions only, no data).
8. **Restart** Directory Services, so the AD groups no longer resolve.
9. **Home folder:** owner and group `staff`, and only the `everyone deny delete` ACL (stale domain ACLs are removed). Every item with the old AD primary group or any other group that no longer resolves (all AD groups, after the unbind) is moved to `staff`. `.CFUserTextEncoding` is set to 600. The mode is left alone when it is stock (750 on macOS 27, 755 on accounts made by older macOS); anything else is set to 750.
10. **Compare** with a fresh local account again.

The account keeps its UID.

### Known limitation: Local KDC (Kerberos)

A fresh local account has a `Kerberosv5` entry for the Local KDC (LKDC), plus `KerberosKeys` and
`HeimdalSRPKey`. A converted mobile account doesn't, because these are created by the LKDC when the
password is set — and the mobile account's password was set by Active Directory, not the local KDC.

The account works without them: login, FileVault unlock, and the login keychain all use the preserved
`ShadowHash` and `SecureToken`. The only thing missing is Kerberos single sign-on for local services
(screen sharing, AFP, etc.). To add it, the user changes their password once in System Settings after
the migration. The LKDC then creates the missing entries. Running the script again on a converted account is safe, and fixes items macOS services gave the old AD group again at the first login, so an MDM can run it once more after that login.

## Logging

Everything is logged to `/var/log/decouple.log` (root-only) and to the console, one line per action. There are three levels: `INFO` (what happened), `WARN` (a problem the run continues past) and `ERROR` (the run stopped).

## swiftDialog (optional)

Set `UseDialog=true` to show a progress dialog during the migration. Requires [swiftDialog](https://github.com/swiftDialog/swiftDialog) (`/usr/local/bin/dialog`) to be pre-installed, typically deployed via MDM as a `.pkg`.

The dialog shows a list item for each step with live status (running, success, warning), a progress bar, and a Close button that enables when the migration finishes. If swiftDialog is not installed or no user is at the console, the script runs headless (logging to the log file only).

```bash
sudo UseDialog=true EnrollmentUser="username" ./decouple.sh
```

## Testing

Tests for the parsing and filtering helpers, and for the detection logic against a stubbed mobile account and this Mac's real account (read-only). Run with the macOS bash:

```
/bin/bash tests/test_filters.sh
```

To compare a converted account with a fresh local account made in System Settings (read-only, needs root; the snapshots contain no password hashes or keys):

```
sudo tests/collect_state.sh freshuser > /tmp/fresh.txt
sudo tests/collect_state.sh <converted user> > /tmp/converted.txt
tests/compare_state.sh /tmp/fresh.txt /tmp/converted.txt
```

The compare leaves out what macOS sets through use rather than by account type: the Trash, APFS compression, the `com.apple.provenance` attribute, the `Library` hidden flag, `_writers_LinkedIdentity` (Apple Account) and record keys macOS adds with empty defaults.

Live result (macOS 27, FileVault on): a converted mobile account logged in and unlocked FileVault after a reboot.

### Live result

Tested on macOS 27 (FileVault on): a mobile AD account was converted, logged in, and unlocked
FileVault after a reboot. After a second run (to clean up files macOS services re-grouped at the
first login), the account matched a fresh local account. The only remaining differences were the
Local KDC entries (see the known limitation above) and a macOS daemon file — neither is an AD trace.

Run the script again after the user's first login to clean up files that macOS services give the
old AD group. An MDM can do this with a second deployment.

Test on a disposable Mac first. Version history is in git.

## Credits

- `MigrateUserHomeToDomainAcct.sh` by [Patrick Gallagher](https://twitter.com/patgmac), with guidance from [Lisa Davies](http://lisacherie.com/?p=239)
- `MigrateADMobileAccounttoLocalAccount.command` by [Rich Trouton](https://github.com/rtrouton/rtrouton_scripts/tree/main/rtrouton_scripts/migrate_ad_mobile_account_to_local_account), with contributions from Rick Lemmon (AD unbind process) and an anonymous reporter (macOS 10.14.4 ShadowHashData fix)
- `decouple.sh` by Noel Rodriguez-Lebron

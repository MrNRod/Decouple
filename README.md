# AD Account Migration

## Description

The AD Account Migration script is a utility script that allows you to migrate an Active Directory (AD) mobile account to a local account on macOS. This is useful for detaching a machine from AD while preserving the user's home directory and settings.

## Usage

### Terminal
To run the script manually via terminal, you must execute it as root and provide the target username via the `EnrollmentUser` environment variable:

```bash
sudo EnrollmentUser="username" ./MigrateADMobileAccountToLocalAccount.sh
```

### MDM (Mobile Device Management)
Upload the script to your MDM provider. You must configure the execution environment to set the `EnrollmentUser` variable to the username of the account to be migrated.
- **Variable Name:** `EnrollmentUser`
- **Value:** Set this to the console variable that matches your end user's name (e.g., `$EnrollmentUser` in Workspace ONE).

## Functionality

The script performs the following actions:

### Checks
- Verifies if the migration has already completed (checks for `/var/db/.mobile_to_local_migration_done`).
- Checks if the target user exists.
- Checks if the device is bound to Active Directory.
- Verifies if the target account is an AD mobile account.

### Changes
- **Unbinds AD:** Forcefully unbinds the Mac from Active Directory and removes AD from search paths.
- **Attribute Removal:** Removes AD-specific attributes from the user's local record (e.g., `cached_groups`, `OriginalNodeName`, `CopyTimestamp`).
- **Password Migration:** Removes only the Active Directory entries (`LocalCachedUser`, AD `Kerberosv5`) from `AuthenticationAuthority`. The local `ShadowHash`, `SecureToken` and local `@LKDC` Kerberos entry are kept.
- **Permissions:**
  - Removes stale ACLs from the home directory.
  - Resets ownership of the home directory to the user and the `staff` group.
  - Sets the home directory to mode 755 with a "deny delete" ACL for the `everyone` group, as on a fresh account.
- **Group Membership:**
  - Sets `PrimaryGroupID` to 20 (`staff`). The user is not listed in the `staff` group, matching a fresh account.
  - Adds the user to the `awagent_enrolled` group (Workspace ONE).
  - Removes `macadmin` from `awagent_enrolled` if present.
- **Admin Rights:** Automatically grants admin rights to the migrated user.

### Logging
- Logs all actions to `/var/log/mobile_to_local_migration.log`.
- Creates a marker file `/var/db/.mobile_to_local_migration_done` upon successful completion to prevent re-running.

## Fresh-account result

The converted account is made to match a fresh local account: the account record is backed up first
(without the password hash), a FileVault guard stops the run if unlock could break, and a final check
logs any difference from a fresh account.

Tests for the parsing and filtering helpers (read-only, run with the macOS bash):

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

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
- **Password Migration:** Modifies the `AuthenticationAuthority` to remove Kerberos and LocalCachedUser entries, effectively converting the password to a local shadow hash.
- **Permissions:**
  - Removes stale ACLs from the home directory.
  - Resets ownership of the home directory to the user and the `staff` group.
  - Sets "deny delete" permissions for the `everyone` group.
- **Group Membership:**
  - Adds the user to the `staff` group.
  - Adds the user to the `awagent_enrolled` group (Workspace ONE).
  - Removes `macadmin` from `awagent_enrolled` if present.
- **Admin Rights:** Automatically grants admin rights to the migrated user.

### Logging
- Logs all actions to `/var/log/mobile_to_local_migration.log`.
- Creates a marker file `/var/db/.mobile_to_local_migration_done` upon successful completion to prevent re-running.
## Version 1.8: fresh-account result

The converted account is made to match a fresh local account. See the Version 1.8 notes at the top of
the script. Highlights: only AD entries are removed from `AuthenticationAuthority` (`ShadowHash`,
`SecureToken` and the local `@LKDC` Kerberos entry are kept), the account isn't added to `staff`,
the home folder is 755 with the "everyone deny delete" ACL, the account record is backed up first
(no password hash), and a FileVault guard stops the run if unlock could break.

Tests for the parsing and filtering helpers (read-only, run with the macOS bash):

```
/bin/bash tests/test_filters.sh
```

This has not been run against a real AD-bound Mac. Test on a disposable one first.

# UI Operator Authentication

## Overview

The UI uses password-based authentication with a secure bootstrap workflow.

### First Boot

On first startup, a random 32-character password is generated automatically.

**Location:** `/etc/security-automation-go/secrets/admin_password`

**Permissions:** `0600` (read/write owner only)

**Storage:** Only the bcrypt hash is stored; the plaintext password is generated once and never saved.

### Bootstrap Password

The bootstrap password is active only on first login. After the operator changes the password, the bootstrap flag is cleared and the bootstrap password is no longer valid.

### Password Requirements

- Minimum 16 characters
- Must contain:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Digits (0-9)
  - Symbols (!@#$%^&*()_+-=[]{}|;:,.<>?)

### Login Flow

1. Operator visits `/login`
2. Enters password
3. System verifies against stored hash
4. If bootstrap password active: operator is forced to change password before accessing other pages
5. After password change: bootstrap flag is cleared, operator gains full access

### Password Rotation

To change the operator password:

1. Navigate to **Settings → Security → Change Password**
2. Enter current password
3. Enter new password (meeting complexity requirements)
4. Confirm new password
5. Submit

The system records a `password_changed` audit event with no password values logged.

## Security Considerations

- Passwords are never logged or displayed
- Only bcrypt hashes are stored
- Sessions are HTTP-only cookies with SameSite=Lax
- CSRF tokens are required for all state-changing operations
- Rate limiting is enforced on login attempts

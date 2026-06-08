# UI Operator Authentication

## Overview

The UI uses password-based authentication with a secure bootstrap workflow.

### First Boot

On first startup, a one-time UI setup secret is created automatically and used
for step 1 of the wizard. A separate one-time setup password is created for
step 2.

**Location:** `/var/lib/security-automation-go/runtime/ui_secret`

**Permissions:** `0600` (read/write owner only)

The UI setup secret is used once and then the browser session takes over. The
separate setup password is used in step 2 and is invalidated after the
operator sets a permanent password.

### Bootstrap Password

The bootstrap password is active only on first login. After the operator
changes the password, the bootstrap flag is cleared and the bootstrap password
is no longer valid.

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
- Only bcrypt hashes are stored for the permanent password
- Sessions are HTTP-only cookies with SameSite=Lax
- CSRF tokens are required for all state-changing operations
- Rate limiting is enforced on login attempts

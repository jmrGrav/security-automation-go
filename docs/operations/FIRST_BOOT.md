# First Boot Procedure

## Startup Sequence

1. **Instance Lock Check**: System acquires a PID lock file at `/run/security-automation-go.pid`
   - If another instance is running, startup fails with the running process's PID
   - Prevents multiple instances from running simultaneously

2. **Port Availability Check**: System verifies the UI port (default 6969) is available
   - If port is in use, startup fails with the occupying process's PID and name
   - Operator must resolve the port conflict or change the UI port

3. **Bootstrap Password Generation**: On first startup, a random password is generated
   - Password is 32 characters, cryptographically secure
   - Only the bcrypt hash is stored in `/etc/security-automation/secrets/admin_password`
   - Password is printed to stdout once; operator must capture it

4. **UI Server Starts**: The operator UI is now available at the configured address

## First Login

1. Operator navigates to the UI login page
2. Enters the bootstrap password
3. System verifies the password
4. Operator is redirected to **Settings → Security → Change Password**
5. Operator must change the password before accessing other pages
6. After successful password change:
   - Bootstrap flag is cleared
   - Operator gains full access to the UI
   - Old bootstrap password is no longer valid

## Subsequent Startups

1. Instance lock check (same as first boot)
2. Port availability check (same as first boot)
3. No password generation (already exists)
4. UI server starts with existing password configuration

## Failure Modes (Fail-Closed)

- **Instance lock held**: Startup fails, operator must stop the other instance manually
- **Port in use**: Startup fails, operator must change the port or resolve the conflict
- **Password file missing**: Startup fails, operator must restore the file or reinitialize
- **No operator action taken**: System remains offline until operator intervenes

## No Automatic Recovery

The system does **not**:
- Automatically kill other processes
- Automatically restart
- Use default passwords
- Bypass authentication

All recovery requires explicit operator action.

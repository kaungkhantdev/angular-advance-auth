# Forgot password and reset

Resetting a forgotten password by email. Admin invitations use the same
"set your password" link with a 72-hour lifetime. Code: [`auth.service.ts`](../../server/src/modules/auth/auth.service.ts) (`forgotPassword`, `resetPassword`, `sendInvite`).

![Forgot password and reset](images/05-password-reset.png)

```mermaid
flowchart TD
    A([User enters their email]) --> B["POST /api/auth/forgot-password"]
    B --> C{"Active user<br/>with this email?"}
    C -- No --> SAME(["Same response either way:<br/>if the account exists, we sent a link"])
    C -- Yes --> D["Create one_time_tokens row<br/>purpose: reset_password, 30 min<br/>(older links invalidated)"]
    D --> E["Email the reset link<br/>audit auth.password_reset_requested"]
    E --> SAME
    INV([Admin invites a new user]) --> INV1["Same token type, 72 h<br/>email: choose your password"]
    SAME --> F([User opens the link and<br/>enters a new password])
    INV1 --> F
    F --> G["POST /api/auth/reset-password"]
    G --> H{"New password contains<br/>name or email?"}
    H -- Yes --> R1(["400, link stays valid"])
    H -- No --> I{"Token valid, unused,<br/>not expired?"}
    I -- No --> R2(["400 Link invalid or expired"])
    I -- Yes --> J["Mark token used<br/>save new password hash<br/>clear lockout<br/>mark email verified"]
    J --> K["Revoke ALL sessions<br/>(every device signed out)"]
    K --> L["Audit auth.password_reset<br/>email: your password was changed"]
    L --> OK(["Done, user logs in<br/>with the new password"])
```

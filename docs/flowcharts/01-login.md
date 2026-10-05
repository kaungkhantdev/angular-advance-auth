# Login (password, lockout, MFA)

Signing in with email and password, including account lockout and the optional
second factor. Code: [`auth.service.ts`](../../server/src/modules/auth/auth.service.ts) (`login`, `completeMfaLogin`).

![Login (password, lockout, MFA)](images/01-login.png)

```mermaid
flowchart TD
    A([User submits email + password]) --> B["POST /api/auth/login<br/>per-IP limit: 20 per 15 min"]
    B --> C{"User with this<br/>email exists?"}
    C -- No --> C1["Verify against a dummy hash<br/>(same timing as a real check)"]
    C1 --> C2["Audit auth.login_failed<br/>reason: unknown_email"]
    C2 --> FAIL1(["401 Invalid email or password"])
    C -- Yes --> D{"locked_until<br/>in the future?"}
    D -- Yes --> LOCKED(["423 Locked<br/>Try again in N minutes"])
    D -- No --> E{"Password correct?<br/>(argon2id)"}
    E -- No --> F["failed_login_attempts + 1<br/>audit auth.login_failed"]
    F --> G{"5 failed attempts?"}
    G -- No --> FAIL1
    G -- Yes --> H["locked_until = now + 15 min<br/>reset counter to 0<br/>audit auth.account_locked<br/>email the user"]
    H --> FAIL1
    E -- Yes --> I{"status = active?"}
    I -- No --> DIS(["403 Account disabled"])
    I -- Yes --> J{"Email verified?"}
    J -- No --> UNV(["403 Verify your email first"])
    J -- Yes --> K["Re-hash password if<br/>argon2 settings changed"]
    K --> L{"MFA enabled?"}
    L -- No --> T["Issue tokens"]
    L -- Yes --> M["Return mfaToken<br/>(short-lived challenge JWT)"]
    M --> N([User enters 6-digit code<br/>or a recovery code])
    N --> O["POST /api/auth/login/mfa"]
    O --> P{"Challenge valid<br/>and not locked?"}
    P -- No --> FAIL2(["401 / 423"])
    P -- Yes --> Q{"TOTP code valid and not reused,<br/>or unused recovery code?"}
    Q -- No --> R["Counts toward the same<br/>5-attempt lockout"]
    R --> FAIL3(["401 Invalid authentication code"])
    Q -- Yes --> T
    T --> U["Create sessions row<br/>(stores SHA-256 of refresh secret)<br/>clear failed attempts and lock"]
    U --> V["Sign access JWT (15 min, contains sid)<br/>set refresh cookie: HttpOnly, SameSite"]
    V --> W(["200 accessToken + user<br/>audit auth.login"])
```

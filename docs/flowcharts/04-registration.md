# Registration and email verification

Self-service sign-up. The response never reveals whether an email is already
registered. Code: [`auth.service.ts`](../../server/src/modules/auth/auth.service.ts) (`register`, `verifyEmail`).

![Registration and email verification](images/04-registration.png)

```mermaid
flowchart TD
    A([User submits name, email, password]) --> B["POST /api/auth/register<br/>validate password strength"]
    B --> C{"Password contains<br/>name or email?"}
    C -- Yes --> R1(["400 Choose a different password"])
    C -- No --> D["Hash password (argon2id)<br/>before checking the email,<br/>so both paths take the same time"]
    D --> E{"Email already<br/>registered?"}
    E -- Yes --> F["Email the real owner:<br/>someone tried to sign up<br/>audit auth.register_duplicate"]
    F --> SAME(["Same success response<br/>check your inbox"])
    E -- No --> G["Create user +<br/>give the default 'user' role"]
    G --> H["Create one_time_tokens row<br/>purpose: verify_email, 24 h<br/>(older links invalidated)"]
    H --> I["Email the verification link"]
    I --> SAME
    SAME --> J([User clicks the link])
    J --> K["POST /api/auth/verify-email"]
    K --> L{"Token hash matches, unused,<br/>not expired?"}
    L -- No --> R2(["400 Link invalid or expired<br/>(can request a new one)"])
    L -- Yes --> M["Mark token used<br/>set email_verified_at<br/>audit auth.email_verified"]
    M --> OK(["Verified, user can now log in"])
```

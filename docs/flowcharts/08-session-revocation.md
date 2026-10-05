# Logout and session revocation

All the ways a session ends. Because every request checks the session row,
revocation takes effect immediately, not when the 15-minute access token expires.
Code: [`session.service.ts`](../../server/src/modules/auth/session.service.ts), [`auth.service.ts`](../../server/src/modules/auth/auth.service.ts).

![Logout and session revocation](images/08-session-revocation.png)

```mermaid
flowchart TD
    subgraph Triggers
        T1["User clicks Log out"]
        T2["User signs out a device<br/>or all other devices"]
        T3["Password changed<br/>(other devices)"]
        T4["Password reset by email<br/>(all devices)"]
        T5["2FA enabled<br/>(other devices)"]
        T6["Admin disables the user<br/>or revokes their sessions"]
        T7["Refresh token reuse detected"]
        T8["Refresh attempted after 7-day idle<br/>or the 30-day cap"]
    end
    T1 --> R
    T2 --> R
    T3 --> R
    T4 --> R
    T5 --> R
    T6 --> R
    T7 --> R
    T8 --> R
    R["sessions.revoked_at = now<br/>revoked_reason = why"] --> S["Refresh cookie cleared<br/>(on logout)"]
    R --> N([Next API request from that device])
    N --> C{"authenticate:<br/>session still active?"}
    C -- No --> X(["401 SESSION_REVOKED<br/>app signs the user out"])
    R --> BC["Logout in one tab is broadcast<br/>to other tabs (BroadcastChannel)"]
```

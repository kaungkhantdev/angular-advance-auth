# API request authorization

What happens on every authenticated API call, from the Angular app to the
permission and ownership checks. Code: [`auth.interceptor.ts`](../../client/src/app/core/auth/auth.interceptor.ts),
[`middleware/auth.ts`](../../server/src/middleware/auth.ts), [`article.policy.ts`](../../server/src/modules/articles/article.policy.ts).

![API request authorization](images/02-request-authorization.png)

```mermaid
flowchart TD
    A([Angular makes an API call]) --> B["Interceptor adds<br/>Authorization: Bearer access token<br/>(only for /api URLs)"]
    B --> C["Server: authenticate middleware"]
    C --> D{"JWT signature, issuer,<br/>audience and expiry valid?"}
    D -- Expired --> R1(["401 TOKEN_EXPIRED"])
    D -- Invalid --> R2(["401 INVALID_TOKEN"])
    D -- Valid --> E{"Session sid still active?<br/>(not revoked, not past 30-day cap)"}
    E -- No --> R3(["401 SESSION_REVOKED"])
    E -- Yes --> F["loadPrincipal: read the user's roles<br/>and permissions from the database<br/>(fresh on every request)"]
    F --> G{"Route guard:<br/>requirePermission('articles:publish')"}
    G -- Missing --> R4(["403 Forbidden"])
    G -- Has it --> H{"Needs a per-record check?<br/>(e.g. update:own vs update:any)"}
    H -- No --> OK(["200 OK"])
    H -- Yes --> I{"articlePolicy:<br/>has :any, or has :own<br/>and owns this record?"}
    I -- No --> R5(["403 You can only edit your own articles"])
    I -- Yes --> OK

    R1 --> X["Interceptor: refresh once<br/>(see Token refresh)"]
    R2 --> X
    X --> Y{"Refresh worked?"}
    Y -- Yes --> Z["Replay the original request<br/>with the new token"]
    Y -- No --> OUT(["Sign out: session expired"])
    R3 --> OUT2(["Sign out: session revoked"])
```

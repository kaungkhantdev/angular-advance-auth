# Flowcharts

How the main authentication and authorization flows work, step by step. Each page has
the Mermaid source (renders on GitHub) and shows the rendered image.

```
flowcharts/
├── 01-login.md …        pages (text + chart)
├── images/              rendered PNG and SVG files
└── src/                 Mermaid chart sources (.mmd)
```

For the database tables these flows read and write, see the [ERD](../ERD.md).

| # | Flow | Image |
|---|---|---|
| 01 | [Login (password, lockout, MFA)](01-login.md) | [PNG](images/01-login.png) · [SVG](images/01-login.svg) |
| 02 | [API request authorization](02-request-authorization.md) | [PNG](images/02-request-authorization.png) · [SVG](images/02-request-authorization.svg) |
| 03 | [Token refresh (rotation and reuse detection)](03-token-refresh.md) | [PNG](images/03-token-refresh.png) · [SVG](images/03-token-refresh.svg) |
| 04 | [Registration and email verification](04-registration.md) | [PNG](images/04-registration.png) · [SVG](images/04-registration.svg) |
| 05 | [Forgot password and reset](05-password-reset.md) | [PNG](images/05-password-reset.png) · [SVG](images/05-password-reset.svg) |
| 06 | [Two-factor (TOTP) setup](06-mfa-setup.md) | [PNG](images/06-mfa-setup.png) · [SVG](images/06-mfa-setup.svg) |
| 07 | [Assigning roles to a user](07-role-assignment.md) | [PNG](images/07-role-assignment.png) · [SVG](images/07-role-assignment.svg) |
| 08 | [Logout and session revocation](08-session-revocation.md) | [PNG](images/08-session-revocation.png) · [SVG](images/08-session-revocation.svg) |

## Editing a chart

Each chart's source is in `src/<name>.mmd` (the same Mermaid code as in the `.md` page).
After editing, update the `.md` page to match and re-render the images:

```bash
npx @mermaid-js/mermaid-cli -i src/01-login.mmd -o images/01-login.png -s 2 -b white
npx @mermaid-js/mermaid-cli -i src/01-login.mmd -o images/01-login.svg -b white
```

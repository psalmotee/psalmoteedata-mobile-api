# PsalmoteeData Mobile API

Version: 0.1.0

This is an initial mobile-authentication plugin for the PsalmoteeData React Native app.

## Included endpoints

Base URL:
`https://YOUR-DOMAIN/wp-json/psalmoteedata-mobile/v1`

- `POST /login` — authenticate an existing WordPress + VTU Press account and issue a random bearer token.
- `GET /me` — return the authenticated WordPress user's basic profile.
- `POST /logout` — revoke the current bearer token.

## Authentication

Send the token in this header for protected routes:

`Authorization: Bearer YOUR_ACCESS_TOKEN`

Tokens are generated using PHP's cryptographically secure `random_bytes()`. Only a SHA-256 hash is stored in the database. Tokens expire after 30 days. Multiple devices can have separate tokens.

The login endpoint mirrors the existing VTU Press login checks for:
- a matching WordPress user,
- a synchronized VTU Press user record,
- optional VTU Press email verification.

It does not change or replace the existing website login or registration flow.

## Installation

1. Back up the WordPress site and database.
2. In WordPress Admin, open Plugins > Add New Plugin > Upload Plugin.
3. Upload `psalmoteedata-mobile-api.zip` and activate it.
4. If your host blocks ZIP uploads, extract it and upload the `psalmoteedata-mobile-api` folder into `wp-content/plugins/`, then activate it in WordPress Admin.
5. Confirm the site uses HTTPS.

## Initial endpoint tests

Login:

`POST https://YOUR-DOMAIN/wp-json/psalmoteedata-mobile/v1/login`

JSON body:

```json
{
  "username": "YOUR_TEST_USERNAME_OR_EMAIL",
  "password": "YOUR_TEST_PASSWORD"
}
```

Profile:

`GET https://YOUR-DOMAIN/wp-json/psalmoteedata-mobile/v1/me`

Header:

`Authorization: Bearer TOKEN_RETURNED_BY_LOGIN`

Logout:

`POST https://YOUR-DOMAIN/wp-json/psalmoteedata-mobile/v1/logout`

Header:

`Authorization: Bearer TOKEN_RETURNED_BY_LOGIN`

## Important

- Test with your own account, not another customer's account.
- Never commit passwords or returned access tokens to GitHub.
- Do not send login credentials over HTTP. Use HTTPS only.
- This is the first authentication milestone only. It does not yet expose wallet, transactions, KYC, API-key management, virtual accounts, or service-purchase endpoints.
- Before production use, review hosting/WAF rate limits and test the endpoints on a staging site if one is available.

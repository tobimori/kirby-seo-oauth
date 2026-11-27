# Kirby SEO OAuth proxy

A Cloudflare Worker that connects [Kirby SEO](https://github.com/tobimori/kirby-seo) to Google Search Console. With it, sites with a Kirby SEO license can connect Search Console without their own Google Cloud project.

The proxy holds the Google OAuth client secret. It does not store data and never sees Search Console data. The source is public, so you can check what it does with your data.

## How it works

1. The Panel sends `POST /gsc/authorize` with the license, the site callback URL, a PKCE challenge, and a CSRF state. The proxy checks the license and returns the Google consent URL
2. Google redirects the browser to `GET /gsc/callback`. The proxy sends the browser back to the site with the authorization code
3. The site server sends `POST /gsc/token` with the code and the PKCE verifier. The proxy adds the client secret, gets the tokens from Google, and returns them in the response
4. The site stores the tokens. To refresh the access token, the site sends `POST /gsc/token` with the refresh token
5. The site calls the Search Console API directly with the access token. To disconnect, the site revokes the token directly at Google

The proxy signs the site callback URL and state into the Google `state` parameter (an HS256 JWT that expires after 10 minutes), so it does not need a database. PKCE makes sure that only the site that started the sign-in can exchange the code.

### Licenses

The proxy checks the signed license file from `site/config/.tm-licenses` with the public key of the license server. It does not call the license server. A license is valid if:

- The key starts with `KS-`
- The signature is valid
- It has an `expires` date in the future. Kirby SEO gets a new copy of the license before it expires. Offline licenses have no expiry date, so they cannot use the proxy
- For `/gsc/authorize`: the callback URL is `/__seo/gsc/callback` on the site the license is assigned to

## Privacy

The proxy:

- Requests only the `https://www.googleapis.com/auth/webmasters.readonly` scope
- Stores nothing. It has no database, no KV, and no cookies
- Does not log request bodies or URLs. Cloudflare invocation logs are off, because the callback URL contains the authorization code
- Receives the license file (which includes the license email address), the site URL, the OAuth code, and the tokens. It uses them only for the request and forwards the code and tokens only to Google
- Never sees Search Console data. The site gets it directly from Google

When an editor connects Search Console, their browser goes through `/gsc/callback`, so Cloudflare receives their IP address and user agent.

## API

Errors use the [OAuth 2.0 error format](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2): `{ "error": "...", "error_description": "..." }`.

| Endpoint              | Request                                                                      | Response                                                                       |
| --------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `POST /gsc/authorize` | JSON: `license`, `redirect_uri`, `state`, `code_challenge` (S256)            | `{ "url": "..." }`, `400 invalid_request`, `403 invalid_license`               |
| `GET /gsc/callback`   | Query from Google: `state`, `code` or `error`                                | `302` to `redirect_uri` with `state` and `code` or `error`                     |
| `POST /gsc/token`     | JSON: `grant_type: "authorization_code"`, `license`, `code`, `code_verifier` | Google token response, `403 invalid_license`, `400` with the Google error code |
|                       | JSON: `grant_type: "refresh_token"`, `license`, `refresh_token`              | The same                                                                       |

If Google rejects a refresh token, the error is `invalid_grant`. Then the site must connect again.

## Deployment

1. Create a Google Cloud project and enable the Google Search Console API
2. In Google Auth Platform, set the audience to External, add the `webmasters.readonly` scope, and publish the app. In Testing mode, refresh tokens expire after 7 days
3. Create an OAuth client of type Web application. Add `https://<worker host>/gsc/callback` as the only authorized redirect URI
4. Set the secrets:

   ```sh
   pnpm wrangler secret put GOOGLE_CLIENT_ID
   pnpm wrangler secret put GOOGLE_CLIENT_SECRET
   # base64url, at least 32 bytes
   openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' | pnpm wrangler secret put STATE_SECRET
   ```

5. Deploy with `pnpm deploy`

## Development

```sh
pnpm install
cp .dev.vars.example .dev.vars
pnpm dev
pnpm check
```

## License

[MIT](LICENSE)

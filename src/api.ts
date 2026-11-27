import { Schema } from "effect";
import {
  HttpApi,
  HttpApiEndpoint,
  HttpApiGroup,
  HttpApiMiddleware,
  HttpApiSchema,
} from "effect/http-api";

// RFC 7636: the S256 challenge is an unpadded base64url SHA-256 hash, the verifier has 43 to 128 unreserved characters
const CodeChallenge = Schema.String.check(Schema.isPattern(/^[\w-]{43}$/));
const CodeVerifier = Schema.String.check(Schema.isPattern(/^[\w.~-]{43,128}$/));

/**
 * The signed license file that Kirby SEO stores in `site/config/.tm-licenses`
 */
export const License = Schema.Struct({
  license: Schema.String,
  plugin: Schema.String,
  edition: Schema.String,
  allowOfflineUse: Schema.Boolean,
  purchasedOn: Schema.String,
  assignedUrl: Schema.String,
  email: Schema.String,
  expires: Schema.optionalKey(Schema.String),
  signature: Schema.Uint8ArrayFromBase64,
});

export type License = typeof License.Type;

export const Tokens = Schema.Struct({
  access_token: Schema.String,
  expires_in: Schema.Int,
  refresh_token: Schema.optionalKey(Schema.String),
  scope: Schema.String,
  token_type: Schema.String,
});

export type Tokens = typeof Tokens.Type;

// errors use the OAuth 2.0 error response format (RFC 6749, section 5.2)

export class InvalidRequest extends Schema.TaggedError<InvalidRequest>()(
  "InvalidRequest",
  { error: Schema.tag("invalid_request"), error_description: Schema.String },
  { httpApiStatus: 400 },
) {}

export class InvalidLicense extends Schema.TaggedError<InvalidLicense>()(
  "InvalidLicense",
  { error: Schema.tag("invalid_license"), error_description: Schema.String },
  { httpApiStatus: 403 },
) {}

/**
 * An error response from the Google token endpoint, such as `invalid_grant` for a revoked refresh token
 */
export class GoogleError extends Schema.TaggedError<GoogleError>()(
  "GoogleError",
  { error: Schema.String, error_description: Schema.String },
  { httpApiStatus: 400 },
) {}

export class GoogleUnavailable extends Schema.TaggedError<GoogleUnavailable>()(
  "GoogleUnavailable",
  { error: Schema.tag("temporarily_unavailable"), error_description: Schema.String },
  { httpApiStatus: 502 },
) {}

export class OAuthValidationError extends HttpApiMiddleware.Service<OAuthValidationError>()(
  "kirby-seo-oauth/OAuthValidationError",
  { error: InvalidRequest },
) {}

export class GscApi extends HttpApiGroup.make("gsc")
  .add(
    HttpApiEndpoint.post("authorize", "/authorize", {
      payload: Schema.Struct({
        license: License,
        redirect_uri: Schema.URLFromString,
        state: Schema.NonEmptyString.check(Schema.isMaxLength(512)),
        code_challenge: CodeChallenge,
      }),
      success: Schema.Struct({ url: Schema.String }),
      error: [InvalidRequest, InvalidLicense],
    }),
    HttpApiEndpoint.get("callback", "/callback", {
      query: {
        state: Schema.NonEmptyString.check(Schema.isMaxLength(8192)),
        code: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(4096))),
        error: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(256))),
      },
      success: HttpApiSchema.WithHeaders(HttpApiSchema.Empty(302), { location: Schema.String }),
      error: InvalidRequest,
    }),
    HttpApiEndpoint.post("token", "/token", {
      payload: Schema.Union([
        Schema.Struct({
          grant_type: Schema.Literal("authorization_code"),
          license: License,
          code: Schema.NonEmptyString.check(Schema.isMaxLength(4096)),
          code_verifier: CodeVerifier,
        }),
        Schema.Struct({
          grant_type: Schema.Literal("refresh_token"),
          license: License,
          refresh_token: Schema.NonEmptyString.check(Schema.isMaxLength(4096)),
        }),
      ]),
      success: Tokens,
      error: [InvalidLicense, GoogleError, GoogleUnavailable],
    }),
  )
  .prefix("/gsc")
  .middleware(OAuthValidationError) {}

export class Api extends HttpApi.make("kirby-seo-oauth").add(GscApi) {}

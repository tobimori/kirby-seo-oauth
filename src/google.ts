import { Config, Context, Effect, Layer, Redacted, Schema } from "effect";
import { FetchHttpClient, HttpClient, HttpClientRequest, HttpClientResponse } from "effect/http";
import { GoogleError, GoogleUnavailable, Tokens } from "./api.ts";

const AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const SCOPE = "https://www.googleapis.com/auth/webmasters.readonly";

const ErrorResponse = Schema.Struct({
  error: Schema.String,
  error_description: Schema.optionalKey(Schema.String),
});

export class Google extends Context.Service<
  Google,
  {
    readonly authorizationUrl: (options: {
      readonly redirectUri: string;
      readonly state: string;
      readonly codeChallenge: string;
    }) => string;
    readonly exchangeCode: (options: {
      readonly code: string;
      readonly codeVerifier: string;
      readonly redirectUri: string;
    }) => Effect.Effect<Tokens, GoogleError | GoogleUnavailable>;
    readonly refresh: (
      refreshToken: string,
    ) => Effect.Effect<Tokens, GoogleError | GoogleUnavailable>;
  }
>()("kirby-seo-oauth/Google") {
  static readonly layer = Layer.effect(
    Google,
    Effect.gen(function* () {
      const clientId = yield* Config.NonEmptyString("GOOGLE_CLIENT_ID");
      const clientSecret = yield* Config.schema(
        Schema.Redacted(Schema.NonEmptyString),
        "GOOGLE_CLIENT_SECRET",
      );
      const client = (yield* HttpClient.HttpClient).pipe(
        HttpClient.timeout("10 seconds"),
        HttpClient.withScope,
      );

      const unavailable = new GoogleUnavailable({
        error_description: "The Google token endpoint is not available. Try again later",
      });
      const failUnavailable = (message: string, ...args: ReadonlyArray<unknown>) =>
        Effect.logWarning(message, ...args).pipe(Effect.andThen(Effect.fail(unavailable)));

      const tokenRequest = Effect.fn("Google.tokenRequest")(
        function* (params: Readonly<Record<string, string>>) {
          const response = yield* HttpClientRequest.post(TOKEN_URL).pipe(
            HttpClientRequest.acceptJson,
            HttpClientRequest.bodyUrlParams({
              client_id: clientId,
              client_secret: Redacted.value(clientSecret),
              ...params,
            }),
            client.execute,
          );

          if (response.status >= 200 && response.status < 300) {
            return yield* HttpClientResponse.schemaBodyJson(Tokens)(response);
          }

          if (response.status === 429) {
            return yield* failUnavailable("Google token endpoint rate-limited the request (429)");
          }

          if (response.status >= 400 && response.status < 500) {
            const body = yield* HttpClientResponse.schemaBodyJson(ErrorResponse)(response);
            if (
              response.status === 401 ||
              body.error === "invalid_client" ||
              body.error === "unauthorized_client"
            ) {
              return yield* failUnavailable(
                `Google token endpoint rejected the OAuth client credentials (${body.error})`,
              );
            }
            return yield* new GoogleError({
              error: body.error,
              error_description: body.error_description ?? body.error,
            });
          }

          return yield* failUnavailable(`Google token endpoint responded with ${response.status}`);
        },
        Effect.scoped,
        Effect.catchTags({
          HttpClientError: (error) =>
            failUnavailable("Google token request failed", error.reason._tag),
          SchemaError: () => failUnavailable("Google token endpoint returned an unexpected body"),
        }),
      );

      return Google.of({
        authorizationUrl: ({ redirectUri, state, codeChallenge }) => {
          const url = new URL(AUTH_URL);
          url.search = new URLSearchParams({
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: "code",
            scope: SCOPE,
            access_type: "offline",
            prompt: "consent",
            state,
            code_challenge: codeChallenge,
            code_challenge_method: "S256",
          }).toString();
          return url.toString();
        },
        exchangeCode: ({ code, codeVerifier, redirectUri }) =>
          tokenRequest({
            grant_type: "authorization_code",
            code,
            code_verifier: codeVerifier,
            redirect_uri: redirectUri,
          }),
        refresh: (refreshToken) =>
          tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken }),
      });
    }),
  ).pipe(Layer.provide(FetchHttpClient.layer));
}

import { ByteSize, Effect, Layer } from "effect";
import {
  HttpEffect,
  HttpIncomingMessage,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/http";
import { HttpApiBuilder, HttpApiMiddleware, HttpApiSchema } from "effect/http-api";
import { Api, InvalidRequest, OAuthValidationError } from "./api.ts";
import { Google } from "./google.ts";
import { checkRedirectUri, Licenses } from "./license.ts";
import { OAuthState } from "./state.ts";

const MAX_BODY_SIZE = ByteSize.kibibytes(64);
const SECURITY_HEADERS = {
  "cache-control": "no-store",
  pragma: "no-cache",
  "referrer-policy": "no-referrer",
} as const;

// Google only accepts redirect URIs registered for the OAuth client, so all sites share this one
const callbackUrl = Effect.map(HttpServerRequest.HttpServerRequest, (request) =>
  new URL("/gsc/callback", request.originalUrl).toString(),
);

const OAuthValidationErrorLive = HttpApiMiddleware.layerSchemaErrorTransform(
  OAuthValidationError,
  (error) =>
    error.kind === "Body" || error.kind === "ResponseHeaders"
      ? Effect.fail(error)
      : Effect.fail(
          new InvalidRequest({
            error_description:
              "The request is missing a required parameter or includes an invalid parameter value",
          }),
        ),
);

const SecurityMiddleware = HttpRouter.middleware(
  (effect) =>
    effect.pipe(
      Effect.provideService(HttpIncomingMessage.MaxBodySize, MAX_BODY_SIZE),
      HttpEffect.withPreResponseHandler((_request, response) =>
        Effect.succeed(HttpServerResponse.setHeaders(response, SECURITY_HEADERS)),
      ),
    ),
  { global: true },
);

const GscHandlers = HttpApiBuilder.group(
  Api,
  "gsc",
  Effect.fn(function* (handlers) {
    const google = yield* Google;
    const licenses = yield* Licenses;
    const oauthState = yield* OAuthState;

    return handlers.handleAll({
      authorize: Effect.fn("gsc.authorize")(function* ({ payload }) {
        yield* licenses.verify(payload.license);
        const redirectUri = yield* checkRedirectUri(payload.license, payload.redirect_uri);
        const state = yield* oauthState.sign({
          redirectUri: redirectUri.toString(),
          state: payload.state,
        });

        return {
          url: google.authorizationUrl({
            redirectUri: yield* callbackUrl,
            state,
            codeChallenge: payload.code_challenge,
          }),
        };
      }),
      callback: Effect.fn("gsc.callback")(function* ({ query }) {
        const target = yield* oauthState.verify(query.state);
        const location = new URL(target.redirectUri);
        location.searchParams.set("state", target.state);
        if (query.code) {
          location.searchParams.set("code", query.code);
        } else {
          location.searchParams.set("error", query.error || "server_error");
        }

        return HttpApiSchema.withHeaders({
          body: undefined,
          headers: { location: location.toString() },
        });
      }),
      token: Effect.fn("gsc.token")(function* ({ payload }) {
        yield* licenses.verify(payload.license);

        if (payload.grant_type === "refresh_token") {
          return yield* google.refresh(payload.refresh_token);
        }

        return yield* google.exchangeCode({
          code: payload.code,
          codeVerifier: payload.code_verifier,
          redirectUri: yield* callbackUrl,
        });
      }),
    });
  }),
);

export const ApiLive = Layer.mergeAll(
  HttpApiBuilder.layer(Api).pipe(
    Layer.provide(GscHandlers),
    Layer.provide(OAuthValidationErrorLive),
    Layer.provide([Google.layer, Licenses.layer, OAuthState.layer]),
  ),
  SecurityMiddleware,
);

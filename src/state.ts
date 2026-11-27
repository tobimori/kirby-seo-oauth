import { Clock, Config, Context, Effect, Layer, Redacted, Schema } from "effect";
import { Mac, SecureRandom } from "effect/crypto";
import { Jwk, Jwt } from "effect/jose";
import { InvalidRequest } from "./api.ts";

const TTL_SECONDS = 10 * 60;

const Claims = Schema.Struct({
  redirect_uri: Schema.String,
  state: Schema.String,
  exp: Schema.Int,
});

interface Target {
  readonly redirectUri: string;
  readonly state: string;
}

/**
 * Carries the site's redirect URI and state through Google as a signed JWT, so the proxy needs no storage
 */
export class OAuthState extends Context.Service<
  OAuthState,
  {
    readonly sign: (target: Target) => Effect.Effect<string>;
    readonly verify: (token: string) => Effect.Effect<Target, InvalidRequest>;
  }
>()("kirby-seo-oauth/OAuthState") {
  static readonly layer = Layer.effect(
    OAuthState,
    Effect.gen(function* () {
      const mac = yield* Mac.Mac;
      const secret = yield* Config.Redacted("STATE_SECRET");
      const key = yield* Jwk.importSecret(
        Redacted.make({ kty: "oct", k: Redacted.value(secret) } as const),
        "HS256",
      );

      const sign = Effect.fn("OAuthState.sign")(function* (target: Target) {
        const now = yield* Clock.currentTimeMillis;
        const token = yield* Jwt.sign(
          Claims,
          {
            redirect_uri: target.redirectUri,
            state: target.state,
            exp: Math.floor(now / 1000) + TTL_SECONDS,
          },
          key,
        ).pipe(Effect.provideService(Mac.Mac, mac), Effect.orDie);

        return Redacted.value(token);
      });

      const verify = Effect.fn("OAuthState.verify")(function* (token: string) {
        const { claims } = yield* Jwt.verify(Claims, token, key, { requiredClaims: ["exp"] }).pipe(
          Effect.provideService(Mac.Mac, mac),
          Effect.mapError(
            () =>
              new InvalidRequest({
                error_description: "The sign-in took too long or the state is invalid. Try again",
              }),
          ),
        );

        return { redirectUri: claims.redirect_uri, state: claims.state };
      });

      return OAuthState.of({ sign, verify });
    }),
  ).pipe(Layer.provide(Mac.layerWebCrypto), Layer.provide(SecureRandom.layerWebCrypto));
}

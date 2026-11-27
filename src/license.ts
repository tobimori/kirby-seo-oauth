import { Context, DateTime, Effect, Layer, Option, Schema } from "effect";
import { KeyFormat, SecureRandom, Signature } from "effect/crypto";
import { InvalidLicense, InvalidRequest, type License } from "./api.ts";

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt+adZ2ODZhDtkBriVnN8
9noQfD6v1CTJsekknHX+MdcolGb5ydXrfwNCxDXJ399RlY/JGqJTmnvy8rned6S9
5sIR6FowFWmJ+3lrzn0NbqRt1FRMDSNdg99priNUkKRkKajvBiOylRGXlniAQ540
Eh6bm7BO8XMwyLMpuNAM7FOy55BmU0hzCovlVdOLjQM54HpYf8sV8+k37ysVS+5W
u+TgFIg2HCj804raXo5mhZ3bMIyoK3YJ5oXVRa7j6zuE/YF2Gao8j684Br7sYefV
qsyxtl3BRdwXaB98sSQIX4OQIbheqF1ftpDd+TaII6Q0qX+PlyGJb2MCDjAvyLxY
lwIDAQAB
-----END PUBLIC KEY-----`;

const PREFIX = "KS-";
const CALLBACK_PATH = "/__seo/gsc/callback";
const MAX_REDIRECT_URI_LENGTH = 2048;
const LOCAL_HOST = /^(?:localhost|127\.0\.0\.1|\[::1\]|::1|.+\.(?:localhost|test|local))$/i;

const encoder = new TextEncoder();
const decodeUrlOption = Schema.decodeUnknownOption(Schema.URLFromString);

const parseAssignedUrl = (raw: string): Option.Option<URL> => {
  const trimmed = raw.trim();
  return decodeUrlOption(/^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`).pipe(
    Option.filter((url) => url.protocol === "https:" || url.protocol === "http:"),
  );
};

/**
 * Normalizes a parsed URL like the license server: testing subdomains and `www.` are removed
 * only for installations at the root of the domain
 */
const normalizeSite = (url: URL, pathname = url.pathname): string => {
  const host = url.host.toLowerCase();
  const path = pathname.replace(/\/+$/, "").toLowerCase();

  return path !== "" ? host + path : host.replace(/^(?:www|dev|test|staging)\./, "");
};

/**
 * Checks that the redirect URI is the Kirby SEO callback of the site the license is assigned to
 */
export const checkRedirectUri = Effect.fnUntraced(function* (license: License, url: URL) {
  const assigned = parseAssignedUrl(license.assignedUrl);
  const basePath = url.pathname.slice(0, -CALLBACK_PATH.length);

  if (
    Option.isNone(assigned) ||
    url.href.length > MAX_REDIRECT_URI_LENGTH ||
    (url.protocol !== "https:" &&
      !(
        url.protocol === "http:" &&
        (LOCAL_HOST.test(url.hostname) || assigned.value.protocol === "http:")
      )) ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    !url.pathname.endsWith(CALLBACK_PATH) ||
    basePath.endsWith("/") ||
    normalizeSite(url, basePath) !== normalizeSite(assigned.value)
  ) {
    return yield* new InvalidRequest({
      error_description: `The redirect URI must be ${CALLBACK_PATH} on the site the license is assigned to`,
    });
  }

  return url;
});

export class Licenses extends Context.Service<
  Licenses,
  {
    readonly verify: (license: License) => Effect.Effect<void, InvalidLicense>;
  }
>()("kirby-seo-oauth/Licenses") {
  static readonly layer = Layer.effect(
    Licenses,
    Effect.gen(function* () {
      const signatures = yield* Signature.Signature;
      // Decoded lazily so layer construction stays synchronous for Workers module scope
      const getPublicKey = yield* Effect.cached(
        KeyFormat.decodePublic(
          KeyFormat.pem(KeyFormat.spki),
          Signature.rsaPkcs1v15Sha256,
          PUBLIC_KEY,
        ),
      );

      const verify = Effect.fn("Licenses.verify")(function* (license: License) {
        if (!license.license.trim().toUpperCase().startsWith(PREFIX)) {
          return yield* new InvalidLicense({
            error_description: "This is not a Kirby SEO license",
          });
        }

        if (license.expires === undefined) {
          return yield* new InvalidLicense({
            error_description:
              "Licenses without an expiry date, such as offline licenses, cannot use the proxy. Use your own Google OAuth credentials instead",
          });
        }

        // the license server signs the PHP JSON encoding of these fields in this order
        const payload = JSON.stringify({
          license: license.license,
          plugin: license.plugin,
          edition: license.edition,
          allowOfflineUse: license.allowOfflineUse,
          purchasedOn: license.purchasedOn,
          assignedUrl: license.assignedUrl,
          email: license.email,
          expires: license.expires,
        });

        const publicKey = yield* getPublicKey.pipe(Effect.orDie);
        const valid = yield* signatures
          .verify(publicKey, license.signature, encoder.encode(payload))
          .pipe(Effect.orDie);
        if (!valid) {
          return yield* new InvalidLicense({
            error_description: "The license signature is invalid",
          });
        }

        const expires = DateTime.make(license.expires);
        if (Option.isNone(expires) || (yield* DateTime.isPast(expires.value))) {
          return yield* new InvalidLicense({
            error_description: "The license has expired. Open the Panel to renew it",
          });
        }
      });

      return Licenses.of({ verify });
    }),
  ).pipe(Layer.provide(Signature.layerWebCrypto), Layer.provide(SecureRandom.layerWebCrypto));
}

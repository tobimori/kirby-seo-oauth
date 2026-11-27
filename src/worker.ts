import { env } from "cloudflare:workers";
import { ConfigProvider, Layer, Scheduler } from "effect";
import { HttpRouter, HttpServer } from "effect/http";
import { ApiLive } from "./http.ts";

const SyncScheduler = Layer.succeed(Scheduler.Scheduler, new Scheduler.MixedScheduler("sync"));

const app = HttpRouter.toWebHandler(
  ApiLive.pipe(
    Layer.provide(HttpServer.layerServices),
    Layer.provide(ConfigProvider.layer(ConfigProvider.fromUnknown(env))),
    Layer.provideMerge(SyncScheduler),
  ),
  // the request logger would log the authorization code in the callback URL
  { disableLogger: true },
);

export default {
  fetch: (request) => app.handler(request),
} satisfies ExportedHandler;

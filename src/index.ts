import path from "path";
import { Server } from "http";

import set from "lodash/set";
import Koa, { Next, Context } from "koa";
import render from "koa-ejs";
import helmet from "koa-helmet";
import mount from "koa-mount";

import { Provider, Configuration } from "oidc-provider";

import Account from "./support/account";
import configuration from "./support/configuration";
import routes from "./routes";

const { PORT = 3000, ISSUER = `http://localhost:${PORT}` } = process.env;

const app: Koa = new Koa();
app.use(helmet());
render(app, {
  cache: false,
  viewExt: "ejs",
  layout: "_layout",
  root: path.join(__dirname, "views")
});

if (process.env.NODE_ENV === "production") {
  app.proxy = true;
  set(configuration, "cookies.short.secure", true);
  set(configuration, "cookies.long.secure", true);

  app.use(async (ctx: Context, next: Next) => {
    if (ctx.secure) {
      await next();
    } else if (ctx.method === "GET" || ctx.method === "HEAD") {
      ctx.redirect(ctx.href.replace(/^http:\/\//i, "https://"));
    } else {
      ctx.body = {
        error: "invalid_request",
        error_description: "do yourself a favor and only use https"
      };
      ctx.status = 400;
    }
  });
}

let server: Server;
(async () => {
  let adapter;
  if (process.env.MONGODB_URI) {
    adapter = require("./adapters/mongodb"); // eslint-disable-line global-require
    await adapter.connect();
  }

  const provider = new Provider(ISSUER, {
    adapter,
    findAccount: Account.findAccount,
    ...configuration
  } as Configuration);

  provider.use(helmet());

  app.use(routes(provider).routes());
  app.use(mount(provider.app));
  server = app.listen(PORT, () => {
    console.log(
      `application is listening on port ${PORT}, check its /.well-known/openid-configuration`
    );
  });
})().catch(err => {
  if (server && server.listening) server.close();
  console.error(err);
  process.exitCode = 1;
});

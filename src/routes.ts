import { strict as assert } from "assert";
import querystring from "querystring";
import crypto from "crypto";
import { inspect } from "util";
import isEmpty from "lodash/isEmpty";

import { Context, Next, ParameterizedContext } from "koa";

import bodyParser from "koa-body";
import Router from "koa-router";

import Account from "./support/account";

import Provider, {
  InteractionResults,
  KoaContextWithOIDC
} from "oidc-provider";

const keys = new Set();
const debug = (obj: any) =>
  querystring.stringify(
    Object.entries(obj).reduce(
      (acc: { [key: string]: string }, [key, value]) => {
        keys.add(key);
        if (isEmpty(value)) return acc;
        acc[key] = inspect(value, { depth: null });
        return acc;
      },
      {}
    ),
    "<br/>",
    ": ",
    {
      encodeURIComponent(value) {
        return keys.has(value) ? `<strong>${value}</strong>` : value;
      }
    }
  );

async function renderError(ctx: Context, out: any, error: Error) {
  ctx.type = "html";
  ctx.body = `<!DOCTYPE html>
<head>
  <meta charset="utf-8">
  <title>oops! something went wrong</title>
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta http-equiv="x-ua-compatible" content="ie=edge">
  <style>
    @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1{font-weight:100;text-align:center;font-size:2.3em}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}pre{white-space:pre-wrap;white-space:-moz-pre-wrap;white-space:-pre-wrap;white-space:-o-pre-wrap;word-wrap:break-word;margin:0 0 0 1em;text-indent:-1em}
  </style>
</head>
<body>
  <div class="container">
    <h1>oops! something went wrong</h1>
    ${Object.entries(out)
      .map(([key, value]) => `<pre><strong>${key}</strong>: ${value}</pre>`)
      .join("")}
  </div>
</body>
</html>`;
}

export default (provider: Provider) => {
  const router = new Router();
  const {
    constructor: {
      errors: { SessionNotFound }
    }
  } = provider as any;

  router.use(async (ctx: KoaContextWithOIDC, next: Next) => {
    ctx.set("Pragma", "no-cache");
    ctx.set("Cache-Control", "no-cache, no-store");
    try {
      await next();
    } catch (err) {
      if (err instanceof SessionNotFound) {
        ctx.status = err.status;
        const { message: error, error_description } = err;
        renderError(ctx, { error, error_description }, err);
      } else {
        throw err;
      }
    }
  });

  router.get("/interaction/:uid", async (ctx: KoaContextWithOIDC, next) => {
    const { uid, prompt, params, session } = await provider.interactionDetails(
      ctx.req,
      ctx.res
    );
    const client = await provider.Client.find(params.client_id);

    switch (prompt.name) {
      case "select_account": {
        if (!session) {
          return provider.interactionFinished(
            ctx.req,
            ctx.res,
            {
              select_account: {}
            },
            { mergeWithLastSubmission: false }
          );
        }

        const account = await provider.Account.findAccount(
          ctx,
          session.accountId
        );
        const { email } = await account.claims(
          "prompt",
          "email",
          { email: null },
          []
        );

        return ctx.render("select_account", {
          client,
          uid,
          email,
          details: prompt.details,
          params,
          title: "Sign-in",
          session: session ? debug(session) : undefined,
          dbg: {
            params: debug(params),
            prompt: debug(prompt)
          }
        });
      }
      case "login": {
        return ctx.render("login", {
          client,
          uid,
          details: prompt.details,
          params,
          title: "Sign-in",
          google: ctx.google,
          session: session ? debug(session) : undefined,
          dbg: {
            params: debug(params),
            prompt: debug(prompt)
          }
        });
      }
      case "consent": {
        return ctx.render("interaction", {
          client,
          uid,
          details: prompt.details,
          params,
          title: "Authorize",
          session: session ? debug(session) : undefined,
          dbg: {
            params: debug(params),
            prompt: debug(prompt)
          }
        });
      }
      default:
        return next();
    }
  });

  const body = bodyParser({
    text: false,
    json: false,
    patchNode: true,
    patchKoa: true
  });

  router.get("/interaction/callback/google", (ctx: KoaContextWithOIDC) =>
    ctx.render("repost", { provider: "google", layout: false })
  );

  router.post(
    "/interaction/:uid/login",
    body,
    async (ctx: KoaContextWithOIDC) => {
      const {
        prompt: { name }
      } = await provider.interactionDetails(ctx.req, ctx.res);
      assert.equal(name, "login");

      const account = await Account.findByLogin(
        (ctx.request as any).body.login
      );

      const result =
        account != null
          ? {
              select_account: {}, // make sure its skipped by the interaction policy since we just logged in
              login: {
                account: account.accountId
              }
            }
          : {};

      return provider.interactionFinished(ctx.req, ctx.res, result, {
        mergeWithLastSubmission: false
      });
    }
  );

  router.post(
    "/interaction/:uid/federated",
    body,
    async (ctx: KoaContextWithOIDC) => {
      const {
        prompt: { name }
      } = await provider.interactionDetails(ctx.req, ctx.res);
      assert.equal(name, "login");

      const path = `/interaction/${ctx.params.uid}/federated`;
      const callbackParams = ctx.google.callbackParams(ctx.req);

      switch ((ctx.request as any).body.provider) {
        case "google": {
          if (Object.keys(callbackParams).length) {
            const state = ctx.cookies.get("google.state");
            ctx.cookies.set("google.state", "", { path });
            const nonce = ctx.cookies.get("google.nonce");
            ctx.cookies.set("google.nonce", "", { path });

            const tokenset = await ctx.google.callback(
              undefined,
              callbackParams,
              { state, nonce, response_type: "id_token" }
            );
            const account = await Account.findByFederated(
              "google",
              tokenset.claims()
            );

            const result =
              account != null
                ? {
                    select_account: {}, // make sure its skipped by the interaction policy since we just logged in
                    login: {
                      account: account.accountId
                    }
                  }
                : {};

            return provider.interactionFinished(ctx.req, ctx.res, result, {
              mergeWithLastSubmission: false
            });
          }

          const state = `${ctx.params.uid}|${crypto
            .randomBytes(32)
            .toString("hex")}`;
          const nonce = crypto.randomBytes(32).toString("hex");

          ctx.cookies.set("google.state", state, { path, sameSite: "strict" });
          ctx.cookies.set("google.nonce", nonce, { path, sameSite: "strict" });

          return ctx.redirect(
            ctx.google.authorizationUrl({
              state,
              nonce,
              scope: "openid email profile"
            })
          );
        }
        default:
          return undefined;
      }
    }
  );

  router.post(
    "/interaction/:uid/continue",
    body,
    async (ctx: KoaContextWithOIDC) => {
      const interaction = await provider.interactionDetails(ctx.req, ctx.res);
      const {
        prompt: { name, details }
      } = interaction;
      assert.equal(name, "select_account");

      if ((ctx.request as any).body.switch) {
        if (interaction.params.prompt) {
          const prompts: string[] = [
            ...(interaction.params.prompt as string).split(" "),
            "login"
          ];
          interaction.params.prompt = prompts.join(" ");
        } else {
          interaction.params.prompt = "logout";
        }
        await interaction.save();
      }

      const result = { select_account: {} };
      return provider.interactionFinished(ctx.req, ctx.res, result, {
        mergeWithLastSubmission: false
      });
    }
  );

  router.post(
    "/interaction/:uid/confirm",
    body,
    async (ctx: KoaContextWithOIDC) => {
      const {
        prompt: { name, details }
      } = await provider.interactionDetails(ctx.req, ctx.res);
      assert.equal(name, "consent");

      const result: InteractionResults = {
        consent: {
          // any scopes you do not wish to grant go in here
          //   otherwise details.scopes.new.concat(details.scopes.accepted) will be granted
          rejectedScopes: [],
          // any claims you do not wish to grant go in here
          //   otherwise all claims mapped to granted scopes
          //   and details.claims.new.concat(details.claims.accepted) will be granted
          rejectedClaims: [],
          // replace = false means previously rejected scopes and claims remain rejected
          // changing this to true will remove those rejections in favour of just what you rejected above
          replace: false
        }
      };
      return provider.interactionFinished(ctx.req, ctx.res, result, {
        mergeWithLastSubmission: true
      });
    }
  );

  router.get("/interaction/:uid/abort", async (ctx: KoaContextWithOIDC) => {
    const result = {
      error: "access_denied",
      error_description: "End-User aborted interaction"
    };

    return provider.interactionFinished(ctx.req, ctx.res, result, {
      mergeWithLastSubmission: false
    });
  });

  return router;
};

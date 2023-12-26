import { defineEventHandler, getCookie, deleteCookie } from "h3";
import { initClient } from "../../../utils/issueclient.mjs";
import { logger } from "../../../utils/logger.mjs";
import { getRedirectUrl, getCallbackUrl, getDefaultBackUrl, getResponseMode, setCookieInfo, setCookieTokenAndRefreshToken } from "../../../utils/utils.mjs";
import { useRuntimeConfig } from "#imports";
export default defineEventHandler(async (event) => {
  const req = event.node.req;
  const res = event.node.res;
  logger.info("[CALLBACK]: oidc/callback calling, method:" + req.method);
  let request = req;
  if (req.method === "POST") {
    const body = await readBody(event);
    request = {
      method: req.method,
      url: req.url,
      body
    };
  }
  const { op, config } = useRuntimeConfig().openidConnect;
  const responseMode = getResponseMode(config);
  const sessionid = getCookie(event, config.secret);
  deleteCookie(event, config.secret);
  const redirectUrl = getRedirectUrl(req.url);
  const callbackUrl = getCallbackUrl(op.callbackUrl, redirectUrl, req.headers.host);
  const defCallBackUrl = getDefaultBackUrl(redirectUrl, req.headers.host);
  const issueClient = await initClient(op, req, [defCallBackUrl, callbackUrl]);
  const params = issueClient.callbackParams(request);
  if (params.access_token) {
    logger.debug("[CALLBACK]: has access_token in params, accessToken:" + params.access_token);
    await processUserInfo(params.access_token, null, event);
    res.writeHead(302, { Location: redirectUrl || "/" });
    res.end();
  } else if (params.code) {
    logger.debug("[CALLBACK]: has code in params, code:" + params.code + " ,sessionid=" + sessionid);
    const tokenSet = await issueClient.callback(callbackUrl, params, { nonce: sessionid });
    if (tokenSet.access_token) {
      await processUserInfo(tokenSet.access_token, tokenSet, event);
    }
    res.writeHead(302, { Location: redirectUrl || "/" });
    res.end();
  } else {
    if (params.error) {
      logger.error("[CALLBACK]: error callback");
      logger.error(params.error + ", error_description:" + params.error_description);
      res.writeHead(302, { Location: "/oidc/error" });
      res.end();
    } else if (responseMode === "fragment") {
      logger.warn("[CALLBACK]: callback redirect");
      res.writeHead(302, { Location: "/oidc/cbt?redirect=" + redirectUrl });
      res.end();
    } else {
      logger.error("[CALLBACK]: error callback");
      res.writeHead(302, { Location: redirectUrl || "/" });
      res.end();
    }
  }
  async function processUserInfo(accessToken, tokenSet, event2) {
    try {
      const userinfo = await issueClient.userinfo(accessToken);
      const { config: config2 } = useRuntimeConfig().openidConnect;
      if (tokenSet) {
        setCookieTokenAndRefreshToken(event2, config2, tokenSet);
      }
      await setCookieInfo(event2, config2, userinfo);
    } catch (err) {
      logger.error("[CALLBACK]: " + err);
    }
  }
});

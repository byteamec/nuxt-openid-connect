import { getCookie, deleteCookie, defineEventHandler } from "h3";
import { initClient } from "../../../utils/issueclient.mjs";
import { decrypt } from "../../../utils/encrypt.mjs";
import { logger } from "../../../utils/logger.mjs";
import { setCookieInfo, setCookieTokenAndRefreshToken } from "../../../utils/utils.mjs";
import { useRuntimeConfig } from "#imports";
export default defineEventHandler(async (event) => {
  const { config, op } = useRuntimeConfig().openidConnect;
  logger.debug("[USER]: oidc/user calling");
  logger.trace("[USER]: " + event.req.headers.cookie);
  const sessionid = getCookie(event, config.secret);
  const accesstoken = getCookie(event, config.cookiePrefix + "access_token");
  const refreshToken = getCookie(event, config.cookiePrefix + "refresh_token");
  const userinfoCookie = getCookie(event, config.cookiePrefix + "user_info");
  const issueClient = await initClient(op, event.node.req, []);
  if (userinfoCookie) {
    logger.info("userinfo:Cookie");
    const userInfoStr = await decrypt(userinfoCookie, config);
    return JSON.parse(userInfoStr ?? "");
  } else if (accesstoken) {
    logger.info("userinfo:accesstoken");
    try {
      const userinfo = await issueClient.userinfo(accesstoken);
      await setCookieInfo(event, config, userinfo);
      return userinfo;
    } catch (err) {
      logger.error("[USER]: " + err);
      deleteCookie(event, config.secret);
      deleteCookie(event, config.cookiePrefix + "access_token");
      deleteCookie(event, config.cookiePrefix + "user_info");
      const cookie = config.cookie;
      if (cookie) {
        for (const [key, value] of Object.entries(cookie)) {
          deleteCookie(event, config.cookiePrefix + key);
        }
      }
      return {};
    }
  } else if (refreshToken) {
    logger.info("userinfo:refresh token");
    const tokenSet = await issueClient.refresh(refreshToken);
    if (tokenSet.access_token) {
      const userinfo = await issueClient.userinfo(tokenSet.access_token);
      setCookieTokenAndRefreshToken(event, config, tokenSet);
      await setCookieInfo(event, config, userinfo);
      return userinfo;
    } else {
      return {};
    }
  } else {
    logger.debug("[USER]: empty accesstoken for access userinfo");
    return {};
  }
});

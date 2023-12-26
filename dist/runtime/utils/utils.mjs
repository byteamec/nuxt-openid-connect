import { setCookie } from "h3";
import { encrypt } from "./encrypt.mjs";
export const setCookieTokenAndRefreshToken = (event, config, tokenSet) => {
  if (tokenSet && tokenSet.expires_at) {
    const expireDate = new Date(tokenSet.expires_at * 1e3);
    setCookie(event, config.cookiePrefix + "access_token", tokenSet.access_token, {
      expires: expireDate,
      ...config.cookieFlags["access_token"]
    });
  } else {
    setCookie(event, config.cookiePrefix + "access_token", tokenSet.access_token, {
      maxAge: config.cookieMaxAge,
      ...config.cookieFlags["access_token"]
    });
  }
  if (tokenSet && tokenSet.refresh_expires_in && tokenSet.refresh_token) {
    setCookie(event, config.cookiePrefix + "refresh_token", tokenSet.refresh_token, {
      maxAge: tokenSet.refresh_expires_in
    });
  }
};
export const setCookieInfo = async (event, config, userinfo) => {
  const { cookie, isCookieUserInfo } = config;
  if (isCookieUserInfo) {
    for (const [key, value] of Object.entries(userinfo)) {
      if (cookie && Object.prototype.hasOwnProperty.call(cookie, key)) {
        setCookie(event, config.cookiePrefix + key, JSON.stringify(value), {
          maxAge: config.cookieMaxAge,
          ...config.cookieFlags[key]
        });
      }
    }
    try {
      const encryptedText = await encrypt(JSON.stringify(userinfo), config);
      setCookie(event, config.cookiePrefix + "user_info", encryptedText, { ...config.cookieFlags["user_info"] });
    } catch (err) {
      console.error("encrypted userinfo error.", err);
    }
  }
};
export const isUnset = (o) => typeof o === "undefined" || o === null;
export const isSet = (o) => !isUnset(o);
export const getRedirectUrl = (uri) => {
  if (!uri) {
    return "/";
  }
  const idx = uri.indexOf("?");
  const searchParams = new URLSearchParams(idx >= 0 ? uri.substring(idx) : uri);
  return searchParams.get("redirect") || "/";
};
export function getCallbackUrl(callbackUrl, redirectUrl, host) {
  if (callbackUrl && callbackUrl.length > 0) {
    return callbackUrl.includes("?") ? callbackUrl + "&redirect=" + redirectUrl : callbackUrl + "?redirect=" + redirectUrl;
  } else {
    return getDefaultBackUrl(redirectUrl, host);
  }
}
export function getDefaultBackUrl(redirectUrl, host) {
  return "http://" + host + "/oidc/cbt?redirect=" + redirectUrl;
}
export function getResponseMode(config) {
  const responseType = config.response_type;
  return config.response_mode || getDefaultResponseMode(responseType);
}
function getDefaultResponseMode(responseType) {
  const resTypeArray = responseType.match(/[^ ]+/g);
  if (resTypeArray && resTypeArray?.findIndex((i) => i === "code") >= 0) {
    return "query";
  } else if (resTypeArray && resTypeArray?.findIndex((i) => i === "token")) {
    return "fragment";
  }
  return "query";
}

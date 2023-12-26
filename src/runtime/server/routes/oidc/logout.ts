import { getCookie, deleteCookie, defineEventHandler } from 'h3'
import { logger } from '../../../utils/logger'
import { useRuntimeConfig } from '#imports'

export default defineEventHandler((event) => {
  const res = event.node.res
  logger.log('[LOGOUT]: oidc/logout calling')

  const { config } = useRuntimeConfig().openidConnect
  deleteCookie(event, config.secret)
  deleteCookie(event, config.cookiePrefix + 'access_token')
  deleteCookie(event, config.cookiePrefix + 'refresh_token')
  deleteCookie(event, config.cookiePrefix + 'user_info')
  deleteCookie(event, config.cookiePrefix + 'logout_url')

  // delete part of cookie userinfo (depends on user's setting.).
  const cookie = config.cookie
  if (cookie) {
    for (const [key, value] of Object.entries(cookie)) {
      deleteCookie(event, config.cookiePrefix + key)
    }
  }

  res.writeHead(302, { Location: '/' })
  res.end()
})

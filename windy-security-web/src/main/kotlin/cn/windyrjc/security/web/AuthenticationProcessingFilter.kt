package cn.windyrjc.security.web

import cn.windyrjc.security.common.UrlMatcherRegistry
import cn.windyrjc.security.core.exception.WindySecurityException
import cn.windyrjc.security.core.service.AuthenticationTokenService
import cn.windyrjc.security.web.properties.WindySecurityWebProperties
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.InitializingBean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.AuthenticationEventPublisher
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.util.AntPathMatcher
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * ┌───┐   ┌───┬───┬───┬───┐ ┌───┬───┬───┬───┐ ┌───┬───┬───┬───┐ ┌───┬───┬───┐
 * │Esc│   │ F1│ F2│ F3│ F4│ │ F5│ F6│ F7│ F8│ │ F9│F10│F11│F12│ │P/S│S L│P/B│  ┌┐    ┌┐    ┌┐
 * └───┘   └───┴───┴───┴───┘ └───┴───┴───┴───┘ └───┴───┴───┴───┘ └───┴───┴───┘  └┘    └┘    └┘
 * ┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───────┐ ┌───┬───┬───┐ ┌───┬───┬───┬───┐
 * │~ `│! 1│@ 2│# 3│$ 4│% 5│^ 6│& 7│* 8│( 9│) 0│_ -│+ =│ BacSp │ │Ins│Hom│PUp│ │N L│ / │ * │ - │
 * ├───┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─────┤ ├───┼───┼───┤ ├───┼───┼───┼───┤
 * │ Tab │ Q │ W │ E │ R │ T │ Y │ U │ I │ O │ P │{ [│} ]│ | \ │ │Del│End│PDn│ │ 7 │ 8 │ 9 │   │
 * ├─────┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴─────┤ └───┴───┴───┘ ├───┼───┼───┤ + │
 * │ Caps │ A │ S │ D │ F │ G │ H │ J │ K │ L │: ;│" '│ Enter  │               │ 4 │ 5 │ 6 │   │
 * ├──────┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴────────┤     ┌───┐     ├───┼───┼───┼───┤
 * │ Shift  │ Z │ X │ C │ V │ B │ N │ M │< ,│> .│? /│  Shift   │     │ ↑ │     │ 1 │ 2 │ 3 │   │
 * ├─────┬──┴─┬─┴──┬┴───┴───┴───┴───┴───┴──┬┴───┼───┴┬────┬────┤ ┌───┼───┼───┐ ├───┴───┼───┤ E││
 * │ Ctrl│    │Alt │         Space         │ Alt│    │    │Ctrl│ │ ← │ ↓ │ → │ │   0   │ . │←─┘│
 * └─────┴────┴────┴───────────────────────┴────┴────┴────┴────┘ └───┴───┴───┘ └───────┴───┴───┘
 * 键盘保佑  永无BUG
 * create by windyrjc
 * @Date 2019-03-20 17:55
 */
class AuthenticationProcessingFilter : OncePerRequestFilter(), InitializingBean {

    private val log = LoggerFactory.getLogger(AuthenticationProcessingFilter::class.java)
    private var eventPublisher: AuthenticationEventPublisher = NullEventPublisher()

    @Autowired
    lateinit var authenticationEntryPoint: AuthenticationEntryPoint
    @Autowired
    lateinit var properties: WindySecurityWebProperties
    @Autowired
    lateinit var authenticationTokenService: AuthenticationTokenService
    @Autowired
    lateinit var matcherRegistry: UrlMatcherRegistry

    private val requestMatcher = AntPathMatcher()

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        try {
            //检测filter url 路径匹配  1.except,2.match
            if (checkUrl(request)) {
                //取出token
                val token = extractToken(request)
                //校验token
                val authenticationToken = authenticationTokenService.readAccessToken(tokenStr = token)
                        ?: throw WindySecurityException("登录过期或已失效!")
                log.debug("authentication success: ${authenticationToken.authentication!!.id}")
                //插入context
                SecurityContextHolder.getContext().authentication = authenticationToken.authentication
                eventPublisher.publishAuthenticationSuccess(authenticationToken.authentication)
            } else {
                SecurityContextHolder.clearContext()
            }
        } catch (e: Exception) {
            SecurityContextHolder.clearContext()
            eventPublisher.publishAuthenticationFailure(BadCredentialsException(e.message, e), PreAuthenticatedAuthenticationToken("token", "N/A"))
            authenticationEntryPoint.commence(request, response, BadCredentialsException(e.message, e))
            return
        }
        filterChain.doFilter(request, response)
    }


    override fun afterPropertiesSet() {
        try {
            properties.matchUrl.split(",")
            properties.ignoreUrl.split(",")
            return
        } catch (e: Exception) {
            throw WindySecurityException("")
        }
    }


    private fun checkUrl(request: HttpServletRequest): Boolean {
        val matchUrls = matcherRegistry.matchUrls
        return if (matchUrls.isNotEmpty() && matchUrls[0].isNotEmpty()) {
            matchUrls.any { requestMatcher.match(it, request.requestURI) }
        } else {
            val ignoreUrls = matcherRegistry.ignoreUrls
            ignoreUrls.forEach {
                if (requestMatcher.match(it, request.requestURI)) {
                    return false
                } else {
                    return@forEach
                }
            }
            return true
        }
    }

    private fun extractToken(request: HttpServletRequest): String {
        val header = request.getHeader(HttpHeaders.AUTHORIZATION) ?: throw WindySecurityException("受保护的资源: 请传入token")
        if (header.isEmpty() && !header.startsWith("Bearer ")) {
            throw WindySecurityException("未找到token或token格式不正确")
        }
        return if (header.length > 10) header.substring(7) else ""
    }

    private class NullEventPublisher : AuthenticationEventPublisher {
        override fun publishAuthenticationFailure(exception: AuthenticationException, authentication: Authentication) {}

        override fun publishAuthenticationSuccess(authentication: Authentication) {}
    }
}
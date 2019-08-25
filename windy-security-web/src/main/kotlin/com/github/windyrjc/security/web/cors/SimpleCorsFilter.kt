package com.github.windyrjc.security.web.cors

import com.github.windyrjc.security.common.UrlMatcherRegistry
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.util.AntPathMatcher
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.ServletException
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
 * @Date 2019-04-15 19:39
 */
class SimpleCorsFilter : OncePerRequestFilter() {

    private val log = LoggerFactory.getLogger(SimpleCorsFilter::class.java)

    private val requestMatcher = AntPathMatcher()

    @Autowired
    lateinit var urlMatcherRegistry: UrlMatcherRegistry

    @Throws(ServletException::class, IOException::class)
    override fun doFilterInternal(httpServletRequest: HttpServletRequest, httpServletResponse: HttpServletResponse, filterChain: FilterChain) {
        val origin = httpServletRequest.remoteHost as String + ":" + httpServletRequest.remotePort
        if (checkUrl(httpServletRequest)) {
            log.debug("cors: url: {} port: {}", httpServletRequest.requestURI, origin)
            httpServletResponse.setHeader("Access-Control-Allow-Origin", "*")
            httpServletResponse.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE,PUT,PATCH")
            httpServletResponse.setHeader("Access-Control-Max-Age", "3600")
            httpServletResponse.setHeader("Access-Control-Allow-Headers", "x-requested-with,Authorization,content-type")
            httpServletResponse.setHeader("Access-Control-Allow-Credentials", "true")
            //主要适应前后端分离架构 对跨域请求 axios 库会预先发送options 请求
            if ("OPTIONS".equals(httpServletRequest.method, ignoreCase = true)) {
                httpServletResponse.status = HttpServletResponse.SC_OK
            } else {
                filterChain.doFilter(httpServletRequest, httpServletResponse)
            }
        } else {
            filterChain.doFilter(httpServletRequest, httpServletResponse)
        }
    }

    private fun checkUrl(request: HttpServletRequest): Boolean {
        val ignoreUrls = urlMatcherRegistry.corsIgnoreUrls
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
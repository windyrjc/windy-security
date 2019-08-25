package cn.windyrjc.security.web

import cn.windyrjc.security.core.exception.WindySecurityException
import cn.windyrjc.security.web.annotation.AuthMapping
import cn.windyrjc.security.web.annotation.RefreshMapping
import org.springframework.beans.factory.InitializingBean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.core.annotation.AnnotationUtils
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.util.Assert
import javax.servlet.http.HttpServletRequest

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
 * @Date 2019-03-31 20:29
 */
class AuthRequireCheckService : InitializingBean {

    @Autowired
    private lateinit var authenticationServices: List<cn.windyrjc.security.web.AuthenticationService<*>>

    override fun afterPropertiesSet() {
        setAuthFilterProcessUrls()
    }

    private var requiresAuthenticationRequestMatchers: List<RequestMatcher>? = null

    fun requiresAuthentication(request: HttpServletRequest): Boolean {
        return requiresAuthenticationRequestMatchers!!.any { it.matches(request) }
    }

    // 拿到接口上方的登录路径
    private fun setAuthFilterProcessUrls() {
        val urls = mutableListOf<String>()
        authenticationServices.forEach {
            val annotation = AnnotationUtils.findAnnotation(it::class.java, AuthMapping::class.java)
            if (annotation != null) {
                urls.add(annotation.value)
            } else {
                val refresh = AnnotationUtils.findAnnotation(it::class.java, RefreshMapping::class.java)
                        ?: return@forEach
                urls.add(refresh.value)
            }
        }
        if (urls.isEmpty()) {
            throw WindySecurityException("登录url不能为空!")
        }
        val requestMatchers = arrayListOf<RequestMatcher>()
        urls.forEach {
            requestMatchers.add(AntPathRequestMatcher(it))
        }
        setRequiresAuthenticationRequestMatcher(requestMatchers)
    }

    private fun setRequiresAuthenticationRequestMatcher(
            requestMatchers: List<RequestMatcher>) {
        Assert.notNull(requestMatchers, "requestMatchers cannot be null")
        this.requiresAuthenticationRequestMatchers = requestMatchers
    }

}
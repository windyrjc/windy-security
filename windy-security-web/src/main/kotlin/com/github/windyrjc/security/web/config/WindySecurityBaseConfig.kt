package com.github.windyrjc.web.config

import com.github.windyrjc.common.UrlMatcherRegistry
import com.github.windyrjc.common.UrlStrategyMatcher
import com.github.windyrjc.web.AuthenticationProcessingFilter
import com.github.windyrjc.web.AuthenticationService
import com.github.windyrjc.web.WindySecurityAuthenticationEntryPoint
import com.github.windyrjc.web.annotation.RefreshMapping
import com.github.windyrjc.web.config.selector.WindySecurityConfigSelector
import com.github.windyrjc.web.handler.AuthenticationTokenResponseHandler
import com.github.windyrjc.web.properties.WindySecurityWebProperties
import com.github.windyrjc.web.refresh.RefreshAuthenticationService
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.InitializingBean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.AnnotationUtils
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.AuthenticationEntryPoint

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
 * @Date 2019-03-18 14:56
 */
@Configuration
@EnableConfigurationProperties(WindySecurityWebProperties::class)
class WindySecurityBaseConfig : InitializingBean {

    @Autowired
    lateinit var properties: WindySecurityWebProperties
    @Autowired
    lateinit var objectMapper: ObjectMapper
    @Autowired
    lateinit var authenticationServices: List<AuthenticationService<*>>
    @Autowired(required = false)
    var urlStrategyMatchers: List<UrlStrategyMatcher>? = null

    @Bean
    @ConditionalOnMissingBean
    fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }

//    @Bean
//    @ConditionalOnMissingBean
//    fun authenticationTokenService(): JwtAuthenticationTokenService {
//        return JwtAuthenticationTokenService(properties.jwt.jwtKey)
//    }

    @Bean
    @ConditionalOnMissingBean
    fun authenticationTokenResponseHandler(): AuthenticationTokenResponseHandler {
        return AuthenticationTokenResponseHandler(authenticationServices.any {
            AnnotationUtils.findAnnotation(it::class.java, RefreshMapping::class.java) != null
        })
    }

    override fun afterPropertiesSet() {
        val refreshService = authenticationServices.filter {
            AnnotationUtils.findAnnotation(it::class.java, RefreshMapping::class.java)
                    ?: return@filter false
            if (it is RefreshAuthenticationService) {
                return@filter true
            } else {
                throw IllegalArgumentException("@RefreshMapping 注解指定类必须实现RefreshAuthenticationService方法!")
            }
        }
        if (refreshService.size > 1) {
            throw IllegalArgumentException("refresh token路由不能有多个!")
        }

    }

//    @Bean
//    @ConditionalOnMissingBean
//    fun authenticationSuccessHandler():AuthenticationSuccessHandler{
//        return DefaultAuthenticationSuccessHandler()
//    }
//
//    @Bean
//    @ConditionalOnMissingBean
//    fun authenticationFailureHandler(): AuthenticationFailureHandler {
//        return DefaultAuthenticationFaliureHandler()
//    }

    @Bean
    @ConditionalOnMissingBean
    fun windySecurityAuthenticationEntryPoint(): AuthenticationEntryPoint {
        return WindySecurityAuthenticationEntryPoint(objectMapper)
    }

    @Bean
    @ConditionalOnMissingBean
    fun authenticationProcessingFilter(): AuthenticationProcessingFilter {
        return AuthenticationProcessingFilter()
    }

    @Bean
    @ConditionalOnMissingBean
    fun urlMatcherRegistry(): UrlMatcherRegistry {
        val matchUrls = properties.matchUrl.split(",")
        val ignoreUrls = properties.ignoreUrl.split(",")
        val corsIgnoreUrls = properties.cors.ignoreUrl.split(",")
        val registry = UrlMatcherRegistry(matchUrls = matchUrls, ignoreUrls = ignoreUrls,corsIgnoreUrls = corsIgnoreUrls)
        if (urlStrategyMatchers != null) {
            urlStrategyMatchers!!.forEach {
                it.handleUrl(registry)
            }
        }
        return registry
    }


    @Bean
    @ConditionalOnMissingBean
    fun windySecurityConfigSelector(): WindySecurityConfigSelector {
        return WindySecurityConfigSelector()
    }
}
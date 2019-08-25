package com.github.windyrjc.security.web.config

import com.github.windyrjc.security.web.*
import com.github.windyrjc.security.web.config.selector.WindySecurityConfigSelector
import com.github.windyrjc.security.web.cors.SimpleCorsFilter
import com.github.windyrjc.security.web.properties.WindySecurityWebProperties
import com.github.windyrjc.security.web.resolver.WindySecurityWebArgumentResolver
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter
import org.springframework.web.method.support.HandlerMethodArgumentResolver
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

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
 * @Date 2019-03-06 17:56
 */
@Configuration
class WindySecurityWebConfig : WebSecurityConfigurerAdapter(), WebMvcConfigurer {


    @Autowired
    lateinit var authenticationServices: List<AuthenticationService<*>>
    @Autowired
    lateinit var passwordEncoder: PasswordEncoder
    @Autowired
    lateinit var objectMapper: ObjectMapper
    @Autowired
    lateinit var properties: WindySecurityWebProperties
    @Autowired
    lateinit var authenticationProcessingFilter: AuthenticationProcessingFilter
    @Autowired
    lateinit var windySecurityConfigSelector: WindySecurityConfigSelector
    @Autowired(required = false)
    var authenticationSuccessHandler: AuthenticationSuccessHandler? = null
    @Autowired(required = false)
    var authenticationFailureHandler: AuthenticationFailureHandler? = null
    @Autowired(required = false)
    var simpleCorsFilter: SimpleCorsFilter? = null

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.authenticationProvider(SecurityAuthenticationProvider(authenticationServices, passwordEncoder, objectMapper, properties))
    }

    override fun configure(http: HttpSecurity) {
        windySecurityConfigSelector.selectAndConfig(http)
        http.formLogin().disable()
                .sessionManagement().disable()
                .csrf().disable()
                .httpBasic().disable()
        http.addFilterBefore(authenticationFilter(), UsernamePasswordAuthenticationFilter::class.java)
        http.addFilterAfter(authenticationProcessingFilter, UsernamePasswordAuthenticationFilter::class.java)
        if (simpleCorsFilter != null) {
            http.addFilterBefore(simpleCorsFilter, AbstractPreAuthenticatedProcessingFilter::class.java)
        }
    }

    override fun addArgumentResolvers(resolvers: MutableList<HandlerMethodArgumentResolver>) {
        resolvers.add(WindySecurityWebArgumentResolver(properties.injectClass, objectMapper))
    }

    @Bean
    @ConditionalOnMissingBean
    fun authenticationFilter(): AuthenticationFilter {
        return AuthenticationFilter(authenticationManager(), authenticationSuccessHandler, authenticationFailureHandler)
    }

    @Bean
    @ConditionalOnMissingBean
    fun authRequireCheckService(): AuthRequireCheckService {
        return AuthRequireCheckService()
    }

}
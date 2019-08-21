package cn.windyrjc.security.web

import cn.windyrjc.security.core.exception.WindySecurityException
import cn.windyrjc.security.core.service.AuthenticationTokenService
import cn.windyrjc.security.web.annotation.AuthMapping
import cn.windyrjc.security.web.annotation.RefreshMapping
import cn.windyrjc.security.web.beans.CheckAuthenticationToken
import cn.windyrjc.security.web.beans.RefreshTokenLoginForm
import cn.windyrjc.security.web.handler.AuthenticationTokenResponseHandler
import cn.windyrjc.security.web.refresh.RefreshAuthenticationService
import cn.windyrjc.security.web.validate.ValidateCodeService
import cn.windyrjc.security.web.validate.ValidateCodeType
import cn.windyrjc.security.web.validate.image.ImageValidateCodeBean
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.InitializingBean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.core.annotation.AnnotationUtils
import org.springframework.security.authentication.*
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.util.Assert
import org.springframework.web.filter.GenericFilterBean
import sun.reflect.generics.reflectiveObjects.ParameterizedTypeImpl
import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
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
 * @Date 2019-02-14 20:37
 */
class AuthenticationFilter(private var authenticationManager: AuthenticationManager? = null,
                           private var successHandler: AuthenticationSuccessHandler? = null,
                           private var failureHandler: AuthenticationFailureHandler? = null) : GenericFilterBean(), InitializingBean {

    private var authenticationDetailsSource: AuthenticationDetailsSource<HttpServletRequest, *> = WebAuthenticationDetailsSource()

    override fun afterPropertiesSet() {
        Assert.notNull(authenticationManager, "authenticationManager must be specified")
    }

    @Autowired
    private lateinit var authRequireCheckService: AuthRequireCheckService
    @Autowired
    private lateinit var authenticationEventPublisher: AuthenticationEventPublisher
    @Autowired
    private lateinit var authenticationEntryPoint: AuthenticationEntryPoint
    @Autowired
    private lateinit var objectMapper: ObjectMapper
    @Autowired
    private lateinit var authenticationServices: List<AuthenticationService<*>>
    @Autowired
    private lateinit var authenticationTokenResponseHandler: AuthenticationTokenResponseHandler
    @Autowired
    private lateinit var authenticationTokenService: AuthenticationTokenService
    @Autowired(required = false)
    private var validateCodeServices: Map<String, ValidateCodeService>? = null

    override fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
        request as HttpServletRequest
        response as HttpServletResponse
        var isRefresh = false
        //检查是否为登录路径
        if (!authRequireCheckService.requiresAuthentication(request) || request.method == "OPTIONS") {
            chain.doFilter(request, response)
            return
        }
        if ("POST" != request.method) {
            throw AuthenticationServiceException("authentication http method not supported")
        }
        try {
            //拿到通过登录路径拿到对应的处理器
            val authenticationService: AuthenticationService<*> = getAuthenticationService(request)
            val formClass: Class<*>
            //检查是否是refresh token 对应的处理器
            if (authenticationService is RefreshAuthenticationService) {
                isRefresh = true
                formClass = RefreshTokenLoginForm::class.java
            } else {
                //通过泛型拿到登录的表单类
                formClass = (authenticationService.javaClass.genericInterfaces[0] as ParameterizedTypeImpl).actualTypeArguments[0] as Class<*>
            }
            //传入的http请求的json通过表单类解析成表单对象
            val body = extractBody(request, formClass)
            //解析表单类是否有空字段
            checkNotNullRecur(body, formClass)

            //检查图形验证码
            if (body is ImageValidateCodeBean) {
                if (validateCodeServices != null) {
                    val service = validateCodeServices!![ValidateCodeType.image.serviceBeanName]
                            ?: throw WindySecurityException("请检查图形验证码服务是否未开启")
                    service.validate(body.getImageCode(), body.getDeviceId())
                } else {
                    throw WindySecurityException("请检查图形验证码服务是否未开启")
                }
            }
            //todo 检查短信验证码

            //组装token对象,准备送入AuthenticationManager进行校验
            val authRequest = if (!isRefresh) {
                extractAuthRequest(body, formClass, isRefresh)
            } else {
                body as RefreshTokenLoginForm
                extractRefreshRequest(body, isRefresh)
            }
            setDetails(request, authRequest)
            //送入AuthenticationManager进行校验
            val authResult = this.authenticationManager!!.authenticate(authRequest)
//            authResult as AuthenticationUser
            //登录成功操作
            loginSuccess(authResult, request, response, isRefresh)
        } catch (failed: Exception) {
            SecurityContextHolder.clearContext()
            logger.debug("authenticate request failed: ${failed.message}")
            authenticationEventPublisher.publishAuthenticationFailure(BadCredentialsException(failed.message),
                    PreAuthenticatedAuthenticationToken("access-token", "N/A"))
            if (failureHandler != null) {
                failureHandler!!.onAuthenticationFailure(request, response, BadCredentialsException(failed.message, failed))
            }
            authenticationEntryPoint.commence(request, response, BadCredentialsException(failed.message, failed))
        }
    }

    @Throws(WindySecurityException::class)
    private fun loginSuccess(authResult: Authentication, request: HttpServletRequest, response: HttpServletResponse, isRefresh: Boolean) {
        if (isRefresh) {
            //todo refresh_token 之前旧信息删除
            logger.debug("Refresh login success: $authResult")
        } else {
            logger.debug("Login success: $authResult")
        }
        SecurityContextHolder.getContext().authentication = authResult
        authenticationEventPublisher.publishAuthenticationSuccess(authResult)
        //组装token返回用户
        authenticationTokenResponseHandler.responseWithToken(request, response, authResult)
        if (successHandler != null) {
            successHandler!!.onAuthenticationSuccess(request, response, authResult)
        }
    }

    @Throws(WindySecurityException::class)
    private fun getAuthenticationService(request: HttpServletRequest): AuthenticationService<*> {
        var authenticationService: AuthenticationService<*>? = null

        for (service in authenticationServices) {
            val annotation = AnnotationUtils.findAnnotation(service::class.java, RefreshMapping::class.java)
            if (annotation != null) {
                val refreshUrl = annotation.value
                if (refreshUrl.trim() == request.requestURI) {
                    authenticationService = service
                    break
                }
            }
        }
        if (authenticationService == null) {
            for (service in authenticationServices) {
                val annotation = AnnotationUtils.findAnnotation(service::class.java, AuthMapping::class.java)
                        ?: throw WindySecurityException("请检查authenticationService 是否加上@AuthMapping注解")
                val url = annotation.value
                if (url.trim() == request.requestURI) {
                    authenticationService = service
                    break
                }
            }
        }
        if (authenticationService == null) {
            throw WindySecurityException("service 错误!")
        }
        return authenticationService
    }

    @Throws(WindySecurityException::class)
    private fun checkNotNullRecur(body: Any?, loginForm: Class<*>) {
        loginForm.declaredFields.forEach {
            it.isAccessible = true
            if (it.get(body) == null) {
                throw WindySecurityException("传入参数 ${it.name} 为空,与原定义数据不一致!")
            }
        }
    }

    private fun <T> extractBody(request: HttpServletRequest, clazz: Class<T>): T {
        return objectMapper.readValue(request.inputStream, clazz)
    }

    private fun setDetails(request: HttpServletRequest,
                           authRequest: CheckAuthenticationToken) {
        authRequest.details = authenticationDetailsSource.buildDetails(request)
    }

    private fun extractAuthRequest(body: Any, clazz: Class<*>, isRefresh: Boolean): CheckAuthenticationToken {
        return CheckAuthenticationToken(body, isRefresh, clazz)
    }

    @Throws(WindySecurityException::class)
    private fun extractRefreshRequest(body: RefreshTokenLoginForm, isRefresh: Boolean): CheckAuthenticationToken {
        val refreshToken = authenticationTokenService.readRefreshToken(body.refreshToken!!)
                ?: throw WindySecurityException("未找到refresh_token或已使用过")
        return CheckAuthenticationToken(refreshToken.id, isRefresh, String::class.java)
    }


}

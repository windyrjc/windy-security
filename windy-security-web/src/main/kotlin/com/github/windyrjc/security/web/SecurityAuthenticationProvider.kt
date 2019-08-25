package com.github.windyrjc.security.web

import com.github.windyrjc.security.core.AuthenticationUser
import com.github.windyrjc.security.core.exception.WindySecurityException
import com.github.windyrjc.security.web.beans.CheckAuthenticationToken
import com.github.windyrjc.security.web.beans.UserDetails
import com.github.windyrjc.security.web.properties.WindySecurityWebProperties
import cn.windyrjc.utils.copy.DataUtil
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.crypto.password.PasswordEncoder
import sun.reflect.generics.reflectiveObjects.ParameterizedTypeImpl
import java.lang.reflect.InvocationTargetException

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
 * @Date 2019-02-17 22:42
 */
class SecurityAuthenticationProvider(private var authenticationServices: List<AuthenticationService<*>>,
                                     private var passwordEncoder: PasswordEncoder,
                                     private var objectMapper: ObjectMapper,
                                     private var properties: WindySecurityWebProperties) : AuthenticationProvider {

    override fun supports(authentication: Class<*>): Boolean {
        return CheckAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

    override fun authenticate(authentication: Authentication): Authentication? {
        authentication as CheckAuthenticationToken
//        try {
        val service = if (authentication.isRefresh) {
            authenticationServices.filter {
                val type = it.javaClass.genericInterfaces[0] ?: return@filter false
                if (type is Class<*>) {
                    checkAuthenticationServices(type, authentication)
                } else return@filter false
            }[0]
        } else authenticationServices.filter {
            return@filter checkAuthenticationServices(it::class.java, authentication)
        }[0]
        val method = AuthenticationService::class.java.getDeclaredMethod("loadUserByCredential", Any::class.java, PasswordEncoder::class.java)
        try {
            val userDetails = method.invoke(service, authentication.principal, passwordEncoder) as UserDetails
            preChecks(userDetails)
            var jsonStr: String? = null
            if (userDetails.userDetail != null) {
                if (!userDetails.userDetail!!::class.java.isAssignableFrom(properties.injectClass)) {
                    throw WindySecurityException("传入注入对象非法,请修改userDetail类型!")
                }
                jsonStr = objectMapper.writeValueAsString(userDetails.userDetail)
            }

            val authenticationUser = DataUtil.convert(userDetails, AuthenticationUser::class.java)
            authenticationUser.userDetail = jsonStr
            return authenticationUser
        } catch (e: InvocationTargetException) {
            throw WindySecurityException(e.targetException.message ?: "加载 loadUserByCredential方法错误")
        }
//        } catch (e: Exception) {
//            e.printStackTrace()
//            throw WindySecurityException("加载 loadUserByCredential方法错误 msg = ${e.message}")
//        }
    }

    private fun checkAuthenticationServices(it: Class<*>, authentication: CheckAuthenticationToken): Boolean {
        val type = it.genericInterfaces[0] ?: return false
        return if (type is ParameterizedTypeImpl) {
            authentication.principalClass == type.actualTypeArguments[0] as Class<*>
        } else false
    }

    private fun preChecks(userDetails: UserDetails) {
        if (userDetails.id == null) {
            throw WindySecurityException("id 不能为空!")
        }
        if (userDetails.isEnabled == false) {
            throw WindySecurityException("该账号不可用!")
        }
        if (userDetails.isNonForbidden == false) {
            throw WindySecurityException("该账号被禁止使用!")
        }
        if (userDetails.isNonLocked == false) {
            throw  WindySecurityException("该账号被锁定!")
        }
    }


}
package com.github.windyrjc.security.web.expression

import com.github.windyrjc.security.core.AuthenticationUser
import org.springframework.security.access.PermissionEvaluator
import org.springframework.security.access.expression.SecurityExpressionOperations
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations
import org.springframework.security.access.hierarchicalroles.RoleHierarchy
import org.springframework.security.authentication.AuthenticationTrustResolver
import org.springframework.security.core.Authentication
import java.io.Serializable

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
 * @Date 2019-03-24 10:17
 */
class WindySecurityExpressionRoot(private val auth: Authentication) : SecurityExpressionOperations, MethodSecurityExpressionOperations {

    var target: Any? = null
    var filterTarget: Any? = null
    var returnTarget: Any? = null
    var trustResolver: AuthenticationTrustResolver? = null
    var roleHierarchy: RoleHierarchy? = null
    var permissionEvaluator: PermissionEvaluator? = null
    //todo 暂时不使用
    var rolePrefix: String? = null


    override fun denyAll(): Boolean {
        return false
    }

    override fun getAuthentication(): Authentication {
        return auth
    }

    override fun permitAll(): Boolean {
        return true
    }

    override fun isAuthenticated(): Boolean {
        return !isAnonymous
    }

    override fun hasAuthority(authority: String?): Boolean {
        return auth.authorities!!.any { it.authority == authority }
    }

    override fun isRememberMe(): Boolean {
        return trustResolver!!.isRememberMe(authentication)
    }

    override fun hasAnyAuthority(vararg authorities: String?): Boolean {
        return authorities.any { that -> auth.authorities!!.any { it.authority == that } }
    }

    override fun isAnonymous(): Boolean {
        return trustResolver!!.isAnonymous(authentication)
    }

    override fun hasRole(role: String?): Boolean {
        return if (auth is AuthenticationUser) {
            if (auth.roles != null) {
                auth.roles!!.any { it == role }
            } else false
        } else {
            hasAuthority(role)
        }
    }

    override fun isFullyAuthenticated(): Boolean {
        return !trustResolver!!.isAnonymous(authentication) && !trustResolver!!.isRememberMe(authentication)
    }

    override fun hasAnyRole(vararg roles: String?): Boolean {
        return if (auth is AuthenticationUser) {
            return if (auth.roles != null) {
                roles.any { that -> auth.roles!!.any { it == that } }
            } else {
                false
            }
        } else {
            hasAnyAuthority(*roles)
        }
    }

    override fun hasPermission(target: Any?, permission: Any?): Boolean {
        return permissionEvaluator!!.hasPermission(authentication, target, permission)
    }

    override fun hasPermission(targetId: Any?, targetType: String?, permission: Any?): Boolean {
        return permissionEvaluator!!.hasPermission(authentication, targetId as Serializable,
                targetType, permission)
    }

    fun hasPermission(permission: String): Boolean {
        return if (auth is AuthenticationUser) {
            if (auth.permissions != null) {
                auth.permissions!!.any { it == permission }
            } else false
        } else false
    }

    override fun setReturnObject(returnObject: Any?) {
        returnTarget = returnObject
    }

    override fun getFilterObject(): Any? {
        return filterTarget
    }

    override fun setFilterObject(filterObject: Any?) {
        this.filterTarget = filterObject
    }

    override fun getReturnObject(): Any? {
        return returnTarget
    }

    override fun getThis(): Any? {
        return target
    }


}
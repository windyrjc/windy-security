package com.github.windyrjc.security.web.beans

import org.apache.catalina.User

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
 * @Date 2019-03-22 10:37
 */
data class UserDetails(var id: String? = null,
                       var roles: List<String>? = null,
                       var permissions: List<String>? = null,
                       var userDetail: Any? = null,
                       var isNonForbidden: Boolean? = true,
                       var isNonLocked: Boolean? = true,
                       var isEnabled: Boolean? = true) {


    companion object {
        @JvmStatic
        fun instance(): UserDetails {
            return UserDetails()
        }
    }

    fun id(id: String): UserDetails {
        this.id = id
        return this
    }

    fun roles(roles: List<String>): UserDetails {
        this.roles = roles
        return this
    }

    fun permissions(permissions: List<String>?): UserDetails {
        this.permissions = permissions
        return this
    }

    fun userDetail(userDetail: Any?): UserDetails {
        this.userDetail = userDetail
        return this
    }

    fun nonForbidden(nonForbidden: Boolean): UserDetails {
        this.isNonForbidden = nonForbidden
        return this
    }

    fun nonLocked(nonLocked: Boolean): UserDetails {
        this.isNonLocked = nonLocked
        return this
    }

    fun enabled(enabled: Boolean): UserDetails {
        this.isEnabled = enabled
        return this
    }

    fun addRoles(vararg role: String): UserDetails {
        if (this.roles == null) {
            this.roles = mutableListOf()
        }
        (this.roles as MutableList<String>).addAll(role)
        return this
    }

    fun addPermission(vararg permissions: String): UserDetails {
        if (this.permissions == null) {
            this.permissions = mutableListOf()
        }
        (permissions as MutableList<String>).addAll(permissions)
        return this
    }


}
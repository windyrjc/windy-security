package cn.windyrjc.security.web.handler

import cn.windyrjc.security.core.AuthenticationRefreshToken
import cn.windyrjc.security.core.AuthenticationToken
import cn.windyrjc.security.core.AuthenticationTokenResponse
import cn.windyrjc.security.core.AuthenticationUser
import cn.windyrjc.security.core.service.AuthenticationTokenService
import cn.windyrjc.security.web.enhancer.TokenEnhancer
import cn.windyrjc.security.web.properties.WindySecurityWebProperties
import cn.windyrjc.utils.response.Response
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
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
 * @Date 2019-03-18 17:07
 */
class AuthenticationTokenResponseHandler(private val isRefreshEnabled: Boolean = false) {

    @Autowired
    lateinit var objectMapper: ObjectMapper
    @Autowired
    lateinit var authenticationTokenService: AuthenticationTokenService
    @Autowired
    lateinit var properties: WindySecurityWebProperties
    @Autowired(required = false)
    var tokenEnhancers: List<TokenEnhancer>? = null

    fun responseWithToken(request: HttpServletRequest, response: HttpServletResponse, authentication: Authentication) {
        val token = buildAuthenticationToken(authentication as AuthenticationUser)
        val tokenStr = authenticationTokenService.createAccessToken(token)
        response.contentType = "application/json;charset=UTF-8"
        response.status = HttpStatus.OK.value()
        val tokenResponse = AuthenticationTokenResponse(token = tokenStr, tokenExpireIn = token.expireIn, additionalInfo = token.additionalInfo)
        if (isRefreshEnabled) {
            val refreshToken = authenticationTokenService.createRefreshToken(buildRefreshAuthenticationToken(authentication.id!!, tokenStr))
            tokenResponse.refreshToken = refreshToken
            tokenResponse.refreshTokenExpireIn = properties.refreshTokenExpireIn
        }
        response.writer.write(objectMapper.writeValueAsString(Response.success(tokenResponse)))
    }

    private fun buildAuthenticationToken(authRequest: AuthenticationUser): AuthenticationToken {
        val map = mutableMapOf<String, Any>()
        if (tokenEnhancers != null) {
            tokenEnhancers!!.forEach { map.putAll(it.enhance(authRequest)) }
            return AuthenticationToken(authRequest, properties.accessTokenExpireIn, map)
        }
        return AuthenticationToken(authRequest, properties.accessTokenExpireIn)
    }

    private fun buildRefreshAuthenticationToken(id: String, accessToken: String): AuthenticationRefreshToken {
        return AuthenticationRefreshToken(id, properties.refreshTokenExpireIn, accessToken)
    }

}
package cn.windyrjc.security.core.service.impl

import cn.windyrjc.security.core.AuthenticationRefreshToken
import cn.windyrjc.security.core.AuthenticationToken
import cn.windyrjc.security.core.exception.WindySecurityException
import cn.windyrjc.security.core.service.AuthenticationTokenService
import cn.windyrjc.utils.copy.DataUtil
import io.jsonwebtoken.*
import java.util.*

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
 * @Date 2019-02-14 21:02
 */
@Suppress("UNCHECKED_CAST")
class JwtAuthenticationTokenService(private val jwtKey: String) : AuthenticationTokenService {

    private val signatureAlgorithm = SignatureAlgorithm.HS256


    override fun readAccessToken(token: String): AuthenticationToken? {
        val claims: Jws<Claims>
        try {
            claims = Jwts.parser()
                    .setSigningKey(jwtKey)
                    .parseClaimsJws(token)
        } catch (e: ExpiredJwtException) {
            throw WindySecurityException("access token 过期!")
        }
        if (claims != null) {
            return try {
                val tokenMap = claims.body["token"]
                if (tokenMap == null) {
                    null
                } else {
                    tokenMap as Map<String, Any>
                    DataUtil.mapToBean(tokenMap, AuthenticationToken::class.java)
                }
            } catch (e: Exception) {
                e.printStackTrace()
                throw WindySecurityException(e.message ?: "token 解析错误!")
            }
        } else {
            throw WindySecurityException("token解析错误!")
        }
    }


    override fun createAccessToken(token: AuthenticationToken): String {
        val date = System.currentTimeMillis()
        val expireTime = date + token.expireIn!! * 1000

        val builder = Jwts.builder()
//                .setId()
                .setIssuedAt(Date(date))
                .claim("token", token)
                .setSubject("access_token ${token.authentication!!.principal}")
                .signWith(signatureAlgorithm, jwtKey)
                .setExpiration(Date(expireTime))
        return builder.compact()
    }


    override fun createRefreshToken(refreshToken: AuthenticationRefreshToken): String {
        val date = System.currentTimeMillis()
        val expireTime = date + refreshToken.expireIn!! * 1000
        val builder = Jwts.builder()
//                .setId()
                .setIssuedAt(Date(date))
                .claim("refresh_token", refreshToken)
                .setSubject("refresh_token ${refreshToken.id}")
                .signWith(signatureAlgorithm, jwtKey)
                .setExpiration(Date(expireTime))
        return builder.compact()
    }

    override fun readRefreshToken(refreshToken: String): AuthenticationRefreshToken {
        val claims: Jws<Claims>
        try {
            claims = Jwts.parser()
                    .setSigningKey(jwtKey)
                    .parseClaimsJws(refreshToken)
        } catch (e: ExpiredJwtException) {
            throw WindySecurityException("refresh token 过期!")
        }
        if (claims != null) {
            val tokenMap = claims.body["refresh_token"] ?: throw WindySecurityException("token解析错误")
            tokenMap as Map<String, Any>
            return DataUtil.mapToBean(tokenMap, AuthenticationRefreshToken::class.java)
        }
        throw WindySecurityException("token解析错误!")
    }

    override fun removeAccessToken(token: String) {}

    override fun removeRefreshToken(refreshToken: String) {}

    override fun removeAccessTokenByRefreshToken(refreshToken: String) {}

    override fun findTokenByUserId(userId: String): AuthenticationToken? {
        return null
    }


}
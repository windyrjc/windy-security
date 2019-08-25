package com.github.windyrjc.security.core.service.impl

import com.github.windyrjc.security.core.AuthenticationRefreshToken
import com.github.windyrjc.security.core.AuthenticationToken
import com.github.windyrjc.security.core.exception.WindySecurityException
import com.github.windyrjc.security.core.service.AuthenticationTokenService
import com.fasterxml.uuid.EthernetAddress
import com.fasterxml.uuid.Generators
import org.springframework.beans.factory.InitializingBean
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.data.redis.serializer.StringRedisSerializer
import java.util.concurrent.TimeUnit

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
 * @Date 2019-04-02 11:17
 */
class RedisAuthenticationTokenService(var redisTemplate: RedisTemplate<Any, Any>,
                                      var stringRedisTemplate: StringRedisTemplate,
                                      var prefix: String) : AuthenticationTokenService, InitializingBean {
    override fun afterPropertiesSet() {
        redisTemplate.keySerializer = StringRedisSerializer()
        redisTemplate.hashKeySerializer = StringRedisSerializer()
    }

    private val ID_TO_ACCESS = "id_to_access:"
    private val ACCESS_TO_REFRESH = "access_to_refresh:"
    private val ACCESS_TO_ACCESS_OBJ = "access_to_access_obj:"

    private val REFRESH_TO_REFRESH_OBJ = "refresh_to_refresh_obj:"
    private val REFRESH_TO_ACCESS = "refresh_to_access:"

    companion object {
        var uuidGen = Generators.timeBasedGenerator(EthernetAddress.fromInterface())
    }

    override fun removeAccessTokenByRefreshToken(tokenStr: String) {
        redisTemplate.delete(buildKey(REFRESH_TO_ACCESS, tokenStr))
    }

    override fun findTokenByUserId(userId: String): AuthenticationToken? {
        val token = stringRedisTemplate.opsForValue().get(buildUserKey(userId)) ?: return null
        //todo token List模式
        return readAccessToken(token)
    }

    override fun createAccessToken(authenticationToken: AuthenticationToken): String {
        val uuid = stringRedisTemplate.opsForValue().get(buildUserKey(authenticationToken.authentication!!.id!!))
                ?: uuidGen.generate().toString()
        //create accessToken
        redisTemplate.opsForValue().set(buildKey(ACCESS_TO_ACCESS_OBJ, uuid), authenticationToken, authenticationToken.expireIn!!.toLong(), TimeUnit.SECONDS)
        //create id-token mapping
        stringRedisTemplate.opsForValue().set(buildUserKey(authenticationToken.authentication!!.id!!), uuid, authenticationToken.expireIn!!.toLong(), TimeUnit.SECONDS)
        return uuid
    }

    override fun readAccessToken(tokenStr: String): AuthenticationToken? {
        val authenticationToken = redisTemplate.opsForValue().get(buildKey(ACCESS_TO_ACCESS_OBJ, tokenStr))
                ?: return null
        //todo 读取失败 删除id-token 映射
        return if (authenticationToken is AuthenticationToken) {
            authenticationToken
        } else {
            throw WindySecurityException("token对象转化失败!")
        }
    }

    override fun createRefreshToken(refreshToken: AuthenticationRefreshToken): String {

        val uuid = stringRedisTemplate.opsForValue().get(buildKey(ACCESS_TO_REFRESH, refreshToken.accessToken!!))
                ?: uuidGen.generate().toString()
        redisTemplate.opsForValue().set(buildKey(REFRESH_TO_REFRESH_OBJ, uuid), refreshToken, refreshToken.expireIn!!.toLong(), TimeUnit.SECONDS)
        //refresh_to_access
        stringRedisTemplate.opsForValue().set(buildKey(REFRESH_TO_ACCESS, uuid), refreshToken.accessToken!!, refreshToken.expireIn!!.toLong(), TimeUnit.SECONDS)
        //access_to_refresh
        stringRedisTemplate.opsForValue().set(buildKey(ACCESS_TO_REFRESH, refreshToken.accessToken!!), uuid, refreshToken.expireIn!!.toLong(), TimeUnit.SECONDS)
        return uuid
    }

    override fun readRefreshToken(tokenStr: String): AuthenticationRefreshToken? {
        val key = buildKey(REFRESH_TO_REFRESH_OBJ, tokenStr)
        val refreshToken = redisTemplate.opsForValue().get(key) ?: return null
        if (refreshToken is AuthenticationRefreshToken) {
            removeRefreshToken(tokenStr)
            redisTemplate.delete(buildKey(ACCESS_TO_REFRESH, refreshToken.accessToken!!))
            return refreshToken
        } else throw WindySecurityException("refresh_token 对象转化失败!")
    }

    override fun removeAccessToken(tokenStr: String) {
        val accessToken = readAccessToken(tokenStr) ?: return
        redisTemplate.delete(buildKey(ACCESS_TO_ACCESS_OBJ, tokenStr))
        val refreshToken = stringRedisTemplate.opsForValue().get(buildKey(ACCESS_TO_REFRESH, tokenStr))
        stringRedisTemplate.delete(buildKey(ACCESS_TO_REFRESH, tokenStr))
        if (refreshToken != null) {
            stringRedisTemplate.delete(buildKey(REFRESH_TO_ACCESS, refreshToken))
            redisTemplate.delete(buildKey(REFRESH_TO_REFRESH_OBJ, refreshToken))
        }
        //删除access_token 和 id 的关系映射
        stringRedisTemplate.delete(buildUserKey(accessToken.authentication!!.id!!))
    }

    override fun removeRefreshToken(tokenStr: String) {
        redisTemplate.delete(buildKey(REFRESH_TO_REFRESH_OBJ, tokenStr))
        removeAccessTokenByRefreshToken(tokenStr)
    }

    private fun buildKey(type: String, key: String): String {
        return "$prefix$type:$key"
    }


    private fun buildUserKey(userId: String): String {
        return "$prefix$ID_TO_ACCESS$userId"
    }
}
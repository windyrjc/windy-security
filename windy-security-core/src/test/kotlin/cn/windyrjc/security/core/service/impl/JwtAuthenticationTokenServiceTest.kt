package cn.windyrjc.security.core.service.impl

import cn.windyrjc.security.core.AuthenticationToken
import cn.windyrjc.security.core.AuthenticationUser
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.Before
import org.junit.Test

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
 *
 * @Date 2019-02-14 21:24
 */
class JwtAuthenticationTokenServiceTest {

    lateinit var tokenService: JwtAuthenticationTokenService

    lateinit var token: AuthenticationToken

    var objectMapper = ObjectMapper()
    @Before
    fun setUp() {
        tokenService = JwtAuthenticationTokenService("testKey")

        val authentication = AuthenticationUser()
        authentication.id = "1"
        authentication.permissions = listOf("read", "write")
        authentication.roles = listOf("admin")
        authentication.userDetail = objectMapper.writeValueAsString(UserInfo("david", 12, Result("test")))
        token = AuthenticationToken(authentication, 7200, mapOf("test" to "hello "))
    }

    @Test
    fun tokenToAuthentication() {
        val token = tokenService.readAccessToken(token = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NTE3NjU1NDksInRva2VuIjp7ImF1dGhlbnRpY2F0aW9uIjp7ImlkIjoiMSIsInJvbGVzIjpbImFkbWluIl0sInBlcm1pc3Npb25zIjpbInJlYWQiLCJ3cml0ZSJdLCJ1c2VyRGV0YWlscyI6IntcInVzZXJuYW1lXCI6XCJkYXZpZFwiLFwiYWdlXCI6MTIsXCJyZXN1bHRcIjp7XCJuYW1lXCI6XCJ0ZXN0XCJ9fSIsIm5hbWUiOiIxIiwiYXV0aGVudGljYXRlZCI6dHJ1ZSwiY3JlZGVudGlhbHMiOm51bGwsImRldGFpbHMiOiJ7XCJ1c2VybmFtZVwiOlwiZGF2aWRcIixcImFnZVwiOjEyLFwicmVzdWx0XCI6e1wibmFtZVwiOlwidGVzdFwifX0iLCJwcmluY2lwYWwiOiIxIiwiYXV0aG9yaXRpZXMiOlt7ImF1dGhvcml0eSI6InJlYWQifSx7ImF1dGhvcml0eSI6IndyaXRlIn1dfSwiZXhwaXJlSW4iOjcyMDAsImFkZGl0aW9uYWxJbmZvIjp7InRlc3QiOiJoZWxsbyAifX0sInN1YiI6IjEiLCJleHAiOjE1NTE3NzI3NDl9.cIgR5BL92OUMlpiIxrGS1521-b0Skq9itENqE74QMZE")
        println(token)
    }

    @Test
    fun authenticationToToken() {
        val token = tokenService.createAccessToken(token)
        println(token)
    }
}
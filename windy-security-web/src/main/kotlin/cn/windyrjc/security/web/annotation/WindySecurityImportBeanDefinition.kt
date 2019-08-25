package cn.windyrjc.security.web.annotation

import cn.windyrjc.security.core.service.TokenService
import cn.windyrjc.security.web.config.JwtAuthenticationServiceConfig
import cn.windyrjc.security.web.config.RedisAuthenticationTokenServiceConfig
import org.springframework.context.annotation.ImportSelector
import org.springframework.core.type.AnnotationMetadata

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
 * @Date 2019-04-02 12:03
 */
class WindySecurityImportBeanDefinition : ImportSelector {


    override fun selectImports(importingClassMetadata: AnnotationMetadata): Array<String> {
        val map = importingClassMetadata.getAnnotationAttributes(EnableWindySecurity::class.java.name) ?: return arrayOf()
        val service = map["service"] as TokenService
        return when (service) {
            TokenService.JWT -> {
                arrayOf(JwtAuthenticationServiceConfig::class.java.name)
            }
            TokenService.REDIS -> {
                arrayOf(RedisAuthenticationTokenServiceConfig::class.java.name)
            }
        }
    }

//    @Autowired
//    lateinit var properties: WindySecurityWebProperties
//    @Autowired
//    lateinit var redisTemplate: RedisTemplate<Any, Any>

//    override fun registerBeanDefinitions(importingClassMetadata: AnnotationMetadata, registry: BeanDefinitionRegistry) {
//        val map = importingClassMetadata.getAnnotationAttributes(EnableWindySecurity::class.java.name) ?: return
//        val service = map["service"] as TokenService
//        when (service) {
//            TokenService.JWT -> {
//                doJwt(registry)
//            }
//            TokenService.REDIS -> {
//                doRedis(registry)
//            }
//        }
//    }
//
//    private fun doJwt(registry: BeanDefinitionRegistry) {
//        val bean = GenericBeanDefinition()
//        bean.setBeanClass(JwtAuthenticationTokenService::class.java)
//        val constructors = ConstructorArgumentValues()
////        constructors.addIndexedArgumentValue(0, env!!["windy.security.jwt.jwtKey"])
//        bean.constructorArgumentValues = constructors
//        registry.registerBeanDefinition(TokenService.JWT.beanName, bean)
//    }
//
//    private fun doRedis(registry: BeanDefinitionRegistry) {
//        val bean = GenericBeanDefinition()
//        bean.setBeanClass(RedisAuthenticationTokenServiceConfig::class.java)
//        val constructors = ConstructorArgumentValues()
////        constructors.addIndexedArgumentValue(0, context!!.getBean(RedisTemplate::class.java))
////        constructors.addIndexedArgumentValue(1, context!!.getBean(WindySecurityWebProperties::class.java).redis.prefix)
//        bean.constructorArgumentValues = constructors
//        registry.registerBeanDefinition(TokenService.REDIS.beanName, bean)
//    }

}
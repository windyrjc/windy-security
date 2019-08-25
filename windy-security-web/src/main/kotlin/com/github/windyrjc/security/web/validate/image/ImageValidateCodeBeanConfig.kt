package com.github.windyrjc.web.validate.image

import com.github.windyrjc.web.properties.WindySecurityWebProperties
import com.github.windyrjc.web.validate.reposiroty.ValidateCodeRepository
import com.google.code.kaptcha.impl.DefaultKaptcha
import com.google.code.kaptcha.util.Config
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
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
 * @Date 2019-04-01 12:28
 */
@Configuration
@ConditionalOnProperty(prefix = "windy.security.imageCode", name = ["enable"], havingValue = "true")
class ImageValidateCodeBeanConfig {

    @Autowired
    lateinit var properties: WindySecurityWebProperties

    val KAPTCHA_BORDER = "kaptcha.border"
    val KAPTCHA_TEXTPRODUCER_FONT_COLOR = "kaptcha.textproducer.font.color"
    val KAPTCHA_TEXTPRODUCER_CHAR_SPACE = "kaptcha.textproducer.char.space"
    val KAPTCHA_IMAGE_WIDTH = "kaptcha.image.width"
    val KAPTCHA_IMAGE_HEIGHT = "kaptcha.image.height"
    val KAPTCHA_TEXTPRODUCER_CHAR_LENGTH = "kaptcha.textproducer.char.length"
    val KAPTCHA_IMAGE_FONT_SIZE = "kaptcha.textproducer.font.size"
    val KAPTCHA_NOISE_IMP = "kaptcha.noise.impl"

    @Bean
    @ConditionalOnMissingBean
    fun imageValidateCodeGenerator(): ImageValidateCodeGenerator {
        return ImageValidateCodeGenerator(properties.imageCode)
    }

    @Bean
    fun imageValidateCodeService(generator: ImageValidateCodeGenerator, repository: ValidateCodeRepository): ImageValidateCodeService {
        return ImageValidateCodeService(generator, repository)
    }

    @Bean
    fun captchaConfig(): DefaultKaptcha {
        val propertie = Properties()
        propertie[KAPTCHA_BORDER] = properties.imageCode.border
        propertie[KAPTCHA_TEXTPRODUCER_FONT_COLOR] = properties.imageCode.borderColor
        propertie[KAPTCHA_TEXTPRODUCER_CHAR_SPACE] = properties.imageCode.charSpace
        propertie[KAPTCHA_IMAGE_WIDTH] = properties.imageCode.width
        propertie[KAPTCHA_IMAGE_HEIGHT] = properties.imageCode.height
        propertie[KAPTCHA_IMAGE_FONT_SIZE] = properties.imageCode.fontSize
        propertie[KAPTCHA_TEXTPRODUCER_CHAR_LENGTH] = properties.imageCode.length.toString()
        propertie[KAPTCHA_NOISE_IMP] = "com.google.code.kaptcha.impl.DefaultNoise"
        val config = Config(propertie)
        val defaultKaptcha = DefaultKaptcha()
        defaultKaptcha.config = config
        return defaultKaptcha
    }

}
# windy security

windy-security 是适用于spring boot的安全框架,它使用kotlin语言编写,基于前后端分离架构(暂时是单体应用)的后端保护,鉴权,它构建在spring-security之上,简化接入安全框架的步骤.

## 起步

首先,需要引入maven包

```xml
         <dependency>
            <groupId>com.github.windyrjc</groupId>
            <artifactId>windy-security-web</artifactId>
            <version>${latest version}</version>
        </dependency>
```

其次,你需要打一个注解:

```java
@SpringBootApplication
@EnableWindySecurity
public class WindySecurityDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(WindySecurityDemoApplication.class, args);
    }
}
```

## 登录

windy security 修改了spring security 默认的登录方法,转而试用注解定义url 的方式

```java
@Component
//登录url
@AuthMapping("/auth/login")
public class MyAuthenticationService implements AuthenticationService<UserBean> {

    public UserDetails loadUserByCredential(UserBean body, PasswordEncoder passwordEncoder) {
        //todo 通过userId 查数据库
        //todo password 加密验证(passwordEncoder.matches())等

        //此处定义用户基本信息,可以在后续接口中使用
        UserDetail userDetail = new UserDetail("david", "11", "asdfsfs");
        return UserDetails.instance()
                .id("windyrjc")
                .userDetail(userDetail)
                .addPermission("admin")
                .addRoles("read", "write", "admin");
    }
}
```

- UserBean 对象为登录表单的bean,登录需要实现@AuthMapping 注解和AuthenticationService 方法,前端需要按照UserBean定义的格式以post json的格式传参
- UserDetail对象为自定义对象,在此处登录的对象可以在后续登录的过程中被解析
- 需要实现的方法的返回值为UserDetails对象,用户需要自行构建该对象,通常是数据库查询到信息后构建用户名(id),权限(permission),角色(roles)和自定义对象等信息

```java
@RestController
public class TestController {

    @GetMapping("/test")
    public Response test(UserDetail userDetail) {
        return Response.success();
    }
```

自定义对象需要在配置信息中配置

```yaml
windy:
  security:
    injectClass: UserDetail
```

### 更换jwt 私钥

```yaml
windy:
  security:
    jwt:
      jwtKey: test
```

## refresh token

- Access Token携带了直接访问资源的必要信息。换句话说，当客户端将`access token`传给管理资源的服务器时，该服务器可以使用`token`中包含的信息来决定是否授权给客户端。`access token`通常有一个过期时间，而且通常时间非常短暂。

![](https://user-gold-cdn.xitu.io/2018/1/14/160f2bcf5950e9cd?w=1280&h=800&f=png&s=68325)

- Refresh Token携带了用来获取新的access token的必要信息。换句话说，当客户端需要使用access token来访问特定资源的时候，客户端可以使用refresh token来向认证服务器请求下发新的access token。通常情况下，当旧的access token失效之后，才需要获得新的access token，或者是在第一次访问资源的时候。refresh token也有过期时间但是时间相对较长。refresh token对存储的要求通常会非常严格，以确保它不会被泄漏。它们也可以被授权服务器列入黑名单。

![](https://user-gold-cdn.xitu.io/2018/1/14/160f2c332aa4c34a?w=1280&h=800&f=png&s=74512)

在windy-security 中,refresh_token的使用很简单

```java
@RefreshMapping("/auth/refresh")
@Component
public class MyRefreshAuthenticationService implements RefreshAuthenticationService {

    @NotNull
    public UserDetails loadUserByCredential(@NotNull String id, @NotNull PasswordEncoder passwordEncoder) {
        return UserDetails.instance()
                          .id("windyrjc")
                          .userDetail(userDetail)
                          .addPermission("admin")
                          .addRoles("read", "write", "admin");
    }
}
```

实现RefreshMapping注解,请求的时候使用post并在body中传递json

![5c9b3c0b5888c](https://i.loli.net/2019/03/27/5c9b3c0b5888c.png)

## 基于redis的token存储

jwt模式虽然简单,但是会存在一些安全风险,比如不可以控制失效时间等,windy-security 提供了基于redis的token存储方案

```java
@SpringBootApplication
@EnableWindySecurity(service = TokenService.REDIS)
public class WindySecurityDemoApplication {
     public static void main(String[] args) {
         SpringApplication.run(WindySecurityDemoApplication.class, args);
     }
}
```

只需要将service 换成redis 并引入spring-boot-starter-redis 包即可

```xml
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>    
```

## 图形验证码

图形验证码是常用防刷的手段,在windy-security 中,实现验证码的方法很简单,首先,你需要在配置文件中添加

```yaml
windy:
  security:
    imageCode:
#      是否开启
      enable: true
```

图形验证码可以配置的选项有

```kotlin
/**
     * 宽度
     */
    var width = "100"

    /**
     * 高度
     */
    var height = "40"

    /**
     * 边框颜色，合法值： r,g,b (and optional alpha) 或者 white,black,blue.
     */
    var borderColor = "black"

    /**
     * 图片边框
     */
    var border = "no"

    /**
     * 默认图片间隔
     */
    var charSpace = "5"

    /**
     * 验证码文字大小
     */
    var fontSize = "30"

    /**
     * 自定义额外验证图形验证码的url,以逗号形式隔开
     */
    var extraUrls: String? = null

    /**
     * 自定义额外验证图形验证码传入参数
     */
    var imageCodeParameter: String = "code"
```

其次,你需要在你自定义的对象中实现ImageValidateCodeBean接口

```java
@Data
public class UserBean implements ImageValidateCodeBean {

    private String openId;
    //
    private String code;

    private String deviceId;

    //
    @NotNull
    public String getImageCode() {
        return code;
    }

    @NotNull
    public String getDeviceId() {
        return deviceId;
    }
}
```

主要实现的是imagecode 和deviceId 两个参数,windy-security 将根据这两个参数取得前端传入的验证码

验证码具体流程为:

1. 创建一个生成验证码的接口,前端传入一个唯一id(deviceId),调用windy-security 的generate()方法,该方法会返回一张验证码图片
   
   ```kotlin
   @RestController
   class ValidateCodeController{
   
       @Autowired
       lateinit var imageValidateCodeService: ImageValidateCodeService
   
       @GetMapping("/image")
       fun image(@RequestParam deviceId:String, request:HttpServletRequest, response:HttpServletResponse){
           imageValidateCodeService.generate(deviceId,response)
       }
   }
   ```

2. 前端请求的时候需要带上自定义表单中的自定义参数 deviceId 和 用户填的验证码

3. windy-security会判断验证码正确性

package cn.like.girl.blog.config.security;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.session.mgt.SessionValidationScheduler;
import org.apache.shiro.session.mgt.eis.JavaUuidSessionIdGenerator;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;
import org.apache.shiro.session.mgt.quartz.QuartzSessionValidationScheduler;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.crazycake.shiro.RedisCacheManager;
import org.crazycake.shiro.RedisManager;
import org.crazycake.shiro.RedisSessionDAO;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by HD on 2018/1/12.
 *
 * @author HD
 */
@Configuration
public class ShiroConfiguration {
    private String host;
    private int port;
    private int timeout;
    private String password;


    /**
     * redis管理器
     */
    public RedisManager redisManager() {
        RedisManager redisManager = new RedisManager();
        // 地址
        redisManager.setHost(host);
        // 端口
        redisManager.setPort(port);
        // 缓存过期时间
        redisManager.setExpire(1800);
        redisManager.setTimeout(timeout);
        // auth
        redisManager.setPassword(password);
        return redisManager;
    }

    /**
     * 缓存管理器 (Redis实现)
     * 说明：shiro-redis 开源插件
     */
    @Bean
    public RedisCacheManager cacheManager() {
        RedisCacheManager redisCacheManager = new RedisCacheManager();
        redisCacheManager.setRedisManager(redisManager());
        return redisCacheManager;
    }

    /**
     * 凭证匹配器
     */
    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        //散列算法:这里使用MD5算法;
        hashedCredentialsMatcher.setHashAlgorithmName("md5");
        //散列的次数
        hashedCredentialsMatcher.setHashIterations(1024);
        hashedCredentialsMatcher.setStoredCredentialsHexEncoded(true);
        return hashedCredentialsMatcher;
    }

    /**
     * 会话ID生成器
     */
    public JavaUuidSessionIdGenerator sessionIdGenerator() {
        SessionIdGenerator sessionIdGenerator = new JavaUuidSessionIdGenerator();
        return (JavaUuidSessionIdGenerator) sessionIdGenerator;
    }

    /**
     * 会话Cookie模板
     */
    public SimpleCookie rememberMeCookie() {
        SimpleCookie simpleCookie = new SimpleCookie("sid");
        simpleCookie.setHttpOnly(true);
        // 记住密码
        // cookie有效时间7天
        // 单位秒;
        simpleCookie.setMaxAge(604800);
        return simpleCookie;
    }

    /**
     * 会话DAO (redis实现)
     * 说明：shiro-redis开源插件
     */
    @Bean
    public RedisSessionDAO redisSessionDAO() {
        RedisSessionDAO redisSessionDAO = new RedisSessionDAO();
        redisSessionDAO.setRedisManager(redisManager());
        redisSessionDAO.setSessionIdGenerator(sessionIdGenerator());
        return redisSessionDAO;
    }

    /**
     * 会话验证调度器
     *
     * @return org.apache.shiro.session.mgt.quartz.QuartzSessionValidationScheduler
     */
    public QuartzSessionValidationScheduler sessionValidationScheduler(){
        QuartzSessionValidationScheduler sessionValidationScheduler = new QuartzSessionValidationScheduler();
        sessionValidationScheduler.setSessionValidationInterval(1800000L);
        sessionValidationScheduler.setSessionManager(sessionManager());
        return  sessionValidationScheduler;
    }

    /**
     * 会话管理器
     * 说明：shiro-redis开源插件
     */
    @Bean
    public DefaultWebSessionManager sessionManager() {
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        sessionManager.setGlobalSessionTimeout(1800000L);
        sessionManager.setDeleteInvalidSessions(true);
        sessionManager.setSessionValidationSchedulerEnabled(true);
        sessionManager.setSessionValidationScheduler(sessionValidationScheduler());
        sessionManager.setSessionDAO(redisSessionDAO());
        sessionManager.setSessionIdCookieEnabled(true);
        sessionManager.setSessionIdCookie(rememberMeCookie());
        return sessionManager;
    }

    /**
     * cookie管理对象;记住我功能
     */
    @Bean
    public CookieRememberMeManager rememberMeManager() {
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
        cookieRememberMeManager.setCookie(rememberMeCookie());
        //rememberMe cookie加密的密钥 建议每个项目都不一样 默认AES算法 密钥长度(128 256 512 位)
        cookieRememberMeManager.setCipherKey(Base64.decode("3AvVhmFLUs0KTA3Kprsdag=="));
        return cookieRememberMeManager;
    }



    @Bean
    public ShiroFilterFactoryBean shirFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        //拦截器.
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        // 配置不会被拦截的链接 顺序判断
        filterChainDefinitionMap.put("/doLogin", "anon");
        filterChainDefinitionMap.put("/css/**", "anon");
        filterChainDefinitionMap.put("/images/**", "anon");
        filterChainDefinitionMap.put("/js/**", "anon");
        filterChainDefinitionMap.put("/libs/**", "anon");
        // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
        shiroFilterFactoryBean.setLoginUrl("/login");
        //未授权界面;
        shiroFilterFactoryBean.setUnauthorizedUrl("/403");
        // 配置需要验证登录后访问的链接
        filterChainDefinitionMap.put("/**", "authc");
        // 从数据库获取
//        List<AdminMenu> list = systemService.selectAllMenu();
//
//        for (AdminMenu menu : list) {
//            filterChainDefinitionMap.put(menu.getMenuUrl(), "authc");
//        }
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }

    /**
     * 安全管理器
     *
     * @return org.apache.shiro.mgt.SecurityManager
     */
    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
//        securityManager.setRealm(myShiroRealm());
        // 自定义缓存实现 使用redis
        securityManager.setCacheManager(cacheManager());
        // 自定义session管理 使用redis
        securityManager.setSessionManager(sessionManager());
        //注入记住我管理器;
        securityManager.setRememberMeManager(rememberMeManager());
        return securityManager;
    }



    /**
     * Shiro生命周期处理器
     */
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor(){
        return new LifecycleBeanPostProcessor();
    }

    /**
     * 相当于调用SecurityUtils.setSecurityManager(securityManager)
     */
    @Bean
    public MethodInvokingFactoryBean methodInvokingFactoryBean(){
        MethodInvokingFactoryBean methodInvokingFactoryBean = new MethodInvokingFactoryBean();
        methodInvokingFactoryBean.setStaticMethod("org.apache.shiro.SecurityUtils.setSecurityManager");
        methodInvokingFactoryBean.setArguments(securityManager());
        return methodInvokingFactoryBean;
    }

    /**
     * 开启注解支持(shiro aop)
     * 使用代理方式;所以需要开启代码支持;
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }
}

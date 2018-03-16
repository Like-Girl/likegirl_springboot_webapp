package cn.like.girl.blog.config.security;

import com.houde.sc.man.core.security.AuthDetailsSource;
import com.houde.sc.man.core.security.AuthEntryPoint;
import com.houde.sc.man.core.security.filter.GeeVerifyProcessFilter;
import com.houde.sc.man.core.security.handler.WebAccessDeniedHandler;
import com.houde.sc.man.core.security.handler.WebLoginFailureHandler;
import com.houde.sc.man.core.security.handler.WebLoginSuccessHandler;
import com.houde.sc.man.core.security.provider.AuthProvider;
import com.houde.sc.man.core.security.provider.RememberMeAuthProvider;
import com.houde.sc.man.core.security.service.AuthRememberMeServices;
import com.houde.sc.man.core.security.service.AuthUserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import javax.annotation.Resource;

/**
 * Created by HD on 2018/1/16.
 */

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled = true, prePostEnabled = true, securedEnabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Value("${app.security.key}")
    private String key;

    @Value("${app.security.login.url}")
    private String loginUrl;

    @Value("${app.security.cookie.session}}")
    private String cookieSession;

    @Value("${app.security.cookie.remember}")
    private String cookieRemember;


    @Resource
    private AuthProvider authProvider;

    /**
     * configure(WebSecurity): Web层面的配置，一般用来配置无需安全检查的路径
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/session/status", "/static/**", "/error/**", "/druid/**");
    }

    /**
     * configure(HttpSecurity): Request层面的配置，对应XML Configuration中的<http>元素
     *
     * anonymous ：允许匿名访问
     * permitAll ：任何人都允许访问
     * hasRole ：指定角色允许访问
     * hasAuthority ：拥有权限允许访问
     *
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .antMatchers("/login", "/login-error", "/register", "/user/register/**", "/forgot/**", "/captchas/**", "/help")
                .anonymous()
                // 设置
          /*      .antMatchers("/my/setting").hasAnyRole("SYSTEM","COMMUNITY","SUPPLIER")
                .antMatchers("/my/setting*//**").hasAnyRole("SYSTEM","COMMUNITY","SUPPLIER")*/

                // 其他所有资源都需要权限
                .anyRequest().authenticated()
                // 登录项配置
                .and()
                .formLogin()
                // 会被successHandler覆盖
                //successHandler defaultTargetUrl 默认：/
//                .defaultSuccessUrl("/route-home", false)
                .loginPage(loginUrl)
                .usernameParameter("usr")
                .passwordParameter("pwd")
                .authenticationDetailsSource(authDetailsSource())
                .failureHandler(failureHandler())
                .successHandler(successHandler())
                // 登出项配置
                .and()
                .logout()
                .invalidateHttpSession(true)
                .logoutSuccessUrl(loginUrl)
                .deleteCookies(cookieSession, cookieRemember)
                // 记住我
                .and()
                .rememberMe()
                .rememberMeServices(rememberMeServices())
                .authenticationSuccessHandler(successHandler());

        http.addFilterBefore(logoutFilter(), LogoutFilter.class);

        http.exceptionHandling().authenticationEntryPoint(authEntryPoint());

        http.exceptionHandling().accessDeniedHandler(accessDeniedHandler());
    }

    /**
     * configure(AuthenticationManagerBuilder): 身份验证配置，用于注入自定义身份验证Bean和密码校验规则
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authProvider)
                .authenticationProvider(rememberMeAuthProvider());
    }

    @Bean
    public AuthDetailsSource authDetailsSource() {
        return new AuthDetailsSource();
    }
    @Bean
    public WebLoginFailureHandler failureHandler() {
        return new WebLoginFailureHandler();
    }

    public WebLoginSuccessHandler successHandler() {
        WebLoginSuccessHandler successHandler = new WebLoginSuccessHandler();
        successHandler.setDefaultTargetUrl("/route-home");
        return successHandler;
    }

    @Bean
    public AuthUserService authUserService() {
        return new AuthUserService();
    }

    @Bean
    public AuthRememberMeServices rememberMeServices() {
        AuthRememberMeServices rememberMeServices = new AuthRememberMeServices(key, authUserService());
        rememberMeServices.setAuthenticationDetailsSource(authDetailsSource());
        rememberMeServices.setParameter("rememberme");
        rememberMeServices.setCookieName(cookieRemember);
        rememberMeServices.setTokenValiditySeconds(3600000);
        return rememberMeServices;
    }

    @Bean
    public GeeVerifyProcessFilter geeVerifyProcessFilter() {
        GeeVerifyProcessFilter geeVerifyProcessFilter = new GeeVerifyProcessFilter();
        geeVerifyProcessFilter.setEnableServerVerify(true);
        geeVerifyProcessFilter.setEnableVerify(false);
        return geeVerifyProcessFilter;
    }

    @Bean
    public LogoutFilter logoutFilter() {
        return new LogoutFilter(loginUrl, securityContextLogoutHandler(), rememberMeServices());
    }

    @Bean
    public SecurityContextLogoutHandler securityContextLogoutHandler() {
        return new SecurityContextLogoutHandler();
    }

    @Bean
    public RememberMeAuthProvider rememberMeAuthProvider() {
        return new RememberMeAuthProvider(key);
    }

    @Bean
    public AuthEntryPoint authEntryPoint() {
        return new AuthEntryPoint(loginUrl);
    }

    @Bean
    public WebAccessDeniedHandler accessDeniedHandler(){
        WebAccessDeniedHandler accessDeniedHandler = new WebAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/403");
        accessDeniedHandler.setLoginPage(loginUrl);
        return accessDeniedHandler;
    }

}

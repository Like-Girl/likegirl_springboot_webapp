package cn.like.girl.blog.config.security.service;

import com.houde.sc.man.core.security.model.AuthDetails;
import com.houde.sc.man.core.security.model.AuthUser;
import com.houde.sc.man.domain.RememberMeToken;
import com.houde.sc.man.domain.RoleEnum;
import com.houde.sc.man.service.RememberMeDBService;
import com.houde.sc.man.util.StringUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.rememberme.CookieTheftException;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;

/**
 * Created by 009 on 2017/5/15.
 * 记住密码登陆验证service类
 * 处理记住密码登陆登出事件
 * 登陆类型：
 *  1.使用账号密码登陆
 *      1.勾选记住密码选项
 *      2.未勾选记住密码项
 *  2.使用Cookies登陆
 *      1.仅限Remember-Me登陆
 */
public class AuthRememberMeServices implements RememberMeServices,
        InitializingBean, LogoutHandler {
    // ~ logger
    private static final Logger LOG = LoggerFactory.getLogger(AuthRememberMeServices.class);

    // ~ Static fields/initializers
    // =====================================================================================
    public static final String SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY = "remember-me";
    public static final String DEFAULT_PARAMETER = "remember-me";
    public static final int TWO_WEEKS_S = 1209600;
    public static final String AUTO_LOGIN_AUTH_ATTR_NAME = "cookie_login_auth_detail";

    private static final String DELIMITER = ":";

    public static final int DEFAULT_SERIES_LENGTH = 16;
    public static final int DEFAULT_TOKEN_LENGTH = 16;


    // ~ Instance fields
    // ================================================================================================
    protected final Log logger = LogFactory.getLog(getClass());

    private SecureRandom random = new SecureRandom();
    private int seriesLength = 16;
    private int tokenLength = 16;

    // ~ Inject component
    @Autowired
    RememberMeDBService rememberMeDBService;


    protected final MessageSourceAccessor messages = SpringSecurityMessageSource
            .getAccessor();

    private UserDetailsService userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    private String cookieName = SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY;
    private String cookieDomain;
    private String parameter = DEFAULT_PARAMETER;
    private boolean alwaysRemember;
    private String key;
    private int tokenValiditySeconds = TWO_WEEKS_S;
    private Boolean useSecureCookie = null;
    private Method setHttpOnlyMethod;
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    public AuthRememberMeServices(String key, UserDetailsService userDetailsService) {
        Assert.hasLength(key, "key cannot be empty or null");
        Assert.notNull(userDetailsService, "UserDetailsService cannot be null");
        this.key = key;
        this.userDetailsService = userDetailsService;
        this.setHttpOnlyMethod = ReflectionUtils.findMethod(Cookie.class, "setHttpOnly",
                boolean.class);
    }

    /**
     * 检查参数
     * @throws Exception
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.hasLength(key, "key cannot be empty or null");
        Assert.notNull(userDetailsService, "A UserDetailsService is required");
    }

    /**
     * 使用cookies自动登录
     * @param request
     * @param response
     * @return
     */
    @Override
    public final Authentication autoLogin(HttpServletRequest request,
                                          HttpServletResponse response) {
        String rememberMeCookie = extractRememberMeCookie(request);

        if (rememberMeCookie == null) {
            return null;
        }

        logger.debug("Remember-me cookie detected");

        if (rememberMeCookie.length() == 0) {
            logger.debug("Cookie was empty");
            cancelCookie(request, response);
            return null;
        }

        UserDetails user;

        try {
            String[] cookieTokens = decodeCookie(rememberMeCookie);
            user = processAutoLoginCookie(cookieTokens, request, response);
            userDetailsChecker.check(user);

            logger.debug("Remember-me cookie accepted");

            return createSuccessfulAuthentication(request, user);
        }
        catch (CookieTheftException cte) {
            cancelCookie(request, response);
            throw cte;
        }
        catch (UsernameNotFoundException noUser) {
            logger.debug("Remember-me login was valid but corresponding user not found.",
                    noUser);
        }
        catch (InvalidCookieException invalidCookie) {
            logger.debug("Invalid remember-me cookie: " + invalidCookie.getMessage());
        }
        catch (AccountStatusException statusInvalid) {
            logger.debug("Invalid UserDetails: " + statusInvalid.getMessage());
        }
        catch (RememberMeAuthenticationException e) {
            logger.debug(e.getMessage());
        }
        catch (Exception e) {
            e.printStackTrace();
            logger.debug(e.getMessage());
        }

        cancelCookie(request, response);
        return null;
    }


    /**
     * 使用remember-me based on cookies登陆成功后设置Authentication
     * @param request
     * @param user
     * @return
     */
    protected Authentication createSuccessfulAuthentication(HttpServletRequest request,
                                                            UserDetails user) {
        RememberMeAuthenticationToken auth = new RememberMeAuthenticationToken(key, user,
                authoritiesMapper.mapAuthorities(user.getAuthorities()));
        //set detail via detail source
        AuthUser userDetail = (AuthUser)auth.getPrincipal();
        request.setAttribute(AUTO_LOGIN_AUTH_ATTR_NAME, userDetail);
        auth.setDetails(authenticationDetailsSource.buildDetails(request));
        return auth;
    }

    /**
     * 登陆失败后删除Cookies
     * @param request
     * @param response
     */
    @Override
    public final void loginFail(HttpServletRequest request, HttpServletResponse response) {
        logger.debug("Interactive login attempt was unsuccessful.");
        cancelCookie(request, response);
        onLoginFail(request, response);
    }

    /**
     * 登陆失败时触发失败事件
     * @param request
     * @param response
     */
    protected void onLoginFail(HttpServletRequest request, HttpServletResponse response) {
    }

    /**
     * 登陆成功时触发事件
     * @param request
     * @param response
     * @param successfulAuthentication
     */
    @Override
    public final void loginSuccess(HttpServletRequest request,
                                   HttpServletResponse response, Authentication successfulAuthentication) {
        //判断是否勾选记住密码选项
        if (!rememberMeRequested(request, parameter)) {
            logger.debug("Remember-me login not requested.");
            return;
        }

        onLoginSuccess(request, response, successfulAuthentication);
    }


    /**
     * 使用Remember-Me登陆成功时的操作(使用用户密码登陆并勾选记住密码选项的时候)
     * 1.根据authentication获取detail创建token记录到db
     * 2.添加Token到Cookies
     * @param request
     * @param response
     * @param successfulAuthentication
     */
    protected void onLoginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication successfulAuthentication) {
        String username = successfulAuthentication.getName();
        checkSupport(successfulAuthentication);
        Object detailObj = successfulAuthentication.getDetails();
        //Assert
        Assert.isInstanceOf(AuthDetails.class, detailObj, "Authentication Detail Only Support AuthDetail Type.");
        if(!(detailObj instanceof AuthDetails)) {
            throw new RememberMeAuthenticationException("Authentication Detail Only Support AuthDetail Type.");
        }
        AuthDetails details = AuthDetails.toThis(detailObj);
        String roleValue = details.getRole();
        RoleEnum type = RoleEnum.valueOf(roleValue);//findType(roleValue);

        this.logger.debug("Creating new persistent login for user a" + username);
        RememberMeToken persistentToken = new RememberMeToken(this.generateSeriesData(), type.getValue(), username,
                this.generateTokenData(), StringUtil.date2timestamp(new Date()));

        try {
            this.rememberMeDBService.createNewToken(persistentToken);
            this.addCookie(persistentToken, request, response);
        } catch (DataAccessException dae) {
            this.logger.error("Failed to save persistent token ", dae);
        }
    }


    /**
     * 验证Cookies并获取User Details
     * @param cookieTokens
     * @param request
     * @param response
     * @return
     */
    protected AuthUser processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request, HttpServletResponse response) {
        //LOG.info("Cookie Login Request Header:\n{}", JSON.toJSONString(request.getHeader("cookie")));
        if(cookieTokens.length != 2) {
            throw new InvalidCookieException("Cookie  token did not contain 2 tokens, but contained '" + Arrays.asList(cookieTokens) + "'");
        } else {
            String presentedSeries = cookieTokens[0];
            String presentedToken = cookieTokens[1];
            RememberMeToken token = this.rememberMeDBService.getTokenForSeries(presentedSeries);
            if(token == null) {
                throw new RememberMeAuthenticationException("No  persistent token found for series id: " + presentedSeries);
            } else if(!presentedToken.equals(token.getToken())) {
                this.rememberMeDBService.removeUserTokens(token.getUsername(), token.getUserrole());
                throw new CookieTheftException(this.messages.getMessage(" PersistentTokenBasedRememberMeServices.cookieStolen", "Invalid remember-me token (Series/token) mismatch. Implies previous cookie theft attack."));
            } else if(token.getLastused().getTime()
                    + (long)this.getTokenValiditySeconds() * 1000L < System.currentTimeMillis()) {
                this.rememberMeDBService.removeUserTokens(token.getUsername(), token.getUserrole());
                throw new RememberMeAuthenticationException(" Remember-me login has expired");
            } else {
                if(this.logger.isDebugEnabled()) {
                    this.logger.debug(" Refreshing persistent login token for user '" + token.getUsername() + "', series '" + token.getSeries() + "'");
                }
                RememberMeToken newToken = new RememberMeToken(token.getSeries(), token.getUserrole(), token.getUsername(),
                        this.generateTokenData(), StringUtil.date2timestamp(new Date()));
                try {
                    this.rememberMeDBService.updateToken(newToken);
                    this.addCookie(newToken, request, response);
                } catch (DataAccessException dae) {
                    this.logger.error(" Failed to update token: ", dae);
                    throw new RememberMeAuthenticationException("Autologin failed due to data access problem");
                }

                RoleEnum typeEnum = RoleEnum.getByValue(token.getUserrole());// findType(token.getUserrole());
                Assert.notNull(typeEnum, "Role Type is Unrecognized for "+token.getUserrole());
                AuthUser authUser = this.getUserDetailsService().loadUserByUsername(token.getUsername(), typeEnum);
                //
                if(authUser == null) {
                    this.rememberMeDBService.removeUserTokens(token.getUsername(), token.getUserrole());
                    cancelCookie(request, response);
                    throw new RememberMeAuthenticationException("User Not Found");
                }
                return authUser;
            }
        }

    }


    /**
     * 登出处理(All Type login)
     * 检查当前会话，判断是否带有记住密码选项的常规登陆或使用Remember-Me的Cookies登陆
     * 使当前会话无效，并清除客户端Cookie和服务端token
     * @param request
     * @param response
     * @param authentication
     */
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (logger.isDebugEnabled()) {
            logger.debug("Logout of user "
                    + (authentication == null ? "Unknown" : authentication.getName()));
        }

        //检查是否为验证过请求（甄别Client Session Status）
        if(authentication == null) {
            commonLogoutProcess(request, response, authentication);
            return;
        }

        logoutProcess(request, response, authentication);
    }

    /**
     * 检查是否支持handle
     * @param authentication
     * @return
     */
    private boolean checkSupport(Authentication authentication) {
        return (checkUserPasswordSupport(authentication)
                || checkRememberMeLogoutSupport(authentication));
    }

    /**
     * 检查Auth类型，是否支持userpassword登陆验证
     * @param authentication
     * @return
     */
    private boolean checkUserPasswordSupport(Authentication authentication) {
        Assert.notNull(authentication, "Null Auth Not Support.");
        Object obj = authentication.getDetails();
        Assert.isInstanceOf(AuthDetails.class, obj, "Authentication Detail Only Support AuthDetail Type.");
        if(!(obj instanceof AuthDetails)) {
            throw new RememberMeAuthenticationException("Authentication Detail Only Support AuthDetail Type.");
        }
        return true;
    }

    /**
     * 检查Auth类型，是否支持rememberme登陆验证
     * @param authentication
     * @return
     */
    private boolean checkRememberMeLogoutSupport(Authentication authentication) {
        Assert.notNull(authentication, "Null Auth Not Support.");
        Object obj = authentication.getPrincipal();
        Assert.notNull(obj, "Null Principal Not Support.");
        Assert.isInstanceOf(AuthUser.class, obj, "Authentication Detail Only Support AuthUser Type.");
        return (obj instanceof AuthUser);
    }

    private void logoutProcess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        //检查是否为handler匹配的类型
        if(!checkSupport(authentication)) {
            return;
        }
        //获取并检查auth中的remember-me参数
        Object detailObj = authentication.getDetails();
        AuthDetails details = AuthDetails.toThis(detailObj);
        boolean isFromRememberMe = details.getRememberme();
        if(!isFromRememberMe) {
            //LOG.info("Not Remember-Me logout type,forwarding...");
            commonLogoutProcess(request, response, authentication);
            return;
        }
        Integer roleValue = RoleEnum.valueOf(details.getRole()).getValue();//findType(details.getRole()).getValue();
        //删除DB token
        //LOG.info("删除DB Remember-me Token...[auth is null:{}]", (authentication == null));
        this.rememberMeDBService.removeUserTokens(authentication.getName(), roleValue);
        //LOG.info("删除删除客户端Cookies（remember-me）...");
        //删除客户端Cookies（remember-me）
        commonLogoutProcess(request, response, authentication);
    }

    /**
     * 常规登出处理，清除会话和Cookie
     * @param request
     * @param response
     * @param authentication
     */
    private void commonLogoutProcess (HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        authentication = null;
        SecurityContextHolder.getContext().setAuthentication(authentication);
        cancelCookie(request, response);
    }





    /**
     * 是否为Remember Me的登陆请求（勾选记住密码选项）
     * @param request
     * @param parameter
     * @return
     */
    protected boolean rememberMeRequested(HttpServletRequest request, String parameter) {
        if (alwaysRemember) {
            return true;
        }
        //获取记住密码请求参数的值
        String paramValue = request.getParameter(parameter);
        if (logger.isDebugEnabled()) {
            logger.debug("remember-me cookie (principal set parameter '"
                    + parameter + "')");
        }
        //根据请求参数判断是否为带有记住密码的登陆请求
        return StringUtil.checkboxSelected(paramValue);
    }

    /**
     * 使客户端（浏览器）Cookies失效
     * 注意使用该方法确保服务端Session失效，避免session攻击
     * @param request
     * @param response
     */
    protected void cancelCookie(HttpServletRequest request, HttpServletResponse response) {
        logger.debug("Cancelling cookie");
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setMaxAge(0);
        cookie.setPath(getCookiePath(request));
        if (cookieDomain != null) {
            cookie.setDomain(cookieDomain);
        }
        response.addCookie(cookie);
    }

    /**
     * 根据token生成相应的Cookie
     * @param tokens
     * @param maxAge
     * @param request
     * @param response
     */
    protected void setCookie(String[] tokens, int maxAge, HttpServletRequest request,
                             HttpServletResponse response) {
        String cookieValue = encodeCookie(tokens);
        Cookie cookie = new Cookie(cookieName, cookieValue);
        cookie.setMaxAge(maxAge);
        cookie.setPath(getCookiePath(request));
        if (cookieDomain != null) {
            cookie.setDomain(cookieDomain);
        }
        if (maxAge < 1) {
            cookie.setVersion(1);
        }

        if (useSecureCookie == null) {
            cookie.setSecure(request.isSecure());
        }
        else {
            cookie.setSecure(useSecureCookie);
        }

        if (setHttpOnlyMethod != null) {
            ReflectionUtils.invokeMethod(setHttpOnlyMethod, cookie, Boolean.TRUE);
        }
        else if (logger.isDebugEnabled()) {
            logger.debug("Note: Cookie will not be marked as HttpOnly because you are not using Servlet 3.0 (Cookie#setHttpOnly(boolean) was not found).");
        }

        response.addCookie(cookie);
    }

    private String getCookiePath(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return contextPath.length() > 0 ? contextPath : "/";
    }



    public void setCookieName(String cookieName) {
        Assert.hasLength(cookieName, "Cookie name cannot be empty or null");
        this.cookieName = cookieName;
    }

    public void setCookieDomain(String cookieDomain) {
        Assert.hasLength(cookieDomain, "Cookie domain cannot be empty or null");
        this.cookieDomain = cookieDomain;
    }

    protected String getCookieName() {
        return cookieName;
    }

    public void setAlwaysRemember(boolean alwaysRemember) {
        this.alwaysRemember = alwaysRemember;
    }

    public void setParameter(String parameter) {
        Assert.hasText(parameter, "Parameter name cannot be empty or null");
        this.parameter = parameter;
    }

    public String getParameter() {
        return parameter;
    }


    public String getKey() {
        return key;
    }

    protected int getTokenValiditySeconds() {
        return tokenValiditySeconds;
    }

    public void setUseSecureCookie(boolean useSecureCookie) {
        this.useSecureCookie = useSecureCookie;
    }

    protected AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
        return authenticationDetailsSource;
    }

    public void setAuthenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource,
                "AuthenticationDetailsSource cannot be null");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
        this.userDetailsChecker = userDetailsChecker;
    }

    public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
        this.authoritiesMapper = authoritiesMapper;
    }

    protected String generateSeriesData() {
        byte[] newSeries = new byte[this.seriesLength];
        this.random.nextBytes(newSeries);
        return new String(Base64.encode(newSeries));
    }

    protected String generateTokenData() {
        byte[] newToken = new byte[this.tokenLength];
        this.random.nextBytes(newToken);
        return new String(Base64.encode(newToken));
    }

    private void addCookie(RememberMeToken token, HttpServletRequest request, HttpServletResponse response) {
        this.setCookie(new String[]{token.getSeries(), token.getToken()}, this.getTokenValiditySeconds(), request, response);
    }

    public void setSeriesLength(int seriesLength) {
        this.seriesLength = seriesLength;
    }

    public void setTokenLength(int tokenLength) {
        this.tokenLength = tokenLength;
    }

    public void setTokenValiditySeconds(int tokenValiditySeconds) {
        Assert.isTrue(tokenValiditySeconds > 0, "tokenValiditySeconds must be positive for this implementation");
        this.tokenValiditySeconds = tokenValiditySeconds;
    }

    /**
     * 对Cookies进行解码
     * @param cookieValue
     * @return
     * @throws InvalidCookieException
     */
    protected String[] decodeCookie(String cookieValue) throws InvalidCookieException {
        for (int j = 0; j < cookieValue.length() % 4; j++) {
            cookieValue = cookieValue + "=";
        }

        if (!Base64.isBase64(cookieValue.getBytes())) {
            throw new InvalidCookieException(
                    "Cookie token was not Base64 encoded; value was '" + cookieValue
                            + "'");
        }

        String cookieAsPlainText = new String(Base64.decode(cookieValue.getBytes()));

        String[] tokens = StringUtils.delimitedListToStringArray(cookieAsPlainText,
                DELIMITER);

        if (("http".equalsIgnoreCase(tokens[0]) || "https".equalsIgnoreCase(tokens[0]))
                && tokens[1].startsWith("//")) {
            // Assume we've accidentally split a URL (OpenID identifier)
            String[] newTokens = new String[tokens.length - 1];
            newTokens[0] = tokens[0] + ":" + tokens[1];
            System.arraycopy(tokens, 2, newTokens, 1, newTokens.length - 1);
            tokens = newTokens;
        }

        return tokens;
    }

    /**
     * 给Cookies进行加密（编码）
     * @param cookieTokens
     * @return
     */
    protected String encodeCookie(String[] cookieTokens) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < cookieTokens.length; i++) {
            sb.append(cookieTokens[i]);

            if (i < cookieTokens.length - 1) {
                sb.append(DELIMITER);
            }
        }

        String value = sb.toString();

        sb = new StringBuilder(new String(Base64.encode(value.getBytes())));

        while (sb.charAt(sb.length() - 1) == '=') {
            sb.deleteCharAt(sb.length() - 1);
        }

        return sb.toString();
    }

    /**
     * 获取remember-me Cookie value
     * @param request
     * @return
     */
    protected String extractRememberMeCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if ((cookies == null) || (cookies.length == 0)) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }

        return null;
    }

    private AuthUserService getUserDetailsService() {
        return (AuthUserService) userDetailsService;
    }




}
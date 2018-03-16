package cn.like.girl.blog.config.security.filter;

import com.alibaba.fastjson.JSONObject;
import com.houde.sc.man.core.security.handler.WebLoginFailureHandler;
import com.houde.sc.man.service.CaptchasService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;

/**
 * Created by 009 on 2017/6/29.
 * Gee Test Server Side | Second Step Verification
 */
public class GeeVerifyProcessFilter extends GenericFilterBean {
    private final static Logger LOG = LoggerFactory.getLogger(GeeVerifyProcessFilter.class);
    @Autowired
    private CaptchasService captchasService;
    @Autowired
    @Qualifier("messageSource")
    MessageSource msg;
    //
    @Autowired
    WebLoginFailureHandler loginFailureHandler;

    private boolean enableVerify;
    private boolean enableServerVerify;

    /**
     * Do Gee Verify Before auth form data
     * @param request
     * @param response
     * @param chain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if(!support(request)) {
            chain.doFilter(request, response);
        } else {
            //
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            Object obj = captchasService.geeVerify(httpRequest);
            JSONObject jsonObject = (JSONObject) obj;
            Boolean status ;
            String statusStr = jsonObject.getString("status");
            status = ("success").equals(statusStr);
            if(status) {
                chain.doFilter(request, response);
            } else {
                AuthenticationException exception =
                        new BadCredentialsException(msg.getMessage("security.auth.exception.gtverifyfail", new String[]{}, Locale.SIMPLIFIED_CHINESE));
                loginFailureHandler.onAuthenticationFailure((HttpServletRequest)request,
                        (HttpServletResponse)response, exception);
            }
        }

    }

    /**
     * checek request is support
     * Only Post login & HttpServletRequest is support
     * @param request
     * @return
     */
    public boolean support(Object request) {
        if(!enableVerify) {
            return false;
        }
        if(!enableServerVerify) {
            return false;
        }
        boolean isSupport = HttpServletRequest.class.isAssignableFrom(request.getClass());
        if(isSupport) {
            String method = ((HttpServletRequest)request).getMethod();
            String url = ((HttpServletRequest)request).getRequestURI();
            isSupport = (("/login".equals(url)) && ("POST".equals(method)));
        }
        return isSupport;
    }

    public boolean isEnableServerVerify() {
        return enableServerVerify;
    }

    public void setEnableServerVerify(boolean enableServerVerify) {
        this.enableServerVerify = enableServerVerify;
    }

    public boolean isEnableVerify() {
        return enableVerify;
    }

    public void setEnableVerify(boolean enableVerify) {
        this.enableVerify = enableVerify;
    }
}

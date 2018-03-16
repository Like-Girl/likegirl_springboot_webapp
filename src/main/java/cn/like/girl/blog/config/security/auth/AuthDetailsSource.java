package cn.like.girl.blog.config.security.auth;

import com.houde.sc.man.core.security.model.AuthDetails;
import com.houde.sc.man.core.security.service.AuthRememberMeServices;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by 009 on 2017/5/11.
 */
@Component("AuthDetailsSource")
public class AuthDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, AuthDetails> {
    public AuthDetails buildDetails(HttpServletRequest context, boolean isForm) {
        return new AuthDetails(context, isForm);
    }
    @Override
    public AuthDetails buildDetails(HttpServletRequest context) {
        Object obj = context.getAttribute(AuthRememberMeServices.AUTO_LOGIN_AUTH_ATTR_NAME);
        boolean isForm = (obj == null||"".equals(obj.toString().trim()));
        return buildDetails(context, isForm);
    }
}
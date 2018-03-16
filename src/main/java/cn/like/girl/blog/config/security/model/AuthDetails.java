package cn.like.girl.blog.config.security.model;

import com.houde.sc.man.core.security.service.AuthRememberMeServices;
import com.houde.sc.man.domain.RoleEnum;
import com.houde.sc.man.util.CommonUtil;
import com.houde.sc.man.util.StringUtil;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by 009 on 2017/5/10.
 */
public class AuthDetails extends WebAuthenticationDetails {
    //define request parameters name pass from front-end
    private static final String PARAM_CAP = "captcha";
    private static final String PARAM_ROLE = "role";
    private static final String PARAM_REMEMBER = "rememberme";

    //define captcha,role and remember-me variable
    private String captcha;
    private String role;  //type value SYSTEM -> 1 etc.
    private Boolean rememberme;

    public AuthDetails(HttpServletRequest request, boolean isForm) {
        super(request);
        init(request, isForm);

    }
    private void init(HttpServletRequest request, boolean isForm) {
        if(isForm) {
            formBuild(request);
        } else {
            cookieBuild(request);
        }
    }

    /**
     * construct auth detail from form login
     * @param request
     */
    private void formBuild(HttpServletRequest request) {
        this.setCaptcha(request.getParameter(PARAM_CAP));
        String role_value = request.getParameter(PARAM_ROLE);
        this.role = (CommonUtil.isValidRole(role_value))
                ?(RoleEnum.getByValue(Integer.valueOf(role_value)).toString()):role_value;
        this.role = StringUtil.notNullString(this.role);
        this.rememberme = isRemember(request.getParameter(PARAM_REMEMBER));
    }

    /**
     * construct auth detail from cookie login
     * @param request
     */
    private void cookieBuild(HttpServletRequest request) {
        Object obj = request.getAttribute(AuthRememberMeServices.AUTO_LOGIN_AUTH_ATTR_NAME);
        AuthUser authUser = (AuthUser) obj;
        this.setCaptcha("");
        this.setRememberme(true);
        this.setRole(authUser.getRole().toString());
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public Boolean getRememberme() {
        if(rememberme == null) {
            rememberme = false;
        }
        return rememberme;
    }

    public void setRememberme(Boolean rememberme) {
        this.rememberme = rememberme;
    }

    public String getCaptcha() {
        if(captcha == null) {
            captcha = "";
        }
        return captcha;
    }

    public void setCaptcha(String captcha) {
        this.captcha = captcha;
    }

    private boolean isRemember(String remember) {
        if(StringUtil.checkboxSelected(remember)) {
            return true;
        }
        return false;
    }

    public static AuthDetails toThis(Object obj) {
        return (AuthDetails)obj;
    }

}

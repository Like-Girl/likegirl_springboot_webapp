package cn.like.girl.blog.config.security.provider;


import com.houde.sc.man.core.security.model.AuthDetails;
import com.houde.sc.man.core.security.model.AuthUser;
import com.houde.sc.man.core.security.service.AuthUserService;
import com.houde.sc.man.core.security.service.PasswordEncoderService;
import com.houde.sc.man.dao.CommunityAdminDao;
import com.houde.sc.man.domain.AccountStatusEnum;
import com.houde.sc.man.domain.RoleEnum;
import com.houde.sc.man.model.CommunityAdmin;
import com.houde.sc.man.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Locale;

/**
 * Created by 009 on 2017/5/8.
 * Form login auth
 */
@Component
public class AuthProvider implements AuthenticationProvider {
    final Logger LOG = LoggerFactory.getLogger(this.getClass());
    @Autowired
    AuthUserService authUserService;
    @Autowired
    @Qualifier("messageSource")
    MessageSource msg;
    @Autowired
    PasswordEncoderService passwordEncoderService;
    @Autowired
    CommunityAdminDao communityAdminDao;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Object authenticationDetails = authentication.getDetails();
        Assert.isInstanceOf(AuthDetails.class, authenticationDetails, "Only authDetails class is supported");
        if (!(authenticationDetails instanceof AuthDetails)) {
            throw new BadCredentialsException("Details type error");
        }
        AuthDetails details = AuthDetails.toThis(authenticationDetails);

        String role_str = details.getRole();
        if ("".equals(role_str)) {
            //throw new BadCredentialsException("User Role not found");
            LOG.warn("Invalid role is empty");
            throw new BadCredentialsException(msg.getMessage("security.auth.exception.role_not_found",
                    new String[]{role_str}, Locale.SIMPLIFIED_CHINESE));
        }
        //
        RoleEnum role;
        try {
            role = RoleEnum.valueOf(role_str);
        } catch (Exception e) {
            LOG.warn("Invalid role {0}", role_str);
            //e.printStackTrace();
            //throw new BadCredentialsException("User Role is unrecognized");
            throw new BadCredentialsException(msg.getMessage("security.auth.exception.wrong_principal",
                    new String[]{role_str}, Locale.SIMPLIFIED_CHINESE));
        }
        if (role == null) {
            //throw new BadCredentialsException("User Role is unrecognized");
            throw new BadCredentialsException(msg.getMessage("security.auth.exception.role_unrecognized",
                    new String[]{role_str}, Locale.SIMPLIFIED_CHINESE));
        }

        String valid_code = details.getCaptcha();

        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        AuthUser user = authUserService.loadUserByUsername(username, role);
        if (user == null) {
            LOG.warn("Invalid user {0}|{1}", username, role);
            //throw new BadCredentialsException("Username not found.");
            throw new BadCredentialsException(msg.getMessage("security.auth.exception.wrong_principal",
                    new String[]{username}, Locale.SIMPLIFIED_CHINESE));
        }
        //用户状态异常
        if (user.getStatus() != AccountStatusEnum.ENABLED) {
            throw new AuthenticationServiceException(msg.getMessage("security.auth.exception.deviant_wrong_principal",
                    new String[]{username}, Locale.SIMPLIFIED_CHINESE));
        } else {
            switch (role) {
                case COMMUNITY:
                    //验证社区管理员是否存在可用社区
                    CommunityAdmin communityAdmin = communityAdminDao.getById(user.getId());
                    String defaultCommunity = communityAdmin.getCommunityId();
                    if (StringUtil.stringIsEmpty(defaultCommunity)) {
                        throw new AuthenticationServiceException(msg.getMessage("security.auth.exception.deviant_wrong_principal",
                                new String[]{username}, Locale.SIMPLIFIED_CHINESE));
                    }
                    break;
                default:
                    break;
            }
        }

        //用户密码错误
        if (!passwordEncoderService.matches(password, user.getPassword())) {
            LOG.warn("Invalid password {0}", password);
            throw new BadCredentialsException(msg.getMessage("security.auth.exception.wrong_principal",
                    new String[]{password}, Locale.SIMPLIFIED_CHINESE));
        }

        Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
        return new UsernamePasswordAuthenticationToken(user, password, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

}

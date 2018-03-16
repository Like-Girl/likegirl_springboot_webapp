package cn.like.girl.blog.config.security.provider;


import com.houde.sc.man.core.security.model.AuthUser;
import com.houde.sc.man.domain.AccountStatusEnum;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.Locale;


/**
 * Created by 009 on 2017/5/14.
 * Remember-Me Authentication Provider
 */
public class RememberMeAuthProvider extends RememberMeAuthenticationProvider {
    final Logger LOG = LoggerFactory.getLogger(this.getClass());

    @Autowired
    @Qualifier("messageSource")
    MessageSource msg;

    public RememberMeAuthProvider(String key) {
        super(key);
    }

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if (this.getKey().hashCode() != ((RememberMeAuthenticationToken) authentication)
                .getKeyHash()) {
            throw new BadCredentialsException(
                    messages.getMessage("RememberMeAuthenticationProvider.incorrectKey",
                            "The presented RememberMeAuthenticationToken does not contain the expected key"));
        }

        //check user status
        AuthUser user = (AuthUser)authentication.getPrincipal();
        if(user == null) {
            throw new AuthenticationServiceException("user not found");
        }

        if(user.getStatus() != AccountStatusEnum.ENABLED) {
            throw new AuthenticationServiceException(msg.getMessage("security.auth.exception.deviant_wrong_principal", null,
                    Locale.SIMPLIFIED_CHINESE));
        }

        return authentication;
    }
}

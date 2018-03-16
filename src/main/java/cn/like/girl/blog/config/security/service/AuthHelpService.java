package cn.like.girl.blog.config.security.service;

import com.houde.sc.man.core.security.model.AuthDetails;
import com.houde.sc.man.core.security.model.AuthUser;
import com.houde.sc.man.domain.RoleEnum;
import com.houde.sc.man.service.RememberMeDBService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

/**
 * Created by 009 on 2017/6/11.
 */
@Service("AuthUserHelpService")
public class AuthHelpService {
    @Autowired
    RememberMeDBService rememberMeDBService;
    /**
     * 获取当前授权对象
     * @return
     */
    private Authentication findAuth() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        //验证是否为合法用户
        if ((auth != null) && (!(auth instanceof AnonymousAuthenticationToken))) {
            return auth;
        }
        return null;
    }

    /**
     * 获取当前授权用户信息
     * @return
     */
    public AuthUser findAuthUser() {
        Authentication auth = findAuth();
        AuthUser user = (auth == null) ? null : (AuthUser) auth.getPrincipal();
        return user;
    }

    /**
     * 获取授权detail
     * @return
     */
    public AuthDetails findAuthDetail() {
        Authentication auth = findAuth();
        AuthDetails details = (auth == null) ? null : (AuthDetails) auth.getDetails();
        return details;
    }

    /**
     * 获取当前授权管理员ID
     * @return
     */
    public String findAuthAdmin() {
        AuthUser user = findAuthUser();
        return findAuthAdmin(user);
    }

    /**
     *
     * @return
     */
    /**
     * 获取指定授权用户的授权管理员ID
     * @param user | 授权用户
     * @return
     */
    public String findAuthAdmin(AuthUser user) {
        return (user == null)
                ? null
                : (user.getRole().equals(RoleEnum.SYSTEM)
                ? user.getId()
                : null
        );
    }

    /**
     * 获取当前授权物业ID
     * @return
     */
    public String findAuthProperty() {
        AuthUser user = findAuthUser();
        return findAuthProperty(user);
    }

    /**
     * 获取指定授权用户的授权物业ID
     * @param user | 授权用户
     * @return
     */
    public String findAuthProperty(AuthUser user) {
        return (user == null)
                ? null
                : (user.getRole().equals(RoleEnum.COMMUNITY)
                ? user.getId()
                : null
        );
    }

    /**
     * 获取当前授权服务商ID
     * @return
     */
    public String findAuthSupplier() {
        AuthUser user = findAuthUser();
        return findAuthSupplier(user);
    }

    /**
     * 获取指定授权用户的授权服务商ID
     * @return user | 授权用户
     */
    public String findAuthSupplier(AuthUser user) {
        return (user == null)
                ? null
                : (user.getRole().equals(RoleEnum.SUPPLIER)
                ? user.getId()
                : null
        );
    }

    /**
     * 获取当前授权用户id
     * @return
     */
    public String findAuthUserId() {
        AuthUser user = findAuthUser();
        return (user == null)
                ? null
                : user.getId();
    }

    /**
     * 获取当前授权用户角色
     * @return Role枚举
     */
    public RoleEnum findAuthUserRole() {
        AuthUser user = findAuthUser();

        return (user == null)
                ? null
                : user.getRole()
        ;
    }

    /**
     * 清除授权信息
     */
    public void clearAuth() {
        Authentication authentication = null;
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    /**
     * 清除remember token
     */
    public void clearRememberAuth() {
        AuthUser user = findAuthUser();
        if(user == null) {
            return;
        }
        String username = user.getUsername();
        Integer userrole = user.getRole().getId();
        rememberMeDBService.removeUserTokens(username, userrole);
    }

    /**
     * 获取认证方式（返回数字类型，-1表示失败，0表示未知，1表示用户密码，2表示自动登录，3表示微信登陆[暂未开发]
     * @return auth way number
     */
    public int findAuthWay() {
        Authentication auth = findAuth();
        return findAuthWay(auth);
    }
    //
    public int findAuthWay(Authentication auth) {
        int way = -1;

        if(auth == null) {
            return way;
        } else if(auth instanceof UsernamePasswordAuthenticationToken) {
            way = 1;
        } else if(auth instanceof RememberMeAuthenticationToken) {
            way = 2;
        } /*else if(auth instanceof ) {
            way = 3;
        }*/ else {
            way = 0;
        }

        return way;
    }
}

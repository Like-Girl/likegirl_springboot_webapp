package cn.like.girl.blog.config.security.service;

import com.houde.sc.man.core.security.model.AuthUser;
import com.houde.sc.man.dao.AdminDao;
import com.houde.sc.man.dao.CommunityAdminDao;
import com.houde.sc.man.dao.SupplierDao;
import com.houde.sc.man.domain.AccountStatusEnum;
import com.houde.sc.man.domain.LoginUser;
import com.houde.sc.man.domain.RoleEnum;
import com.houde.sc.man.service.PermissionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;

/**
 * Created by 009 on 2017/5/8.
 */
@Service("AuthUserService")
public class AuthUserService implements UserDetailsService {
    private static final Logger LOG = LoggerFactory.getLogger(AuthUserService.class);
    private String username;
    private RoleEnum role;
    @Autowired
    AdminDao adminDao;
    @Autowired
    CommunityAdminDao communityAdminDao;
    @Autowired
    SupplierDao supplierDao;
    @Autowired
    PermissionService permissionService;



    public AuthUser loadUserByUsername(String username, RoleEnum role) throws UsernameNotFoundException, DataAccessException {
        this.role = role;
        return loadUserByUsername(username);
    }

    @Override
    public AuthUser loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        LoginUser user = null;
        //List<SimpleGrantedAuthority> authorities = new ArrayList<>(1);

        switch(role) {
            case SYSTEM:
                user = LoginUser.fromAdmin(adminDao.getByAccount(username));
                break;
            case COMMUNITY:
                user = LoginUser.fromCommunityAdmin(communityAdminDao.getByAccount(username));
                break;
            case SUPPLIER:
                user = LoginUser.fromSupplier(supplierDao.getByAccount(username));
                break;
            default:
                break;
        }


        AuthUser authUser = AuthUser.fromUser(user);
        if(authUser == null) {
            return authUser;
        }
        if(authUser.getStatus() != AccountStatusEnum.ENABLED) {
            return authUser;
        }

        Collection<GrantedAuthority> authorities = authUser.getAuthorities();
        permissionService.findPermissions(role).forEach(permission -> {
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(permission.getKey());
            authorities.add(authority);
        });

        return authUser;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}

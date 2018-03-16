package cn.like.girl.blog.config.security.model;

import com.houde.sc.man.domain.LoginUser;
import com.houde.sc.man.domain.RoleEnum;
import org.springframework.beans.BeanUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Created by 009 on 2017/5/8.
 */
public class AuthUser extends LoginUser implements UserDetails {
    private Boolean enabled;
    private Boolean credentialsNonExpired;
    private Boolean accountNonLocked;
    private Boolean accountNonExpired;

    private Collection<GrantedAuthority> authorities;

    public AuthUser(LoginUser user) {
        BeanUtils.copyProperties(user, this);
        this.authorities = getAuthorities();
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        if(authorities != null) {
            return authorities;
        }
        authorities = new ArrayList<>();
        RoleEnum role = this.getRole();
        if(this.getRole() != null) {
            //default role authority
            GrantedAuthority role_authority = new SimpleGrantedAuthority("ROLE_".concat(role.toString()));
            authorities.add(role_authority);
        }
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        //return accountNonExpired;
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        //return accountNonLocked;
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        //return credentialsNonExpired;
        return true;
    }

    @Override
    public boolean isEnabled() {
        //return enabled; java.lang.NullPointerException
        return true;
    }

    public void setAccountNonExpired(Boolean accountNonExpired) {
        this.accountNonExpired = accountNonExpired;
    }

    public void setAccountNonLocked(Boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
    }

    public void setCredentialsNonExpired(Boolean credentialsNonExpired) {
        this.credentialsNonExpired = credentialsNonExpired;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public static AuthUser fromUser(LoginUser user) {
        if(user == null) {
            return null;
        }
        return new AuthUser(user);
    }

}

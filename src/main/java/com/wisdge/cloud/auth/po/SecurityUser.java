package com.wisdge.cloud.auth.po;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Data
@Slf4j
@AllArgsConstructor
public class SecurityUser implements UserDetails {
    /**
     * 当前登录用户
     */
    private transient User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        for(Role role : user.getRoles()) {
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role.getId());
            authorities.add(authority);
        }
        return authorities;
    }
    public List<String> getPlanAuthorities() {
        List<String> roles = new ArrayList<>();
        for(Role role : user.getRoles()) {
            roles.add(role.getId());
        }
        return roles;
    }

    @Override
    public String getPassword() {
        return user == null ? "" : user.getPassword();
    }

    @Override
    public String getUsername() {
        return user == null ? "" : user.getName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return user.getStatus() != User.STATUS_EXPIRED;
    }

    @Override
    public boolean isAccountNonLocked() {
        return user.getStatus() != User.STATUS_LOCKED;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return user.getStatus() != User.STATUS_PWD_EXPIRED;
    }

    @Override
    public boolean isEnabled() {
        return user.getStatus() != User.STATUS_DISABLED;
    }
}

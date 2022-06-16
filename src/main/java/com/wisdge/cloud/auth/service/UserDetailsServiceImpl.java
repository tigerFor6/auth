package com.wisdge.cloud.auth.service;

import com.wisdge.cloud.auth.exception.AccountNotActivationException;
import com.wisdge.cloud.auth.mapper.RoleMapper;
import com.wisdge.cloud.auth.mapper.UserMapper;
import com.wisdge.cloud.auth.po.SecurityUser;
import com.wisdge.cloud.auth.po.User;
import com.wisdge.utils.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;

@Slf4j
@Service("userDetailsService")
public class UserDetailsServiceImpl implements UserDetailsService {
    @Resource
    protected UserMapper userMapper;
    @Resource
    protected RoleMapper roleMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = getUser(username);
        if (user == null) {
            log.info("账号[{}]不存在!", username);
            throw new UsernameNotFoundException("账号不存在或密码错误");
        }
        if (StringUtils.isEmpty(user.getPassword())) {
            log.info("账号[{}]未激活!", username);
            throw new AccountNotActivationException("账号未激活!");
        }

        user.setRoles(roleMapper.findByUserId(user.getId()));
        return new SecurityUser(user);
    }

    protected User getUser(String username) {
        return userMapper.findByUsername(username);
    }
}

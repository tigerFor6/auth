package com.wisdge.cloud.auth.service;

import com.wisdge.cloud.auth.po.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service("mobileDetailsService")
public class MobileDetailsServiceImpl extends UserDetailsServiceImpl {

    @Override
    protected User getUser(String username) {
        return userMapper.findByMobile(username);
    }
}

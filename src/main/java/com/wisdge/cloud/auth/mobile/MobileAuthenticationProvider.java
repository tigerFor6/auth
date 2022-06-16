package com.wisdge.cloud.auth.mobile;

import com.wisdge.cloud.auth.internal.SecurityConstant;
import com.wisdge.commons.redis.RedisTemplate;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * 手机验证码登录逻辑实现
 */
@Slf4j
@Data
public class MobileAuthenticationProvider implements AuthenticationProvider {
    private RedisTemplate redisTemplate;
    private UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MobileAuthenticationToken mobileAuthenticationToken = (MobileAuthenticationToken) authentication;
        String mobile = mobileAuthenticationToken.getPrincipal().toString();
        String realCode = (String) redisTemplate.get(SecurityConstant.REDIS_CODE_PREFIX + mobile);
        String inputCode = authentication.getCredentials().toString();
        // 判断手机的验证码是否存在
        if (realCode == null) {
            log.debug("登录失败，当前手机号验证码不存在或者已经过期");
            throw new BadCredentialsException("登录失败，验证码不存在");
        }
        // 判断是否验证码跟redis中存的验证码是否正确
        if(!inputCode.equalsIgnoreCase(realCode)) {
            log.debug("登录失败，您输入的验证码不正确");
            throw new BadCredentialsException("登录失败，验证码不正确");
        }
        UserDetails userDetails = userDetailsService.loadUserByUsername(mobile);
        // 重新构造token  登录成功
        MobileAuthenticationToken authenticationToken = new MobileAuthenticationToken(userDetails, inputCode, userDetails.getAuthorities());
        authenticationToken.setDetails(mobileAuthenticationToken.getDetails());
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MobileAuthenticationToken.class.isAssignableFrom(authentication);
    }

}

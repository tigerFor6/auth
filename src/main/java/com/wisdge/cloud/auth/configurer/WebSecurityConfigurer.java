package com.wisdge.cloud.auth.configurer;

import com.wisdge.cloud.auth.filter.CaptchaFilter;
import com.wisdge.cloud.auth.handler.TigerLogoutSuccessHandler;
import com.wisdge.cloud.auth.mobile.MobileAuthenticationFilter;
import com.wisdge.cloud.auth.mobile.MobileAuthenticationProvider;
import com.wisdge.commons.redis.RedisTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
@Configuration
@EnableWebSecurity
public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {

    @Autowired
    private WhiteListConfig ignoreUrlPropertiesConfig;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private RedisTemplate redisTemplate;
    @Autowired
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private UserDetailsService mobileDetailsService;
    @Autowired
    private TigerLogoutSuccessHandler tigerLogoutSuccessHandler;
    @Autowired
    private CaptchaFilter captchaFilter;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .authenticationProvider(mobileAuthenticationProvider())
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry config
                = http
                .addFilterAt(captchaFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin().disable()
                .cors()
                .and()
                .requestMatchers().anyRequest()
                .and()
                .authorizeRequests();

        ignoreUrlPropertiesConfig.getUrls().forEach( e ->{
            config.antMatchers(e).permitAll();
        });
        config.antMatchers("/oauth/**").permitAll()
                .antMatchers("/rsa/publicKey").permitAll()
                .antMatchers("/token/**").permitAll()
                .antMatchers("/user/**").permitAll()
                .antMatchers("/v2/**").permitAll()
                .antMatchers("/v3/**").permitAll()
                .antMatchers("/swagger*/**").permitAll()
                .antMatchers("/error**").permitAll()
                .anyRequest().authenticated()
                .and().logout().logoutSuccessHandler(tigerLogoutSuccessHandler)
                .and().csrf().disable();
    }

    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public AuthenticationProvider mobileAuthenticationProvider() {
        MobileAuthenticationProvider mobileAuthenticationProvider = new MobileAuthenticationProvider();
        mobileAuthenticationProvider.setRedisTemplate(redisTemplate);
        mobileAuthenticationProvider.setUserDetailsService(mobileDetailsService);
        return mobileAuthenticationProvider;
    }

    /**
     * 自定义登陆过滤器
     * @return
     */
    @Bean
    public MobileAuthenticationFilter mobileAuthenticationFilter() {
        MobileAuthenticationFilter filter = new MobileAuthenticationFilter();
        try {
            filter.setAuthenticationManager(this.authenticationManagerBean());
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        filter.setAuthenticationFailureHandler(authenticationFailureHandler);
        return filter;
    }
}

package com.wisdge.cloud.auth.configurer;

import com.wisdge.cloud.auth.mapper.LoginHisMapper;
import com.wisdge.cloud.auth.po.SecurityUser;
import com.wisdge.cloud.auth.handler.CustomWebResponseExceptionTranslator;
import com.wisdge.cloud.auth.internal.SecurityConstant;
import com.wisdge.cloud.auth.po.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.security.rsa.crypto.KeyStoreKeyFactory;

import javax.annotation.Resource;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * @description: oauth2认证服务器配置类
 */
@Slf4j
@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private RedisConnectionFactory redisConnectionFactory;
    @Autowired
    private CustomWebResponseExceptionTranslator customWebResponseExceptionTranslator;
    @Resource
    private LoginHisMapper loginHisMapper;

    @Value("${accessTokenValiditySeconds:3600}")
    private int accessTokenValiditySeconds;

    /**
     * 配置token存储到redis中
     *
     * @return
     */
    @Bean
    public RedisTokenStore redisTokenStore() {
        RedisTokenStore store = new RedisTokenStore(redisConnectionFactory);
        store.setPrefix(SecurityConstant.CLOUD_PREFIX);
        return store;
    }

    /**
     * 配置client通过jdbc从数据库查询
     *
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//        clients.jdbc(dataSource);
        clients.inMemory()
                .withClient("pc")
                .secret(passwordEncoder.encode("Letmein_0308"))
                .authorizedGrantTypes("authorization_code", "password", "refresh_token")
                .scopes("all")
                .accessTokenValiditySeconds(accessTokenValiditySeconds)
                .refreshTokenValiditySeconds(864000)
                .autoApprove(true)

                .and()
                .withClient("app")
                .secret(passwordEncoder.encode("Letmein_0308"))
                .authorizedGrantTypes("authorization_code", "password", "refresh_token")
                .scopes("all")
                .accessTokenValiditySeconds(accessTokenValiditySeconds)
                .refreshTokenValiditySeconds(864000)
                .autoApprove(true)

                .and()
                .withClient("wechat")
                .secret(passwordEncoder.encode("Letmein_0308"))
                .authorizedGrantTypes("authorization_code", "password", "refresh_token")
                .scopes("all")
                .accessTokenValiditySeconds(accessTokenValiditySeconds)
                .refreshTokenValiditySeconds(864000)
                .autoApprove(true);
    }


    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // token增强链
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        // 把jwt增强，与额外信息增强加入到增强链
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(), jwtAccessTokenConverter()));
        endpoints
                .authenticationManager(authenticationManager)
                .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST)
                .tokenStore(redisTokenStore())
                .tokenEnhancer(tokenEnhancerChain)
                // refresh_token有两种使用方式：重复使用(true)、非重复使用(false)，默认为true
                //      1.重复使用：access_token过期刷新时， refresh token过期时间未改变，仍以初次生成的时间为准
                //      2.非重复使用：access_token过期刷新时， refresh_token过期时间延续，在refresh_token有效期内刷新而无需失效再次登录
                .reuseRefreshTokens(false)
                .userDetailsService(userDetailsService)
                .tokenServices(tokenServices(endpoints))
                .exceptionTranslator(customWebResponseExceptionTranslator); // 添加认证异常处理器
    }

    private SingleTokenServices tokenServices(AuthorizationServerEndpointsConfigurer endpoints) {
        SingleTokenServices tokenServices = new SingleTokenServices();
        tokenServices.setTokenStore(redisTokenStore());
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setReuseRefreshToken(false);
        tokenServices.setClientDetailsService(endpoints.getClientDetailsService());
        tokenServices.setTokenEnhancer(endpoints.getTokenEnhancer());
        tokenServices.setAuthenticationManager(authenticationManager);
        tokenServices.setLoginHisMapper(loginHisMapper);
        return tokenServices;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                // 允许表单认证请求
                .allowFormAuthenticationForClients()
                // spel表达式 访问公钥端点（/auth/token_key）需要认证
                .tokenKeyAccess("isAuthenticated()")
                // spel表达式 访问令牌解析端点（/auth/check_token）需要认证
                .checkTokenAccess("isAuthenticated()");
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        //jwtAccessTokenConverter.setSigningKey(SecurityConstant.SIGN_KEY);
        jwtAccessTokenConverter.setKeyPair(keyPair());
        return jwtAccessTokenConverter;
    }

    /**
     * jwt token增强，添加额外信息
     *
     * @return
     */
    @Bean
    public TokenEnhancer tokenEnhancer() {
        return (accessToken, authentication) -> {
            // 添加额外信息的map
            final Map<String, Object> additionMessage = new HashMap<>(4);
            // 获取当前登录的用户
            SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();
            User user = securityUser.getUser();
            log.info("当前登录用户：{}", user.getName());
            // 每个微服务通过Header中的User获取到的当前登录用户的信息
            additionMessage.put("code", 1);
            additionMessage.put(SecurityConstant.TOKEN_ENHANCER_USERID, user.getId());
            additionMessage.put(SecurityConstant.TOKEN_ENHANCER_FULLNAME, user.getFullname());
            additionMessage.put(SecurityConstant.TOKEN_ENHANCER_ORGID, user.getOrgId());
            additionMessage.put(SecurityConstant.TOKEN_ENHANCER_AUTHORITIES, securityUser.getPlanAuthorities());
            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionMessage);
            return accessToken;
        };
    }

    @Bean
    public KeyPair keyPair() {
        // 从classpath下的证书中获取秘钥对
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "123456".toCharArray());
        return keyStoreKeyFactory.getKeyPair("jwt", "123456".toCharArray());
    }
}

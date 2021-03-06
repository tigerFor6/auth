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
 * @description: oauth2????????????????????????
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
     * ??????token?????????redis???
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
     * ??????client??????jdbc??????????????????
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
        // token?????????
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        // ???jwt????????????????????????????????????????????????
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(), jwtAccessTokenConverter()));
        endpoints
                .authenticationManager(authenticationManager)
                .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST)
                .tokenStore(redisTokenStore())
                .tokenEnhancer(tokenEnhancerChain)
                // refresh_token????????????????????????????????????(true)??????????????????(false)????????????true
                //      1.???????????????access_token?????????????????? refresh token?????????????????????????????????????????????????????????
                //      2.??????????????????access_token?????????????????? refresh_token????????????????????????refresh_token?????????????????????????????????????????????
                .reuseRefreshTokens(false)
                .userDetailsService(userDetailsService)
                .tokenServices(tokenServices(endpoints))
                .exceptionTranslator(customWebResponseExceptionTranslator); // ???????????????????????????
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
                // ????????????????????????
                .allowFormAuthenticationForClients()
                // spel????????? ?????????????????????/auth/token_key???????????????
                .tokenKeyAccess("isAuthenticated()")
                // spel????????? ???????????????????????????/auth/check_token???????????????
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
     * jwt token???????????????????????????
     *
     * @return
     */
    @Bean
    public TokenEnhancer tokenEnhancer() {
        return (accessToken, authentication) -> {
            // ?????????????????????map
            final Map<String, Object> additionMessage = new HashMap<>(4);
            // ???????????????????????????
            SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();
            User user = securityUser.getUser();
            log.info("?????????????????????{}", user.getName());
            // ?????????????????????Header??????User???????????????????????????????????????
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
        // ???classpath??????????????????????????????
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "123456".toCharArray());
        return keyStoreKeyFactory.getKeyPair("jwt", "123456".toCharArray());
    }
}

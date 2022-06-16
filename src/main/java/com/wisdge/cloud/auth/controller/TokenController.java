package com.wisdge.cloud.auth.controller;

import com.wisdge.cloud.auth.internal.OAuth2AccessTokenQuery;
import com.wisdge.cloud.auth.internal.SecurityConstant;
import com.wisdge.cloud.controller.BaseController;
import com.wisdge.cloud.dto.ApiResult;
import com.wisdge.commons.redis.RedisTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/token")
public class TokenController extends BaseController {

    @Autowired
    private RedisTemplate redisTemplate;

    @Autowired
    private RedisTokenStore redisTokenStore;

    @GetMapping("/findByClientId")
    public ApiResult findByClientId() {
        String clientId = request.getParameter("client_id");
        return new ApiResult(redisTokenStore.findTokensByClientId(clientId));
    }

    @GetMapping("/findByUserId")
    public ApiResult findByUserId() {
        String clientId = request.getParameter("client_id");
        String userName = request.getParameter("username");
        return new ApiResult(redisTokenStore.findTokensByClientIdAndUserName(clientId, userName));
    }

    @GetMapping("/page")
    public ApiResult listForPage(OAuth2AccessTokenQuery oAuth2AccessTokenQuery) {
        redisTemplate.setValueSerializer(new JdkSerializationRedisSerializer());
        oAuth2AccessTokenQuery.setRecords((List) redisTemplate.opsForList().range(SecurityConstant.REDIS_LIST_LEY, oAuth2AccessTokenQuery.getStart(), oAuth2AccessTokenQuery.getEnd()));
        List<OAuth2AccessToken> all = (List) redisTemplate.opsForList().range(SecurityConstant.REDIS_LIST_LEY, 0, -1);
        if (all != null) {
            oAuth2AccessTokenQuery.setTotal(all.size());
        }
        return new ApiResult(oAuth2AccessTokenQuery);
    }

}

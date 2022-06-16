package com.wisdge.cloud.auth.controller;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.wisdge.cloud.controller.BaseController;
import com.wisdge.cloud.dto.ApiResult;
import com.wisdge.utils.SnowflakeIdWorker;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@Slf4j
@RestController
public class AuthController extends BaseController {

    @Resource
    private KeyPair keyPair;

    @Resource
    private SnowflakeIdWorker snowflakeIdWorker;


    @GetMapping("/rsa/publicKey")
    public Map<String, Object> getKey() {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAKey key = new RSAKey.Builder(publicKey).build();
        return new JWKSet(key).toJSONObject();
    }

    @GetMapping("/captcha/puzzle")
    public ApiResult captchaPuzzle() {
        String captchaId = String.valueOf(snowflakeIdWorker.nextId());

        return ApiResult.ok("", captchaId);
    }

    @GetMapping("/captcha/image")
    public ApiResult captchaImage() {
        String captchaId = String.valueOf(snowflakeIdWorker.nextId());

        return ApiResult.ok("", captchaId);
    }
}

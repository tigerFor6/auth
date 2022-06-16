package com.wisdge.cloud.auth.internal;

/**
 * @description: 安全配置常量
 */
public interface SecurityConstant {

    String CLOUD_PREFIX = "cloud_auth:";

    String REDIS_LIST_LEY = "client_id_to_access:cloud";
    String REDIS_CODE_PREFIX = "mobile_code:";
    String REDIS_CODE_CAPTCHA = "captcha:";
    Integer REDIS_CODE_EXPIRE = 60;

    /**
     * jwt 加密key
     */
    String SIGN_KEY = "wisdge.cloud";

    String SPRING_SECURITY_MOBILE_KEY = "mobile";
    String SPRING_SECURITY_CODE_KEY = "code";
    String SPRING_SECURITY_MOBILE_TOKEN_URL = "/mobile/token";

    String TOKEN_HEADER = "Authorization";
    String TOKEN_PREFIX = "Bearer ";
    String TOKEN_ENHANCER_USERID = "userId";
    String TOKEN_ENHANCER_FULLNAME = "fullname";
    String TOKEN_ENHANCER_ORGID = "orgId";
    String TOKEN_ENHANCER_AUTHORITIES = "authorities";

    Integer CUSTOM_ERROR_INVALID_GRANT = -2;
    Integer CUSTOM_ERROR_UNKNOWN = -7;
    Integer CUSTOM_ERROR_DUPLICATION = -9; // 重复登录
    Integer CUSTOM_ERROR_INVALID_CAPTCHA = -13;

}

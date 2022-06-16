package com.wisdge.cloud.auth.exception;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * @description: oauth2自定义异常
 */
@JsonSerialize(using = CustomOauthExceptionSerializer.class)
public class CustomOauth2Exception extends OAuth2Exception {
    private int code;
    private Object value;

    public CustomOauth2Exception(String message, int code) {
        super(message);
        this.code = code;
    }

    public CustomOauth2Exception(String message, int code, Object value) {
        super(message);
        this.code = code;
        this.value = value;
    }

    public int getCode() {
        return this.code;
    }

    public Object getValue() {
        return this.value;
    }
}

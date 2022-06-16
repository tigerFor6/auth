package com.wisdge.cloud.auth.exception;

import org.springframework.security.core.AuthenticationException;

public class CaptchaFailedException extends AuthenticationException {
    public CaptchaFailedException(String message) {
        super(message);
    }
}

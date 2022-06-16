package com.wisdge.cloud.auth.exception;

import org.springframework.security.core.AuthenticationException;

public class DuplicationLoginAuthenticationException extends AuthenticationException {
    public DuplicationLoginAuthenticationException(String msg) {
        super(msg);
    }
}

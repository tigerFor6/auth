package com.wisdge.cloud.auth.exception;

import org.springframework.security.core.AuthenticationException;

public class AccountNotActivationException extends AuthenticationException {
    public AccountNotActivationException(String message) {
        super(message);
    }
}

package com.wisdge.cloud.auth.handler;

import com.wisdge.cloud.auth.exception.CustomOauth2Exception;
import com.wisdge.cloud.auth.exception.DuplicationLoginAuthenticationException;
import com.wisdge.cloud.auth.internal.SecurityConstant;
import com.wisdge.cloud.util.UrlUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.DefaultThrowableAnalyzer;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import javax.servlet.http.HttpServletRequest;

/**
 * @description: oauth2异常处理器
 */
@Component("customWebResponseExceptionTranslator")
@Slf4j
public class CustomWebResponseExceptionTranslator implements WebResponseExceptionTranslator {
    private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

    @Override
    public ResponseEntity<OAuth2Exception> translate(Exception e) throws Exception {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        String username = request.getParameter("username");
        log.debug("认证失败：{} visit {}@{} from {}", username, request.getMethod(), request.getRequestURI(), UrlUtil.getRemoteHost(request));
        Throwable[] causeChain = throwableAnalyzer.determineCauseChain(e);
        AuthenticationException ase = (AuthenticationException) throwableAnalyzer.getFirstThrowableOfType(AuthenticationException.class, causeChain);
        // 异常链中有AuthenticationException异常
        if (ase != null) {
            log.debug("Account already login>>>>>>");
            if (ase instanceof DuplicationLoginAuthenticationException) {
                return handleOAuth2Exception("Account already login", SecurityConstant.CUSTOM_ERROR_DUPLICATION, e.getMessage());
            }
            log.error("{} not catch", ase.getClass().toString());
            return handleOAuth2Exception(e.getMessage(), SecurityConstant.CUSTOM_ERROR_UNKNOWN);
        } else if (e instanceof InvalidGrantException) {
            return handleOAuth2Exception(e.getMessage(), SecurityConstant.CUSTOM_ERROR_INVALID_GRANT);
        } else {
            log.error(e.getMessage(), e);
            return handleOAuth2Exception(e.getMessage(), SecurityConstant.CUSTOM_ERROR_UNKNOWN);
        }
    }

    private ResponseEntity<OAuth2Exception> handleOAuth2Exception(String message, int code, Object value) {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(new CustomOauth2Exception(message, code, value));
    }

    private ResponseEntity<OAuth2Exception> handleOAuth2Exception(String message, int code) {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(new CustomOauth2Exception(message, code));
    }
}

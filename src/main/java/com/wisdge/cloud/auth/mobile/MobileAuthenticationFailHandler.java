package com.wisdge.cloud.auth.mobile;

import com.wisdge.cloud.dto.ApiResult;
import com.wisdge.dataservice.utils.JSonUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
@Component
public class MobileAuthenticationFailHandler implements AuthenticationFailureHandler {
    private final static String UTF8 = "utf-8";
    private final static String CONTENT_TYPE = "application/json";

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        log.info("登录失败 原因: {}", exception.getMessage());
        response.setCharacterEncoding(UTF8);
        response.setContentType(CONTENT_TYPE);
        PrintWriter printWriter = response.getWriter();
        printWriter.append(JSonUtils.parse(ApiResult.fail(exception.getMessage())));
    }
}

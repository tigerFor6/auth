package com.wisdge.cloud.auth.handler;

import com.wisdge.cloud.auth.internal.SecurityConstant;
import com.wisdge.cloud.dto.ApiResult;
import com.wisdge.dataservice.utils.JSonUtils;
import com.wisdge.utils.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class TigerLogoutSuccessHandler implements LogoutSuccessHandler {

    @Resource
    private ConsumerTokenServices consumerTokenServices;


    @Override
    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        String token = httpServletRequest.getHeader(SecurityConstant.TOKEN_HEADER);
        if (StringUtils.isNotEmpty(token)) {
            String realToken = token.replace(SecurityConstant.TOKEN_PREFIX, "").trim();
            if (consumerTokenServices.revokeToken(realToken)) {
                httpServletResponse.setContentType("application/json;charset=UTF-8");
                httpServletResponse.getWriter().write(JSonUtils.parse(ApiResult.ok()));
                return;
            }
        }
        httpServletResponse.setContentType("application/json;charset=UTF-8");
        httpServletResponse.getWriter().write(JSonUtils.parse(ApiResult.unauthorized()));
    }
}

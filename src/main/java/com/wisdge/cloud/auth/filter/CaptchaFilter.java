package com.wisdge.cloud.auth.filter;

import com.wisdge.cloud.auth.internal.SecurityConstant;
import com.wisdge.cloud.dto.ApiResult;
import com.wisdge.commons.redis.RedisTemplate;
import com.wisdge.dataservice.utils.JSonUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 对/oauth/token认证请求进行验证码识别
 */
@Slf4j
@Component
public class CaptchaFilter extends OncePerRequestFilter {
    @Value("${cloud.captcha:false}")
    private String captchaType;
    @Resource
    private RedisTemplate redisTemplate;

    private String captchaIdParameter = "captchaId";
    private String captchaValueParameter = "captchaValue";

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String captchaId = this.obtainCaptchaId(httpServletRequest);
        String captchaValue = this.obtainCaptchaValue(httpServletRequest);
        if (! captchaType.equalsIgnoreCase("false")) {
            log.debug("Verify captcha with {}", captchaType);
            if (StringUtils.isEmpty(captchaId)) {
                exception(httpServletResponse,"CaptchaId must not be empty or null");
                return;
            }
            if (StringUtils.isEmpty(captchaValue)) {
                exception(httpServletResponse,"captchaValue must not be empty or null");
                return;
            }
            Object value = redisTemplate.get(SecurityConstant.REDIS_CODE_CAPTCHA + captchaId);
            if (value == null) {
                exception(httpServletResponse,"CaptchaId not exists");
                return;
            }
            redisTemplate.delete(SecurityConstant.REDIS_CODE_CAPTCHA + captchaId);
            switch(captchaType) {
                case "puzzle":
                    int real = obtainPuzzlePos(captchaValue);
                    if (real != (Integer)value) {
                        exception(httpServletResponse,"Incorrect captchaValue");
                        return;
                    }
                    break;
                case "image":
                    if (! captchaValue.equalsIgnoreCase(value.toString())) {
                        exception(httpServletResponse,"Incorrect captchaValue");
                        return;
                    }
                    break;
                default:
                    exception(httpServletResponse, "Unimplemented captcha type");
                    return;
            }
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }


    @Nullable
    protected String obtainCaptchaValue(HttpServletRequest request) {
        return request.getParameter(this.captchaValueParameter);
    }

    @Nullable
    protected String obtainCaptchaId(HttpServletRequest request) {
        return request.getParameter(this.captchaIdParameter);
    }

    protected int obtainPuzzlePos(String captchaValue) {
        try {
            return Integer.parseInt(captchaValue);
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * 意外处理
     * @param response
     * @param message
     */
    private void exception(HttpServletResponse response, String message) {
        try {
            response.getWriter().write(JSonUtils.parse(ApiResult.fail(SecurityConstant.CUSTOM_ERROR_INVALID_CAPTCHA, message)));
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }
}

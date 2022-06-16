package com.wisdge.cloud.auth.handler;

import com.wisdge.cloud.dto.ApiResult;
import com.wisdge.cloud.dto.ResultCode;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.auth.AuthenticationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.nio.file.AccessDeniedException;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * 参数未通过验证异常
     * @param exception MethodArgumentNotValidException
     */
    @ExceptionHandler(value = MethodArgumentNotValidException.class)
    public ApiResult MethodArgumentNotValidHandler(MethodArgumentNotValidException exception) {
        return ApiResult.build(ResultCode.BAD_REQUEST.getCode(), exception.getBindingResult().getFieldError().getDefaultMessage());
    }

    /**
     * 无法解析参数异常
     * @param exception
     */
    @ExceptionHandler(value = HttpMessageNotReadableException.class)
    public Object HttpMessageNotReadableHandler(HttpMessageNotReadableException exception) throws Exception {
        return ApiResult.fail("参数无法正常解析");
    }

    /**
     * 方法访问权限不足异常
     * @param exception
     */
    @ExceptionHandler(value = AccessDeniedException.class)
    public Object AccessDeniedExceptionHandler(AccessDeniedException exception) throws Exception {
        return ApiResult.forbidden("方法访问权限不足");
    }

    @ExceptionHandler(value = NoHandlerFoundException.class)
    public Object NoHandlerFoundExceptionHandler(NoHandlerFoundException exception) throws Exception {
        return ApiResult.notFound("链接不存在");
    }

    @ExceptionHandler(value = AuthenticationException.class)
    public Object AuthenticationExceptionHandler(AuthenticationException e) {
        return ApiResult.forbidden();
    }

    @ExceptionHandler(value = DuplicateKeyException.class)
    public Object DuplicateKeyExceptionHandler(DuplicateKeyException e) throws Exception {
        return ApiResult.internalError("重复的数据库主键");
    }

    @ExceptionHandler(value = Exception.class)
    @ResponseBody
    public ApiResult exceptionHandler(Exception e) {
        log.error(e.getMessage(), e);
        return ApiResult.fail(e.getMessage());
    }

}

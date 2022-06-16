package com.wisdge.cloud.auth.controller;

import com.wisdge.cloud.dto.LoginUser;
import com.wisdge.cloud.internal.CoreConstant;
import com.wisdge.utils.SnowflakeIdWorker;

import javax.annotation.Resource;
import java.util.*;

public abstract class BaseController extends com.wisdge.cloud.controller.BaseController {

    @Resource
    protected SnowflakeIdWorker snowflakeIdWorker;

    protected LoginUser getLoginUser() {
        return (LoginUser) request.getAttribute(CoreConstant.JWT_REQUEST_USER);
    }

    protected String newId() {
        return String.valueOf(snowflakeIdWorker.nextId());
    }

    protected String uuid() {
        return UUID.randomUUID().toString();
    }

}

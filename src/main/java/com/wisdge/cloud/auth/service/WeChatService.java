package com.wisdge.cloud.auth.service;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

/**
 * 微信相关业务
 */
@FeignClient(name = "wechat")
public interface WeChatService {
    /**
     * 获取openId
     * @param code
     * @return
     */
    @GetMapping("/wechat/{code}")
    String getOpenId(@PathVariable("code") String code);
}

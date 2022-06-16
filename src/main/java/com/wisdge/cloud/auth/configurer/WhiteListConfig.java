package com.wisdge.cloud.auth.configurer;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.stereotype.Component;
import java.util.ArrayList;
import java.util.List;

/**
 * @description: 过滤URL属性配置类
 */
@Data
@RefreshScope
@ConfigurationProperties(prefix = "ignore")
@Component
public class WhiteListConfig {

    private List<String> urls = new ArrayList<>();

    private List<String> client = new ArrayList<>();

}

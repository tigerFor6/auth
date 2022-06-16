package com.wisdge.cloud.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;

@Slf4j
@SpringBootApplication
@EnableDiscoveryClient
@EnableFeignClients
@ComponentScan(basePackages = { "com.wisdge.cloud"} )
@RestController
public class Application implements CommandLineRunner, DisposableBean {
    private final static CountDownLatch latch = new CountDownLatch(1);

    @Value("${cloud.app-name:cloud.auth}")
    private String appName;

    public static void main(String[] args) {
        Locale.setDefault(Locale.SIMPLIFIED_CHINESE);
        SpringApplication.run(Application.class, args);
    }

    @Override
    public void run(String... args) {
        log.info("{} ------>> 启动成功", appName);
    }

    @Override
    public void destroy() {
        latch.countDown();
        log.info("{} ------>> 关闭成功",appName);
    }

    @GetMapping("/")
    public String home() {
        return "Welcome to " + appName;
    }

}

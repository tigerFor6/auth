package com.wisdge.cloud.auth.po;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.Date;

@Data
@NoArgsConstructor
@ApiModel(value="登录用户记录")
public class LoginHis {
    @ApiModelProperty("JTI")
    private String id;
    @ApiModelProperty("用户ID")
    private String userId;
    @ApiModelProperty("登录时间")
    private Date loginTime;
    @ApiModelProperty("客户端IP")
    private String remoteIp;
    @ApiModelProperty("客户端类型")
    private String clientId;
    @ApiModelProperty("TOKEN")
    private String token;
}

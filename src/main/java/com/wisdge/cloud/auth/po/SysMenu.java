package com.wisdge.cloud.auth.po;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;


@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(value="前台菜单")
@TableName("SYS_MENU")
public class SysMenu {
    @TableId(value="id", type = IdType.ASSIGN_ID)
    @ApiModelProperty("主键")
    private String id;

    @ApiModelProperty("主键")
    private String name;

    @ApiModelProperty("菜单类型（0=目录，1=插件，2=虚拟页面）")
    private int type;

    @ApiModelProperty("内容")
    private String content;

    @ApiModelProperty("父目录")
    private String parentId;

    @ApiModelProperty("启动参数")
    private String parameter;

    @ApiModelProperty("创建者")
    private String createBy;

    @ApiModelProperty("创建时间")
    private Date createTime;

    @ApiModelProperty("更新者")
    private String updateBy;

    @ApiModelProperty("更新时间")
    private Date updateTime;

    @ApiModelProperty("持久")
    private Boolean persistent;

    @ApiModelProperty("图标")
    private String icon;

    @ApiModelProperty("隐藏")
    private Boolean hidden;

    @ApiModelProperty("自启动")
    private Boolean startup;

    @ApiModelProperty("状态")
    private int status;

    @ApiModelProperty("排序")
    private int orderIndex;

    private static final long serialVersionUID = 1L;
}
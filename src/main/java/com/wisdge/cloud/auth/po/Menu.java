package com.wisdge.cloud.auth.po;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Menu implements Serializable {
    
    /** 用户Id **/
    private String id;

    /** 上级ID，一级菜单为0 **/
    private String pid;

    /** 菜单URL **/
    private String url;

    /** 授权(多个用逗号分隔，如：sys:user:list,sys:user:save) **/
    private String permissions;

    /** 类型   0：菜单   1：按钮 **/
    private Byte type;

    /** 服务器ID **/
    private String serverId;

    /** 菜单图标 **/
    private String icon;

    /** 状态（1正常，0停用） **/
    private Integer status;

    /** 排序 **/
    private Integer sort;

    /** 创建者 **/
    private String createBy;

    /** 创建时间 **/
    private Date createTime;

    /** 更新者 **/
    private String updateBy;

    /** 更新时间 **/
    private Date updateTime;

    private static final long serialVersionUID = 1L;
}
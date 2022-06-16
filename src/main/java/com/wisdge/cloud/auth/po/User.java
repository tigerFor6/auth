package com.wisdge.cloud.auth.po;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.io.Serializable;
import java.util.List;

/**
 * 用户信息实体类
 */
@Data
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class User implements Serializable {
    public static final int STATUS_DISABLED = 0;
    public static final int STATUS_EXPIRED = -1;
    public static final int STATUS_LOCKED = -2;
    public static final int STATUS_PWD_EXPIRED = -3;

    /**
     * 用户Id
     **/
    private String id;

    /**
     * 用户名
     **/
    private String name;

    /**
     * 用户全名
     **/
    private String fullname;

    /**
     * 用户密码
     **/
    private String password;

    /**
     * 账号状态
     **/
    private int status;

    /**
     * 角色列表
     **/
    private List<Role> roles;

    /**
     * 所在组织
     **/
    private String orgId;

    private List<String> menus;

    private List<String> sysMenus;

}


package com.wisdge.cloud.auth.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface SysMenuMapper {

    @Select("select distinct T1.CONTENT from sys_menu T1\n" +
            "    left join sys_menu_role T2 on T2.MENU_ID = T1.ID\n" +
            "where T2.ROLE_ID in (" +
            "       #{roles}\n" +
            ")")
    List<String> findByRoles(@Param("roles") String roles);


}

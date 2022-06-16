package com.wisdge.cloud.auth.mapper;

import com.wisdge.cloud.auth.po.Role;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface MenuMapper {

    @Select("<script>\n" +
            "   select distinct T1.MENU_ID from role_menu T1\n" +
            "       left join sys_role T2 on T2.ID = T1.ROLE_ID\n" +
            "   where 1=1\n" +
            "       and T2.ID in (" +
            "       <foreach collection='list' index='index' separator=',' item='role'>\n" +
            "           #{role.id}\n" +
            "       </foreach>\n" +
            "   )" +
            "</script>\n")
    List<String> findByRoleMenu(@Param("list") List<Role> list);

}

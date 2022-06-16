package com.wisdge.cloud.auth.mapper;

import com.wisdge.cloud.auth.po.Role;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import java.util.List;

@Mapper
public interface RoleMapper {
    @Select("select R.ID, R.NAME from SYS_USER_ROLE UR inner join SYS_ROLE R on R.ID=UR.ROLE_ID where UR.USER_ID=#{userId}")
    List<Role> findByUserId(@Param("userId") String userId);
}

package com.wisdge.cloud.auth.mapper;

import com.wisdge.cloud.auth.po.User;
import org.apache.ibatis.annotations.*;

@Mapper
public interface UserMapper {

    @Select("select * from SYS_USER where NAME=#{username} or PHONE=#{username} or EMAIL=#{username}")
    User findByUsername(@Param("username") String username);

    @Select("select * from SYS_USER where ID=#{userId}")
    User findById(@Param("userId") String userId);

    @Select("select * from SYS_USER where PHONE=#{mobile}")
    User findByMobile(@Param("mobile") String mobile);

    @Update("update SYS_USER set PASSWORD=#{password} where ID=#{userId}")
    int updatePassword(@Param("password") String password, @Param("userId") String userId);
}

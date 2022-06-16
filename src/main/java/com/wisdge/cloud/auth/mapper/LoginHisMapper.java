package com.wisdge.cloud.auth.mapper;

import com.wisdge.cloud.auth.po.LoginHis;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface LoginHisMapper {

    @Insert("insert into T_LOGIN_HIS(ID, USER_ID, LOGIN_TIME, CLIENT_ID, REMOTE_IP, TOKEN) " +
            "values(#{loginHis.id}, #{loginHis.userId}, #{loginHis.loginTime}, " +
            "#{loginHis.clientId}, #{loginHis.remoteIp}, #{loginHis.token})")
    int insert(@Param("loginHis") LoginHis loginHis);

}

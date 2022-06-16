package com.wisdge.cloud.auth.controller;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.wisdge.cloud.auth.internal.SecurityConstant;
import com.wisdge.cloud.auth.mapper.MenuMapper;
import com.wisdge.cloud.auth.mapper.RoleMapper;
import com.wisdge.cloud.auth.mapper.SysMenuMapper;
import com.wisdge.cloud.auth.mapper.UserMapper;
import com.wisdge.cloud.auth.po.Role;
import com.wisdge.cloud.auth.po.SysMenu;
import com.wisdge.cloud.auth.po.User;
import com.wisdge.cloud.controller.BaseController;
import com.wisdge.cloud.dto.ApiResult;
import com.wisdge.utils.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.text.ParseException;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/user")
public class UserController extends BaseController {

    @Resource
    private UserMapper userMapper;
    @Resource
    private RoleMapper roleMapper;

    @Resource
    private MenuMapper menuMapper;
    @Resource
    private SysMenuMapper sysMenuMapper;

    @GetMapping("/info")
    public ApiResult getCurrentUserInfo() {
        String token = request.getHeader(SecurityConstant.TOKEN_HEADER);
        if (StringUtils.isEmpty(token)) {
            return ApiResult.unauthorized();
        }
        try {
            // 从token中解析用户信息并设置到Header中去
            String realToken = token.replace(SecurityConstant.TOKEN_PREFIX, "").trim();
            SignedJWT sjwt = SignedJWT.parse(realToken);
            JWTClaimsSet claims = sjwt.getJWTClaimsSet();
            String userId = claims.getStringClaim(SecurityConstant.TOKEN_ENHANCER_USERID);
            User user = userMapper.findById(userId);
            if (user == null) {
                return ApiResult.unauthorized();
            }
            user.setRoles(roleMapper.findByUserId(user.getId()));
            if (user.getRoles() != null && user.getRoles().size() > 0) {
                user.setMenus(menuMapper.findByRoleMenu(user.getRoles()));
            }
            StringBuilder sb = new StringBuilder();
            for(Role role : user.getRoles()) {
                if(!StringUtils.isEmpty(role.getId())) {
                    sb.append(role.getId());
                    sb.append(",");
                }
            }
            if(sb.length() > 0) {
                sb.substring(0, sb.length() - 1);
                List<String> sysMenus = sysMenuMapper.findByRoles(sb.toString());
                user.setSysMenus(sysMenus);
            }
            return ApiResult.ok("", user);
        } catch (ParseException e) {
            log.error(e.getMessage(), e);
            return ApiResult.internalError(e.getMessage());
        }
    }

    @GetMapping("/profile")
    public ApiResult getCurrentUserProfile() {
        String token = request.getHeader(SecurityConstant.TOKEN_HEADER);
        if (StringUtils.isEmpty(token)) {
            return ApiResult.unauthorized();
        }
        try {
            String realToken = token.replace(SecurityConstant.TOKEN_PREFIX, "").trim();
            SignedJWT sjwt = SignedJWT.parse(realToken);
            JWTClaimsSet claims = sjwt.getJWTClaimsSet();
            return new ApiResult(claims.toJSONObject());
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return ApiResult.fail(e.getMessage());
        }
    }
}

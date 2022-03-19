package com.xy.service.impl;

import com.xy.domain.LoginUser;
import com.xy.domain.ResponseResult;
import com.xy.domain.User;
import com.xy.service.LoginService;
import com.xy.utils.JwtUtil;
import com.xy.utils.RedisCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * @program: SpringSecurityDemo
 * *
 * @author: XY
 * @create: 2022-03-08 10:10
 **/

@Service
public class LoginServiceImpl implements LoginService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisCache redisCache;

    @Override
    public ResponseResult login(User user) {

        //AuthenticationManager authenticate 进行用户认证
        //TODO 在这里就会调用之前写的****UserDetailsService******中查询数据库中的用户信息，然后进行比对
        System.out.println("开始执行登录业务LoginService.login");

        //TODO 需要先将前端传来的username和password封装成UsernamePasswordAuthenticationToken类
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(user.getUserName(),user.getPassword());

        //TODO 调用authenticationManager中的authenticate进行验证
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
        //未通过，就给出提示
        System.out.println(authenticate);
        if(Objects.isNull(authenticate)){
            throw new RuntimeException("登录失败");
            //return new ResponseResult(404,"登录失败");
        }
        //TODO 如果认证通过，使用userid 生成一个jwt jwt存入 ResponseResult中
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        String userid = loginUser.getUser().getId().toString();
        String jwt = JwtUtil.createJWT(userid);
        Map<String,String> map = new HashMap<>();
        map.put("token",jwt);
        //TODO 把完整的用户信息存入redis userid作为key
        redisCache.setCacheObject("login:"+userid,loginUser);
        System.out.println("登录业务完成，成功生成jwt-token");
        return new ResponseResult(200,"登录成功",map);
    }

    @Override
    public ResponseResult logout() {
        //TODO 获取SecurityContextHolder中的用户id
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginuser = (LoginUser) authentication.getPrincipal();
        String userid = loginuser.getUser().getId().toString();

        //TODO 删除redis中的token
        String token = "login:"+userid;
        redisCache.deleteObject(token);
        return new ResponseResult(200,"注销成功");
    }
}

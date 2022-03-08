package com.xy.controller;

import com.xy.domain.ResponseResult;
import com.xy.domain.User;
import com.xy.service.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @program: SpringSecurityDemo
 * *
 * @author: XY
 * @create: 2022-03-08 10:05
 **/

@RestController
public class LoginController {

    @Autowired
    private LoginService loginService;

    @PostMapping("/user/login")
    public ResponseResult login(@RequestBody User user){
        System.out.println("开始执行登录controller");
        return loginService.login(user);
    }

    @RequestMapping("/user/logout")
    public ResponseResult logout(){
        return loginService.logout();
    }

}

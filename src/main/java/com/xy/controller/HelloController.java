package com.xy.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @program: SpringSecurityDemo
 * *
 * @author: XY
 * @create: 2022-03-07 17:38
 **/

@RestController
public class HelloController {

    @RequestMapping("/hello")
    public String hello(){
        return "hello spring boot is running~~~";
    }
}

package com.xy.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.xy.domain.LoginUser;
import com.xy.domain.User;
import com.xy.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Objects;

/**
 * @program: SpringSecurityDemo
 * *
 * @author: XY
 * @create: 2022-03-07 20:31
 **/
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;

    //根据用户信息查询用户信息(查询数据库中的信息)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //TODO 数据库中查询用户信息
        System.out.println("开始执行loadUserByUsername,在数据库中查询用户名的信息");
        LambdaQueryWrapper<User> lambdaQueryWrapper = new LambdaQueryWrapper<>();
        lambdaQueryWrapper.eq(User::getUserName,username);
        User user=userMapper.selectOne(lambdaQueryWrapper);
        if(Objects.isNull(user)){
            throw new UsernameNotFoundException("用户名为空");
        }

        //TODO 查询对应权限信息


        //TODO 封装成UserDetails类别返回

        return new LoginUser(user);
    }
}

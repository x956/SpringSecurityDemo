package com.xy;

import com.xy.domain.User;
import com.xy.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

/**
 * @program: SpringSecurityDemo
 * *
 * @author: XY
 * @create: 2022-03-07 20:22
 **/

@SpringBootTest
public class UserMapperTest {

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private PasswordEncoder pe;

    @Test
    public void testUserMapper(){
        //List<User> users = userMapper.selectList(null);

        System.out.println(pe.encode("123456"));
        //System.out.println(users);
    }

}

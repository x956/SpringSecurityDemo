package com.xy;

import com.xy.mapper.MenuMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

/**
 * @program: SpringSecurityDemo
 * *
 * @author: XY
 * @create: 2022-03-19 14:17
 **/

@SpringBootTest
public class MenuMapperTest {

    @Autowired
    private MenuMapper menuMapper;


    @Test
    public void testSelectPermById(){
        List<String> list = menuMapper.selectPermsByUserId(1L);
        System.out.println(list.toString());

    }
}

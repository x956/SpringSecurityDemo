package com.xy.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.xy.domain.User;
import org.apache.ibatis.annotations.Mapper;

/**
 * @program: SpringSecurityDemo
 * *
 * @author: XY
 * @create: 2022-03-07 20:18
 **/
@Mapper
public interface UserMapper extends BaseMapper<User> {
}

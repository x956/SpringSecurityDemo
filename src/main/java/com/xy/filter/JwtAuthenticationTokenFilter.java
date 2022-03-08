package com.xy.filter;

import com.xy.domain.LoginUser;
import com.xy.utils.JwtUtil;
import com.xy.utils.RedisCache;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

/**
 * @program: SpringSecurityDemo
 * *
 * @author: XY
 * @create: 2022-03-08 19:00
 **/

@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private RedisCache redisCache;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("开始进行JWT过滤...");
        //获取token
        String token = request.getHeader("token");
        if(!StringUtils.hasText(token)){    //如果token是空的
            //放行，交给之后的过滤器处理
            filterChain.doFilter(request,response);
            return;
        }

        //解析token获取其中的userid
        String userid;
        try {
            Claims claims = JwtUtil.parseJWT(token);
            userid = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("token非法");
        }
        //从redis获取用户信息
        String redisKey = "login:"+userid;
        LoginUser loginUser=redisCache.getCacheObject(redisKey);
        if(Objects.isNull(loginUser)){
            throw new RuntimeException("用户未登录");
        }
        //存入SecurityContextHolder
        // TODO 这里还是需要去传入权限信息
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginUser,null,null);
        //其他的过滤器资源可以从securityContextHolder中获取用户的信息
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        //放行
        filterChain.doFilter(request,response);
        System.out.println("jwt过滤器已经完成");
    }
}

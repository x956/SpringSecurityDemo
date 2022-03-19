package com.xy.handler;

import com.alibaba.fastjson.JSON;
import com.xy.domain.ResponseResult;
import com.xy.utils.WebUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.alibaba.fastjson.JSON.toJSONString;

/**
 * @program: SpringSecurityDemo
 * *
 * @author: XY
 * @create: 2022-03-19 19:35
 **/
@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        //处理权限异常
        ResponseResult result = new ResponseResult(HttpStatus.FORBIDDEN.value(),"权限不足");
        String json = JSON.toJSONString(result);
        WebUtils.renderString(response,json);

    }
}

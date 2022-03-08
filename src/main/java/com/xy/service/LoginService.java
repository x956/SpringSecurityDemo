package com.xy.service;

import com.xy.domain.ResponseResult;
import com.xy.domain.User;

public interface LoginService {
    ResponseResult login(User user);

    ResponseResult logout();
}

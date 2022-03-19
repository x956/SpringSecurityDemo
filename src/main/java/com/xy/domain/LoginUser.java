package com.xy.domain;

import com.alibaba.fastjson.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @program: SpringSecurityDemo
 * *
 * @author: XY
 * @create: 2022-03-07 20:52
 **/
@Data
@NoArgsConstructor
public class LoginUser implements UserDetails {

    @Autowired
    private User user;

    private List<String> permissions;

    public LoginUser(User user,List<String> permissions){
        this.user = user;
        this.permissions = permissions;
    }

    //************不会序列化到redis中****************
    @JSONField(serialize = false)
    private List<GrantedAuthority> authorities;

    // SpringSecurity需要调用这个方法获取权限
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        //TODO 把permissions中的String类型的权限信息封装成SimpleGrantedAuthority
        if(authorities!=null){
            return authorities;
        }

//        List<GrantedAuthority> authorities = new ArrayList<>();
//        for (String permission : permissions) {
//            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(permission);
//            authorities.add(authority);
//        }
        authorities = permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUserName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

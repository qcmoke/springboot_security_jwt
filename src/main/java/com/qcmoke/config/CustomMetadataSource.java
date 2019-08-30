package com.qcmoke.config;

import com.qcmoke.entity.Menu;
import com.qcmoke.entity.Role;
import com.qcmoke.service.MenuService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;
import java.util.List;

/**
 * 给请求url赋予数据库中对应的角色列表，如果数据库中不存在则给与该url一个ROLE_LOGIN角色
 * 两种情况:
 * 1.对于需要除了登录以外的角色以外的请求url，给该请求配置所有与之相关的角色
 * 2.对于仅仅只需要登录权限的请求url，可以统一规定需要ROLE_LOGIN角色
 * Created by sang on 2017/12/28.
 */
@Component
public class CustomMetadataSource implements FilterInvocationSecurityMetadataSource {
    @Autowired
    MenuService menuService;
    AntPathMatcher antPathMatcher = new AntPathMatcher();


    @Override
    public Collection<ConfigAttribute> getAttributes(Object o) {
        String requestUrl = ((FilterInvocation) o).getRequestUrl();
        List<Menu> allMenu = menuService.getAllMenu();
        for (Menu menu : allMenu) {
            if (antPathMatcher.match(menu.getUrl(), requestUrl)
                    && menu.getRoles().size() > 0) {
                List<Role> roles = menu.getRoles();
                int size = roles.size();
                String[] values = new String[size];
                for (int i = 0; i < size; i++) {
                    values[i] = roles.get(i).getName();
                }
                return SecurityConfig.createList(values);
            }
        }
        //没有匹配上的资源，都是登录访问，对于登录的角色可自定义为ROLE_LOGIN角色
        return SecurityConfig.createList("ROLE_LOGIN");
    }


    /**
     * getA!lConfigAttributes 方法用来返回所有定义好的权限资源， Spring Security 在启动时会校验
     * 相关配置是否正确 ，如果 需要校验，那么该方法直接返回 null 即可
     *
     * @return null
     */
    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    /**
     * 返回类对象是否支持校验。
     *
     * @param aClass
     * @return boolean
     */
    @Override
    public boolean supports(Class<?> aClass) {
        return FilterInvocation.class.isAssignableFrom(aClass);
    }
}

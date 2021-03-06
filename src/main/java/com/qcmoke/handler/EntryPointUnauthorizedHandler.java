package com.qcmoke.handler;

import com.qcmoke.utils.RespBean;
import com.qcmoke.utils.ResponseWriterUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 用来解决匿名用户访问无权限资源时的异常
 */
@Component
@Slf4j
public class EntryPointUnauthorizedHandler implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
//        log.info(String.format("className:%s,msg:%s", e.getClass().getName(), e.getMessage()));
        log.error("className:{},msg:{}", e.getClass().getName(), e.getMessage());
        ResponseWriterUtil.writeJson(RespBean.unauthorized("请登录认证完成再请求该接口！"));
    }
}

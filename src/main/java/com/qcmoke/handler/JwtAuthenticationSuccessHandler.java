package com.qcmoke.handler;

import com.qcmoke.utils.JwtUtil;
import com.qcmoke.utils.RespBean;
import com.qcmoke.utils.ResponseWriterUtil;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String jwtToken = JwtUtil.geneJsonWebToken(authentication);
        if (jwtToken == null) {
            ResponseWriterUtil.writeJson(RespBean.error("登录认证失败"));
        }
        response.addHeader(JwtUtil.RESPONSE_HEADER_TOKEN_NAME, JwtUtil.TOKEN_PREFIX + jwtToken);
        ResponseWriterUtil.writeJson(response, HttpStatus.OK.value(), RespBean.ok("认证成功", authentication));
    }
}

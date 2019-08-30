package com.qcmoke.filter;

import com.qcmoke.utils.RespBean;
import com.qcmoke.utils.ResponseWriterUtil;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Date;


public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    public static final String SECRET = "qcmoke.com";
    public static final long EXPIRATION_TIME = 10 * 60 * 1000; // 10 days
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_NAME = "Authorization";


    /**
     * @param loginUrl              登录请求接口
     * @param authenticationManager authenticationManager
     */
    public JwtAuthenticationFilter(String loginUrl, AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher(loginUrl));
        setAuthenticationManager(authenticationManager);
    }

    /**
     * 从登录请求中提取出参数，去校验用户名密码是否正确
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse resp) throws AuthenticationException, IOException, ServletException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");
        Authentication authenticate = null;
        try {
            //执行登录认证
            authenticate = getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(username, password));
//            SecurityContextHolder.getContext().setAuthentication(authenticate);//如果希望在这个过滤器中获取SecurityContextHolder.getContext().getAuthentication()，则需要做此设置
        } catch (AuthenticationException e) {
            RespBean respBean = null;
            if (e instanceof BadCredentialsException ||
                    e instanceof UsernameNotFoundException) {
                respBean = RespBean.error("账户名或者密码输入错误!");
            } else if (e instanceof LockedException) {
                respBean = RespBean.error("账户被锁定，请联系管理员!");
            } else if (e instanceof CredentialsExpiredException) {
                respBean = RespBean.error("密码过期，请联系管理员!");
            } else if (e instanceof AccountExpiredException) {
                respBean = RespBean.error("账户过期，请联系管理员!");
            } else if (e instanceof DisabledException) {
                respBean = RespBean.error("账户被禁用，请联系管理员!");
            } else {
                respBean = RespBean.error("登录失败!");
            }
            ResponseWriterUtil.writeJson(resp, HttpStatus.UNAUTHORIZED.value(), respBean);
        }
        return authenticate;
    }


    /**
     * 登录成功的回调
     * 如果登录成功，在这个方法中返回 jwt token
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        StringBuffer as = new StringBuffer();
        for (GrantedAuthority authority : authorities) {
            as.append(authority.getAuthority()).append(",");
        }
        String jwtToken = Jwts.builder()
                .claim("authorities", as)//配置用户角色
                .setSubject(authResult.getName())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();
        response.addHeader(HEADER_NAME, TOKEN_PREFIX + jwtToken);
        ResponseWriterUtil.writeJson(response, HttpStatus.OK.value(), RespBean.ok("认证成功", authResult));
    }

    /**
     * 登录失败的回调
     * 这里返回登录失败的错误提示即可
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest req, HttpServletResponse resp, AuthenticationException failed) throws IOException, ServletException {
        ResponseWriterUtil.writeJson(HttpStatus.INTERNAL_SERVER_ERROR.value(), RespBean.error("登录认证失败"));
    }
}

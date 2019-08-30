package com.qcmoke.filter;

import com.qcmoke.utils.RespBean;
import com.qcmoke.utils.ResponseWriterUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;


/**
 * 在WebSecurityConfig中禁用session后，就不会存在返回sessionid给客户端cookie，因此就不能确保会话的状态，
 * 那么springsecurity就不能识别每次请求的用户是否是已经登录认证过的了，那么就需要客户端每次请求都要携带token，通过token给springsecurity设置用户名和角色等信息，以此来保证每次请求的状态，而不是保证整个会话的状态。
 *
 *
 * 所有的其他请求都会来到这个方法中
 * 在这个方法中，提取出客户端传来的 JWT Token，并进行解析，解析后得到的用户、角色等信息封装到UsernamePasswordAuthenticationToken中，并设置到SecurityContext上下文中。不需要设置密码，因为验证过的jwt token的数据已经确定用户的安全性
 */

public class JwtAuthorizationFilter extends GenericFilterBean {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String jwtToken = request.getHeader("authorization");
        Claims claims = null;
        try {
            claims = Jwts.parser().setSigningKey(JwtAuthenticationFilter.SECRET).parseClaimsJws(jwtToken.replace(JwtAuthenticationFilter.TOKEN_PREFIX, ""))
                    .getBody();
            String username = claims.getSubject();//获取当前登录用户名
            List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList((String) claims.get("authorities"));
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(token);//SecurityContextHolder利用了一个SecurityContextHolderStrategy(具体实现org.springframework.security.core.context.ThreadLocalSecurityContextHolderStrategy)（存储策略）进行上下文的存储，而ThreadLocalSecurityContextHolderStrategy通过ThreadLocal为每个线程开辟一个存储区域（即SecurityContext安全上下文），来存储相应的对象。
            filterChain.doFilter(request, servletResponse);
        } catch (Exception e) {
            ResponseWriterUtil.writeJson(HttpStatus.UNAUTHORIZED.value(), RespBean.error("请携带正确的token"));
        }
    }
}

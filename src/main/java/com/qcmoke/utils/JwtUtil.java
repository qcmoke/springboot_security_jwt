package com.qcmoke.utils;

import io.jsonwebtoken.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * jwt工具类
 */
@SuppressWarnings("all")
public class JwtUtil {

    //请求体token名称
    public static final String REQUEST_TOKEN_NAME = "authorization";

    //响应体token名称
    public static final String RESPONSE_HEADER_TOKEN_NAME = "Authorization";
    //token字符串前缀
    public static final String TOKEN_PREFIX = "Bearer ";


    //token自定义的属性
    public static final String AUTHORITIES_NAME = "authorities";


    //过期时间，毫秒，一周
    public static final long EXPIRATION_TIME = 1000 * 60 * 60 * 24 * 7;

    //秘钥
    public static final String APPSECRET = "qcmoke9860";


    /**
     * 生成jwt token（其实就是通过jwt对用户进行加密）
     *
     * @param authentication 用户，要求user不能为null，并且用户username、authorities都不能为空
     * @return token
     */
    public static String geneJsonWebToken(Authentication authentication) {

        if (authentication == null || authentication.getName() == null || authentication.getAuthorities() == null || authentication.getAuthorities().size() == 0) {
            return null;
        }

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        StringBuffer as = new StringBuffer();
        for (GrantedAuthority authority : authorities) {
            as.append(authority.getAuthority()).append(",");
        }

        String token = Jwts.builder()
                /*1.设置发行者*/
                .setSubject(authentication.getName())
                /*2.设置自定义的属性*/
                .claim(AUTHORITIES_NAME, as)//配置用户角色
                /*3.设置发行时间*/
                .setIssuedAt(new Date())
                /*4.设置过期时间*/
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))

                /*5.设置签名的类型和秘钥*/
                .signWith(SignatureAlgorithm.HS256, APPSECRET).compact();

        return token;
    }


    /**
     * 获取Claims
     * 校验token（其实就是对用户token进行解密验证）
     *
     * @param token
     * @return
     */
    public static Claims getClaims(String token) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException {
        if (token == null) {
            return null;
        }
        //通过秘钥解密token
        return Jwts.parser().setSigningKey(APPSECRET).parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                .getBody();
    }


    /**
     * 返回Authentication对象
     *
     * @param token
     * @return UsernamePasswordAuthenticationToken
     * @throws ExpiredJwtException
     * @throws UnsupportedJwtException
     * @throws MalformedJwtException
     * @throws SignatureException
     * @throws IllegalArgumentException
     */
    public static Authentication getAuthentication(String token) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException {
        Claims claims = getClaims(token);
        if (claims == null) {
            return null;
        }
        String username = claims.getSubject();//获取当前登录用户名
        List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList((String) claims.get(AUTHORITIES_NAME));
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
        return usernamePasswordAuthenticationToken;
    }


    /**
     * 验证token是否正确并有效
     *
     * @param token
     * @return
     */
    public boolean validateToken(String token) {
        boolean flag = false;
        try {
            Claims claims = getClaims(token);
            if (claims != null) {
                return true;
            }
        } catch (Exception e) {
            flag = false;
        }
        return flag;
    }
}
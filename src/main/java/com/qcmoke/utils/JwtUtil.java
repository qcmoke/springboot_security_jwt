package com.qcmoke.utils;

import com.qcmoke.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.GrantedAuthority;

import java.util.Date;

/**
 * jwt工具类
 */
@SuppressWarnings("all")
public class JwtUtil {

    /**
     * 定义发行者
     */
    public static final String SUBJECT = "qcmoke";

    /**
     * 过期时间，毫秒，一周
     */
    public static final long EXPIRE = 1000 * 60 * 60 * 24 * 7;

    /**
     * 秘钥
     */
    public static final String APPSECRET = "qcmoke9860";

    /**
     * 生成jwt token（其实就是通过jwt对用户进行加密）
     *
     * @param user 用户，要求user不能为null，并且用户username、authorities都不能为空
     * @return token
     */
    public static String geneJsonWebToken(User user) {

        if (user == null || user.getUsername() == null || user.getAuthorities() == null || user.getAuthorities().size() == 0) {
            return null;
        }
        StringBuffer as = new StringBuffer();
        for (GrantedAuthority authority : user.getAuthorities()) {
            as.append(authority.getAuthority()).append(",");
        }

        String token = Jwts.builder()
                /*1.设置发行者*/
                .setSubject(SUBJECT)

                /*2.设置自定义的属性*/
                .claim("username", user.getUsername())
                .claim("authorities", as)//配置用户角色

                /*3.设置发行时间*/
                .setIssuedAt(new Date())

                /*4.设置过期时间*/
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE))

                /*5.设置签名的类型和秘钥*/
                .signWith(SignatureAlgorithm.HS256, APPSECRET).compact();

        return token;
    }


    /**
     * 校验token（其实就是对用户token进行解密验证）
     *
     * @param token
     * @return
     */
    public static Claims checkJWT(String token) {
        try {
            //通过秘钥解密token
            return Jwts.parser().setSigningKey(APPSECRET).
                    parseClaimsJws(token).getBody();

        } catch (Exception e) {
            return null;
        }
    }
}
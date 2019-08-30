package com.qcmoke.config;

import com.qcmoke.filter.JwtAuthenticationFilter;
import com.qcmoke.filter.JwtAuthorizationFilter;
import com.qcmoke.service.SysUserDetailsService;
import com.qcmoke.utils.RespBean;
import com.qcmoke.utils.ResponseWriterUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    SysUserDetailsService sysUserDetailsService;

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }


    /**
     * 认证配置
     *
     * @param auth AuthenticationManagerBuilder
     * @throws Exception 异常
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /*
         * 1.通过hrService设置从数据库获取用户数据并设置UserDetails
         * 2.设置登录时用户密码的加密方案，要求：登录时用户密码的加密方案 和 注册（org.sang.service.HrService#hrReg(java.lang.String, java.lang.String)）时用户密码的加密方案一致
         *(其实发现省略这两项也可以)
         */
        auth.userDetailsService(sysUserDetailsService)
                .passwordEncoder(this.passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                /**
                 * 需要授权的请求
                 */
                .antMatchers("/hello").hasRole("user")
                .antMatchers("/admin").hasRole("admin")


                /*登录表单详细配置*/
                .and()
                //loginPage登录访问页面;loginProcessingUrl示登录请求处理接口
                .formLogin().loginPage("/login_p")
                .loginProcessingUrl("/login")
                .usernameParameter("username").passwordParameter("password")

                /*注销登录配置*/
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler((request, response, authentication) -> {
                    RespBean respBean = RespBean.ok("注销成功!");
                    ResponseWriterUtil.writeJson(response, HttpStatus.OK.value(), respBean);
                }).permitAll()

                .and()
                .addFilterAfter(new JwtAuthenticationFilter("/login", authenticationManager()), SecurityContextPersistenceFilter.class) //可以用来取代登录认证成功和失败的Handler
                .addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)//在授权之前给springsecurity注入请求中token的用户名和角色(权限)等信息
                /*关闭csrf*/
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //禁用session(否则使用token验证没有意义)，不创建session会话，不会返回sessionid给客户端


                .and()
                /*无权限访问异常处理*/
                .exceptionHandling().accessDeniedHandler(
                new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        RespBean error = RespBean.error("权限不足，请联系管理员!");
                        ResponseWriterUtil.writeJson(response, HttpStatus.FORBIDDEN.value(), error);
                    }
                });

    }
}

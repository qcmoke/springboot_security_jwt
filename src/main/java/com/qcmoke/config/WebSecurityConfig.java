package com.qcmoke.config;

import com.qcmoke.filter.JwtAuthorizationFilter;
import com.qcmoke.handler.*;
import com.qcmoke.service.SysUserDetailsService;
import com.qcmoke.utils.SpringSecurityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    SysUserDetailsService sysUserDetailsService;
    @Autowired
    CustomMetadataSource metadataSource;
    @Autowired
    UrlAccessDecisionManager urlAccessDecisionManager;
    @Autowired
    JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler;
    @Autowired
    JwtAuthenticationFailureHandler jwtAuthenticationFailureHandler;
    @Autowired
    JwtAccessDeniedHandler jwtAccessDeniedHandler;
    @Autowired
    EntryPointUnauthorizedHandler entryPointUnauthorizedHandler;
    @Autowired
    JwtAuthorizationFilter jwtAuthorizationFilter;
    @Autowired
    JwtLogoutHandler jwtLogoutHandler;


    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }


    /**
     * 忽略的拦截配置
     * 注意：不能把登录/login等受到springsecurity管理的请求地址ignoring掉，否则这些地址将不受到springsecurity管理，那么登录操作将不起作用。
     *
     * @param web WebSecurity
     * @throws Exception 异常
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
        String[] ignoreUris = SpringSecurityUtil.getIgnoreUris();
        web.ignoring().antMatchers(ignoreUris);
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
                 * 静态授权的请求
                 */
                /*
                 在使用数据库动态设置授权的请求后，这些静态授权的请求就会由于自定义CustomMetadataSource而失效
                 .antMatchers("/test").hasRole("admin")
                 .antMatchers("/test2").hasRole("admin")
                 */
                /**
                 * 通过数据库动态设置授权的请求
                 */
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O o) {
                        o.setSecurityMetadataSource(metadataSource);//给请求url赋予对应的角色字符串，但不做是否匹配的判断
                        o.setAccessDecisionManager(urlAccessDecisionManager);//判断url和角色是否匹配
                        return o;
                    }
                })

                /*登录表单详细配置*/
                .and()
                //loginPage登录访问页面;loginProcessingUrl示登录请求处理接口
                .formLogin()
                .loginPage("/login_p")
                .loginProcessingUrl("/login")
                .usernameParameter("username").passwordParameter("password")
                .successHandler(jwtAuthenticationSuccessHandler)
                .failureHandler(jwtAuthenticationFailureHandler) //认证不成功

                /*注销登录配置*/
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(jwtLogoutHandler)
                .permitAll()

                .and()
                //.addFilterAfter(new JwtAuthenticationFilter("/login", authenticationManager()), SecurityContextPersistenceFilter.class) //可以用这个过滤器来取代登录认证成功和失败的Handler
                .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)//在授权之前给springsecurity注入请求中token的用户名和角色(权限)等信息
                /*关闭csrf*/
                .csrf().disable()
                //禁用session(否则使用token验证没有意义)，不创建session会话，不会返回sessionid给客户端
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                /*无权限访问异常处理*/
                .exceptionHandling()
                .accessDeniedHandler(jwtAccessDeniedHandler)//用来解决认证过的用户访问无权限资源时的异常
                .authenticationEntryPoint(entryPointUnauthorizedHandler);//用来解决匿名用户(即为登录认证)访问无权限资源时的异常
    }
}

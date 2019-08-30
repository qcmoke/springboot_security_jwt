package com.qcmoke;

import org.junit.Test;
import org.springframework.util.AntPathMatcher;

//@RunWith(SpringRunner.class)
//@SpringBootTest
public class JwtApplicationTests {

    @Test
    public void contextLoads() {

        String url1 = "/login/html/ss";
        String url2 = "/login/**";
        String url3 = "/login/*";
        String url4 = "demo.html";
        String url5= "*.html";
        System.out.println(new AntPathMatcher().matchStart(url2,url1));
        System.out.println(new AntPathMatcher().matchStart(url3,url1));
        System.out.println(new AntPathMatcher().matchStart(url5,url4));
    }

}

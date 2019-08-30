package com.qcmoke.controller;

import com.qcmoke.utils.RespBean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class HelloController {
    @GetMapping("/hello")
    public RespBean hello() {
        return RespBean.ok("hello jwt !");
    }

    @GetMapping("/admin")
    public RespBean admin() {
        return RespBean.ok("hello admin !");
    }

    @RequestMapping("/test")
    public RespBean test() {
        return RespBean.ok("hello test !");
    }

    @RequestMapping("/test2")
    public RespBean test2() {
        return RespBean.ok("hello test2 !");
    }
}

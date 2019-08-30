package com.qcmoke.utils;

import org.springframework.http.HttpStatus;

public class RespBean {
    private Integer status;
    private String msg;
    private Object obj;

    private RespBean() {
    }


    public static  RespBean ok(String msg, Object obj) {
        return new RespBean(HttpStatus.OK.value(), msg, obj);
    }

    public static RespBean ok(String msg) {
        return new RespBean(HttpStatus.OK.value(), msg, null);
    }

    public static RespBean error(String msg, Object obj) {
        return new RespBean(HttpStatus.INTERNAL_SERVER_ERROR.value(), msg, obj);
    }

    public static RespBean error(String msg) {
        return new RespBean(HttpStatus.INTERNAL_SERVER_ERROR.value(), msg, null);
    }


    public static RespBean unauthorized(String msg) {
        return new RespBean(HttpStatus.UNAUTHORIZED.value(), msg, null);
    }

    private RespBean(Integer status, String msg, Object obj) {
        this.status = status;
        this.msg = msg;
        this.obj = obj;
    }

    public Integer getStatus() {
        return status;
    }

    public RespBean setStatus(Integer status) {
        this.status = status;
        return this;
    }

    public String getMsg() {
        return msg;
    }

    public RespBean setMsg(String msg) {
        this.msg = msg;
        return this;
    }

    public Object getObj() {
        return obj;
    }

    public RespBean setObj(Object obj) {
        this.obj = obj;
        return this;
    }
}

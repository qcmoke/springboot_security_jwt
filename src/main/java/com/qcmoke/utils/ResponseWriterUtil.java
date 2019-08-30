package com.qcmoke.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;


public class ResponseWriterUtil {
    /**
     * @param httpServletResponse HttpServletResponse
     * @param status              相应状态码
     * @param respBean            RespBean
     * @throws IOException 相应IO异常
     */
    public static void writeJson(HttpServletResponse httpServletResponse, final int status, RespBean respBean) throws IOException {
        httpServletResponse.setStatus(status);
        httpServletResponse.setContentType("application/json;charset=UTF-8");
        PrintWriter out = httpServletResponse.getWriter();
        out.write(new ObjectMapper().writeValueAsString(respBean));
        out.flush();
        out.close();
    }


    /**
     * @param status   相应状态码
     * @param respBean RespBean
     * @throws IOException 相应IO异常
     */
    public static void writeJson(final int status, RespBean respBean) throws IOException {
        ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            HttpServletResponse httpServletResponse = requestAttributes.getResponse();
            if (httpServletResponse != null) {
                ResponseWriterUtil.writeJson(httpServletResponse, status, respBean);
            }
        }
    }

    public static void writeOk(RespBean respBean) throws IOException {
        ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            HttpServletResponse httpServletResponse = requestAttributes.getResponse();
            if (httpServletResponse != null) {
                ResponseWriterUtil.writeJson(httpServletResponse, HttpStatus.OK.value(), respBean);
            }
        }
    }

    public static void writeError(RespBean respBean) throws IOException {
        ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            HttpServletResponse httpServletResponse = requestAttributes.getResponse();
            if (httpServletResponse != null) {
                ResponseWriterUtil.writeJson(httpServletResponse, HttpStatus.INTERNAL_SERVER_ERROR.value(), respBean);
            }
        }
    }

    public static void writeOk(Object obj) throws IOException {
        ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            HttpServletResponse httpServletResponse = requestAttributes.getResponse();
            if (httpServletResponse != null) {
                ResponseWriterUtil.writeJson(httpServletResponse, HttpStatus.OK.value(), RespBean.ok(null, obj));
            }
        }
    }

}

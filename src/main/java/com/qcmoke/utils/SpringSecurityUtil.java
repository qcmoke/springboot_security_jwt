package com.qcmoke.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SpringSecurityUtil {

    private static String[] ignoreUris;
    private static String[] openUris;


    @Value("${security.open-uris}")
    public void setOpenUris(String openUris) {
        SpringSecurityUtil.openUris = openUris.split(",");
    }

    @Value("${security.ignore-uris}")
    public void setIgnoreUri(String uris) {
        ignoreUris = uris.split(",");
    }

    public static String[] getIgnoreUris() {
        return ignoreUris;
    }

    public static String[] getOpenUris() {
        return openUris;
    }

}

package com.hwlcn.web.spring;

import org.apache.commons.lang3.StringUtils;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.UUID;

/**
 * User: HuangWeili
 * Date: 13-6-23
 * Time: 下午4:22
 */
public class FormTokenInterceptor extends HandlerInterceptorAdapter {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        HttpSession session = request.getSession();
        String token = request.getParameter(WebConfig.TOKEN_KEY);
        if (!StringUtils.isEmpty(token)) {

            Object keyOjbet = session.getAttribute(WebConfig.TOKEN_KEY);
            if (keyOjbet != null) {
                if (!token.equals(keyOjbet.toString())) {
                    response.sendRedirect("/font/resubmit.html");
                    return false;
                }
            }
        }
        String uuid = UUID.randomUUID().toString();
        session.setAttribute(WebConfig.TOKEN_KEY, uuid);
        return true;
    }
}

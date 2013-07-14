package com.hwlcn.web.font.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * User: HuangWeili
 * Date: 13-6-23
 * Time: 下午4:39
 */
@Controller("commonController")
public class CommonController {
    @RequestMapping(value = "/resubmit.html", method = RequestMethod.GET)
    public String resubmit(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "font/resubmit";
    }

    @RequestMapping(value = "/unauthorized.html")
    public String unauthorized(HttpServletRequest request,HttpServletResponse response,Model model){
        return "font/unauthorized";
    }

}

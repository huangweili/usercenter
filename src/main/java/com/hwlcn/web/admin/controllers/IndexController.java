package com.hwlcn.web.admin.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class IndexController {


    @RequestMapping(value = {"", "/", "/index.html"}, method = RequestMethod.GET)
    public String index(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "index";
    }

    ;


    @RequestMapping(value = "/login.html", method = RequestMethod.GET)
    public String login(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "login";
    }


    @RequestMapping(value = "/login.html", method = RequestMethod.POST)
    public String logined(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "index";
    }


    /**
     * 注销用户
     *
     * @param request
     * @param response
     * @param model
     * @return
     */
    @RequestMapping(value = "logout.html")
    public String logout(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "index";
    }
}

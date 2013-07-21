package com.hwlcn.web.admin.controllers;

import com.hwlcn.security.authz.annotation.Logical;
import com.hwlcn.security.authz.annotation.RequiresRoles;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller("adminIndexController")
@RequestMapping("/admin")
public class IndexController {

    @RequiresRoles(value = {"admin","test"},logical = Logical.AND)
    @RequestMapping(value = {"", "/", "/index.html"}, method = RequestMethod.GET)
    public String index(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "admin/index";
    }

    ;


    @RequestMapping(value = "/login.html", method = RequestMethod.GET)
    public String login(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "admin/login";
    }


    @RequestMapping(value = "/login.html", method = RequestMethod.POST)
    public String logined(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "admin/index";
    }


    /**
     * 注销用户
     *
     * @param request
     * @param response
     * @param model
     * @return
     */
    @RequestMapping(value = "/logout.html")
    public String logout(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "admin/index";
    }
}

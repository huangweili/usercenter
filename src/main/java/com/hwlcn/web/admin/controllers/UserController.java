package com.hwlcn.web.admin.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * User: HuangWeili
 * Date: 13-6-23
 * Time: 下午3:24
 */

@Controller
public class UserController {

    /**
     * 创建用户
     *
     * @return
     */
    @RequestMapping(value = "createUser.html", method = RequestMethod.GET)
    public String createUser(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "createUser";
    }

    @RequestMapping(value = "createUser.html", method = RequestMethod.POST)
    @ResponseBody
    public String createdUser(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "";
    }

    /**
     * 编辑用户
     *
     * @param request
     * @param response
     * @param model
     * @return
     */
    @RequestMapping(value = "editUser.html", method = RequestMethod.GET)
    public String editUser(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "editUser";
    }

    @RequestMapping(value = "editUser.html", method = RequestMethod.POST)
    @ResponseBody
    public String editedUser(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "";
    }

    /**
     * 删除用户
     *
     * @param request
     * @param response
     * @param model
     * @return
     */
    @RequestMapping(value = "deleteUser.html", method = RequestMethod.POST)
    @ResponseBody
    public String deletedUser(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "";
    }


}

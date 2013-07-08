package com.hwlcn.web.font.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * User: HuangWeili
 * Date: 13-6-22
 * Time: 下午11:02
 */

@Controller
public class IndexController {


    /**
     * 个人信息获取
     *
     * @return
     */
    @RequestMapping(value = {"/", "", "index.html"}, method = RequestMethod.GET)
    public String index() {

        return "index";
    }

    /**
     * 编辑操作类
     *
     * @return
     */
    @RequestMapping(value = "edit.html", method = RequestMethod.GET)
    public String edit() {
        return "edit";
    }


    @RequestMapping(value = "logout.html")
    public String logout(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "redirect:/login.html";
    }


    @RequestMapping(value = "edit.html", method = RequestMethod.POST)
    @ResponseBody
    public String edited() {
        return "edited";
    }


    /**
     * 登录操作
     *
     * @return
     */
    @RequestMapping(value = "login.html", method = RequestMethod.GET)
    public String login() {
        return "login";
    }


    @RequestMapping(value = "login.html", method = RequestMethod.POST)
    public String logined() {
        return "index";
    }

    /**
     * 查询操作
     *
     * @return
     */
    @RequestMapping(value = "search.html", method = RequestMethod.GET)
    public String search() {
        return "search";
    }


    @RequestMapping(value = "search.html", method = RequestMethod.POST)
    @ResponseBody
    public String searched() {
        return "";
    }

    /**
     * 修改密码
     *
     * @return
     */
    @RequestMapping(value = "changepassword.html", method = RequestMethod.GET)
    public String changePassword() {
        return "changePassword";
    }

    @RequestMapping(value = "changepassword.html", method = RequestMethod.POST)
    @ResponseBody
    public String changePassworded() {
        return "";
    }


    /**
     * 遗忘密码操作
     *
     * @return
     */
    @RequestMapping(value = "forgetpassword.html", method = RequestMethod.GET)
    public String forgetpassword() {
        return "forgetpassword";
    }

    @RequestMapping(value = "forgetpassword.html", method = RequestMethod.POST)
    @ResponseBody
    public String forgetpassworded() {
        return "";
    }

    /**
     * 离职操作
     *
     * @return
     */
    @RequestMapping(value = "quit.html", method = RequestMethod.GET)
    public String quit() {
        return "";
    }


    @RequestMapping(value = "quit.html", method = RequestMethod.POST)
    @ResponseBody
    public String quited() {
        return "";
    }


}

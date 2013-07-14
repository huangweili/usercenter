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
 * Time: 下午3:25
 */
@Controller
@RequestMapping("/admin")
public class GroupController {


    /**
     * 创建组
     *
     * @return
     */
    @RequestMapping(value = "/createGroup.html", method = RequestMethod.GET)
    public String createGroup(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "admin/createGroup";
    }

    @RequestMapping(value = "/createGroup.html", method = RequestMethod.POST)
    @ResponseBody
    public String createdGroup(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "";
    }

    /**
     * 编辑组
     *
     * @param request
     * @param response
     * @param model
     * @return
     */
    @RequestMapping(value = "/editGroup.html", method = RequestMethod.GET)
    public String editGroup(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "admin/editgroup";
    }

    @RequestMapping(value = "/editGroup.html", method = RequestMethod.POST)
    @ResponseBody
    public String editedGroup(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "";
    }

    /**
     * 删除组
     *
     * @param request
     * @param response
     * @param model
     * @return
     */
    @RequestMapping(value = "/deleteGroup.html", method = RequestMethod.POST)
    @ResponseBody
    public String deletedGroup(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "";
    }
}

package com.hwlcn.web.admin.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 组织单元操作
 * User: HuangWeili
 * Date: 13-6-23
 * Time: 下午3:39
 */
@Controller
@RequestMapping("/admin")
public class OuController {

    /**
     * 创建单元
     *
     * @param request
     * @param response
     * @param model
     * @return
     */
    @RequestMapping(value = "/createOu.html", method = RequestMethod.GET)
    public String createOu(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "admin/createOu";
    }


    @RequestMapping(value = "/createdOu.html", method = RequestMethod.POST)
    @ResponseBody
    public String createdOu(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "";
    }

    /**
     * 编辑单元
     *
     * @param request
     * @param response
     * @param model
     * @return
     */
    @RequestMapping(value = "/editOu.html", method = RequestMethod.GET)
    public String editOu(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "admin/editOu";
    }

    @RequestMapping(value = "/editOu.html", method = RequestMethod.POST)
    @ResponseBody
    public String editedOu(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "";
    }

    /**
     * 删除单元
     *
     * @param request
     * @param response
     * @param model
     * @return
     */
    @RequestMapping(value = "/deleteOu.html", method = RequestMethod.GET)
    public String deletedOu(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "";
    }
}


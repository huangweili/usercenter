package com.hwlcn.web.admin.controllers;

import com.hwlcn.web.services.IDomainService;
import org.springframework.beans.factory.annotation.Autowired;
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
 * Time: 下午4:49
 */
@Controller
public class DomainController {

    @Autowired
    private IDomainService domainService;


    /**
     * 添加域名
     *
     * @param request
     * @param response
     * @param model
     * @return
     */
    @RequestMapping(value = "addDomain.html", method = RequestMethod.GET)
    public String addDomain(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "addDomain";
    }

    @RequestMapping(value = "addDomain.html", method = RequestMethod.POST)
    @ResponseBody
    public String addedDomain(HttpServletRequest request, HttpServletResponse response, Model model) {

        return "";
    }

    /**
     * 编辑域名
     *
     * @param request
     * @param response
     * @param model
     * @return
     */

    @RequestMapping(value = "editDomain.html", method = RequestMethod.GET)
    public String editDomain(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "editDomain";
    }


    @RequestMapping(value = "editDomain.html", method = RequestMethod.POST)
    @ResponseBody
    public String editedDomain(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "";
    }


    /**
     * 删除域名
     *
     * @param request
     * @param response
     * @param model
     * @return
     */
    @RequestMapping(value = "deleteDomain.html", method = RequestMethod.POST)
    @ResponseBody
    public String deleteDomain(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "";
    }


    /**
     * 测试域名
     *
     * @param request
     * @param response
     * @param model
     * @return
     */
    @RequestMapping(value = "testDomain.html", method = RequestMethod.POST)
    @ResponseBody
    public String testDomain(HttpServletRequest request, HttpServletResponse response, Model model) {
        return "";
    }

}

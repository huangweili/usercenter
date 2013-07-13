package com.hwlcn.security.web.env;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;



public class EnvironmentLoaderListener extends EnvironmentLoader implements ServletContextListener {

    public void contextInitialized(ServletContextEvent sce) {
        initEnvironment(sce.getServletContext());
    }


    public void contextDestroyed(ServletContextEvent sce) {
        destroyEnvironment(sce.getServletContext());
    }
}

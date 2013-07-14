package com.hwlcn.security.spring;

import com.hwlcn.security.util.Destroyable;
import com.hwlcn.security.util.Initializable;
import org.springframework.beans.BeansException;
import org.springframework.beans.FatalBeanException;
import org.springframework.beans.factory.config.DestructionAwareBeanPostProcessor;
import org.springframework.core.PriorityOrdered;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;





public class LifecycleBeanPostProcessor implements DestructionAwareBeanPostProcessor, PriorityOrdered {

    private static final Logger log = LoggerFactory.getLogger(LifecycleBeanPostProcessor.class);


    private int order;

   public LifecycleBeanPostProcessor() {
        this(LOWEST_PRECEDENCE);
    }

    public LifecycleBeanPostProcessor(int order) {
        this.order = order;
    }

    public Object postProcessBeforeInitialization(Object object, String name) throws BeansException {
        if (object instanceof Initializable) {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Initializing bean [" + name + "]...");
                }
                ((Initializable) object).init();
            } catch (Exception e) {
                throw new FatalBeanException("Error initializing bean [" + name + "]", e);
            }
        }
        return object;
    }


    public Object postProcessAfterInitialization(Object object, String name) throws BeansException {
        return object;
    }


    public void postProcessBeforeDestruction(Object object, String name) throws BeansException {
        if (object instanceof Destroyable) {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Destroying bean [" + name + "]...");
                }

                ((Destroyable) object).destroy();
            } catch (Exception e) {
                throw new FatalBeanException("Error destroying bean [" + name + "]", e);
            }
        }
    }

    public int getOrder() {
        return order;
    }
}

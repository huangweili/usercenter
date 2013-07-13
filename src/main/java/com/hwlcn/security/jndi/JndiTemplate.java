/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.hwlcn.security.jndi;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Properties;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class JndiTemplate {

    private static final Logger log = LoggerFactory.getLogger(JndiTemplate.class);

    private Properties environment;


    public JndiTemplate() {
    }


    public JndiTemplate(Properties environment) {
        this.environment = environment;
    }


    public void setEnvironment(Properties environment) {
        this.environment = environment;
    }


    public Properties getEnvironment() {
        return this.environment;
    }


    public Object execute(JndiCallback contextCallback) throws NamingException {
        Context ctx = createInitialContext();
        try {
            return contextCallback.doInContext(ctx);
        }
        finally {
            try {
                ctx.close();
            } catch (NamingException ex) {
                log.debug("Could not close JNDI InitialContext", ex);
            }
        }
    }


    protected Context createInitialContext() throws NamingException {
        Properties env = getEnvironment();
        Hashtable icEnv = null;
        if (env != null) {
            icEnv = new Hashtable(env.size());
            for (Enumeration en = env.propertyNames(); en.hasMoreElements();) {
                String key = (String) en.nextElement();
                icEnv.put(key, env.getProperty(key));
            }
        }
        return new InitialContext(icEnv);
    }


    public Object lookup(final String name) throws NamingException {
        log.debug("Looking up JNDI object with name '{}'", name);
        return execute(new JndiCallback() {
            public Object doInContext(Context ctx) throws NamingException {
                Object located = ctx.lookup(name);
                if (located == null) {
                    throw new NameNotFoundException(
                            "JNDI object with [" + name + "] not found: JNDI implementation returned null");
                }
                return located;
            }
        });
    }


    public Object lookup(String name, Class requiredType) throws NamingException {
        Object jndiObject = lookup(name);
        if (requiredType != null && !requiredType.isInstance(jndiObject)) {
            String msg = "Jndi object acquired under name '" + name + "' is of type [" +
                    jndiObject.getClass().getName() + "] and not assignable to the required type [" +
                    requiredType.getName() + "].";
            throw new NamingException(msg);
        }
        return jndiObject;
    }


    public void bind(final String name, final Object object) throws NamingException {
        log.debug("Binding JNDI object with name '{}'", name);
        execute(new JndiCallback() {
            public Object doInContext(Context ctx) throws NamingException {
                ctx.bind(name, object);
                return null;
            }
        });
    }


    public void rebind(final String name, final Object object) throws NamingException {
        log.debug("Rebinding JNDI object with name '{}'", name);
        execute(new JndiCallback() {
            public Object doInContext(Context ctx) throws NamingException {
                ctx.rebind(name, object);
                return null;
            }
        });
    }


    public void unbind(final String name) throws NamingException {
        log.debug("Unbinding JNDI object with name '{}'", name);
        execute(new JndiCallback() {
            public Object doInContext(Context ctx) throws NamingException {
                ctx.unbind(name);
                return null;
            }
        });
    }

}

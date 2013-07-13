package com.hwlcn.security.realm.ldap;

import com.hwlcn.security.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class JndiLdapContextFactory implements LdapContextFactory {

    protected static final String SUN_CONNECTION_POOLING_PROPERTY = "com.sun.jndi.ldap.connect.pool";
    protected static final String DEFAULT_CONTEXT_FACTORY_CLASS_NAME = "com.sun.jndi.ldap.LdapCtxFactory";
    protected static final String SIMPLE_AUTHENTICATION_MECHANISM_NAME = "simple";
    protected static final String DEFAULT_REFERRAL = "follow";

    private static final Logger log = LoggerFactory.getLogger(JndiLdapContextFactory.class);

    private Map<String, Object> environment;
    private boolean poolingEnabled;
    private String systemPassword;
    private String systemUsername;

    public JndiLdapContextFactory() {
        this.environment = new HashMap<String, Object>();
        setContextFactoryClassName(DEFAULT_CONTEXT_FACTORY_CLASS_NAME);
        setReferral(DEFAULT_REFERRAL);
        poolingEnabled = true;
    }

    public void setAuthenticationMechanism(String authenticationMechanism) {
        setEnvironmentProperty(Context.SECURITY_AUTHENTICATION, authenticationMechanism);
    }

    public String getAuthenticationMechanism() {
        return (String) getEnvironmentProperty(Context.SECURITY_AUTHENTICATION);
    }

    public void setContextFactoryClassName(String contextFactoryClassName) {
        setEnvironmentProperty(Context.INITIAL_CONTEXT_FACTORY, contextFactoryClassName);
    }

    public String getContextFactoryClassName() {
        return (String) getEnvironmentProperty(Context.INITIAL_CONTEXT_FACTORY);
    }

    public Map getEnvironment() {
        return this.environment;
    }

    @SuppressWarnings({"unchecked"})
    public void setEnvironment(Map env) {
        this.environment = env;
    }

    private Object getEnvironmentProperty(String name) {
        return this.environment.get(name);
    }

    private void setEnvironmentProperty(String name, String value) {
        if (StringUtils.hasText(value)) {
            this.environment.put(name, value);
        } else {
            this.environment.remove(name);
        }
    }

    public boolean isPoolingEnabled() {
        return poolingEnabled;
    }

    public void setPoolingEnabled(boolean poolingEnabled) {
        this.poolingEnabled = poolingEnabled;
    }

    public void setReferral(String referral) {
        setEnvironmentProperty(Context.REFERRAL, referral);
    }

    public String getReferral() {
        return (String) getEnvironmentProperty(Context.REFERRAL);
    }

    public void setUrl(String url) {
        setEnvironmentProperty(Context.PROVIDER_URL, url);
    }

    public String getUrl() {
        return (String) getEnvironmentProperty(Context.PROVIDER_URL);
    }

    public void setSystemPassword(String systemPassword) {
        this.systemPassword = systemPassword;
    }

    public String getSystemPassword() {
        return this.systemPassword;
    }

    public void setSystemUsername(String systemUsername) {
        this.systemUsername = systemUsername;
    }

    public String getSystemUsername() {
        return systemUsername;
    }

     public LdapContext getSystemLdapContext() throws NamingException {
        return getLdapContext((Object) getSystemUsername(), getSystemPassword());
    }


    protected boolean isPoolingConnections(Object principal) {
        return isPoolingEnabled() && principal != null && principal.equals(getSystemUsername());
    }

    public LdapContext getLdapContext(Object principal, Object credentials) throws NamingException,
            IllegalStateException {

        String url = getUrl();
        if (url == null) {
            throw new IllegalStateException("An LDAP URL must be specified of the form ldap://<hostname>:<port>");
        }

       Hashtable<String, Object> env = new Hashtable<String, Object>(this.environment);

        Object authcMech = getAuthenticationMechanism();
        if (authcMech == null && (principal != null || credentials != null)) {
            env.put(Context.SECURITY_AUTHENTICATION, SIMPLE_AUTHENTICATION_MECHANISM_NAME);
        }
        if (principal != null) {
            env.put(Context.SECURITY_PRINCIPAL, principal);
        }
        if (credentials != null) {
            env.put(Context.SECURITY_CREDENTIALS, credentials);
        }

        boolean pooling = isPoolingConnections(principal);
        if (pooling) {
            env.put(SUN_CONNECTION_POOLING_PROPERTY, "true");
        }

        if (log.isDebugEnabled()) {
            log.debug("Initializing LDAP context using URL [{}] and principal [{}] with pooling {}",
                    new Object[]{url, principal, (pooling ? "enabled" : "disabled")});
        }

        return createLdapContext(env);
    }

    protected LdapContext createLdapContext(Hashtable env) throws NamingException {
        return new InitialLdapContext(env, null);
    }

}

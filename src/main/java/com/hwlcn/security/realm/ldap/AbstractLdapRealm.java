
package com.hwlcn.security.realm.ldap;

import com.hwlcn.security.authc.AuthenticationException;
import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.authz.AuthorizationException;
import com.hwlcn.security.authz.AuthorizationInfo;
import com.hwlcn.security.realm.AuthorizingRealm;
import com.hwlcn.security.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.NamingException;

public abstract class AbstractLdapRealm extends AuthorizingRealm {



    private static final Logger log = LoggerFactory.getLogger(AbstractLdapRealm.class);


    protected String principalSuffix = null;

    protected String searchBase = null;

    protected String url = null;

    protected String systemUsername = null;

    protected String systemPassword = null;

    private LdapContextFactory ldapContextFactory = null;


    public void setPrincipalSuffix(String principalSuffix) {
        this.principalSuffix = principalSuffix;
    }


    public void setSearchBase(String searchBase) {
        this.searchBase = searchBase;
    }


    public void setUrl(String url) {
        this.url = url;
    }


    public void setSystemUsername(String systemUsername) {
        this.systemUsername = systemUsername;
    }



    public void setSystemPassword(String systemPassword) {
        this.systemPassword = systemPassword;
    }



    public void setLdapContextFactory(LdapContextFactory ldapContextFactory) {
        this.ldapContextFactory = ldapContextFactory;
    }


    protected void onInit() {
        super.onInit();
        ensureContextFactory();
    }

    private LdapContextFactory ensureContextFactory() {
        if (this.ldapContextFactory == null) {

            if (log.isDebugEnabled()) {
                log.debug("No LdapContextFactory specified - creating a default instance.");
            }

            JndiLdapContextFactory defaultFactory = new JndiLdapContextFactory();
            defaultFactory.setUrl(this.url);
            defaultFactory.setSystemUsername(this.systemUsername);
            defaultFactory.setSystemPassword(this.systemPassword);

            this.ldapContextFactory = defaultFactory;
        }
        return this.ldapContextFactory;
    }


    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        AuthenticationInfo info;
        try {
            info = queryForAuthenticationInfo(token, ensureContextFactory());
        } catch (javax.naming.AuthenticationException e) {
            throw new AuthenticationException("LDAP authentication failed.", e);
        } catch (NamingException e) {
            String msg = "LDAP naming error while attempting to authenticate user.";
            throw new AuthenticationException(msg, e);
        }

        return info;
    }


    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        AuthorizationInfo info;
        try {
            info = queryForAuthorizationInfo(principals, ensureContextFactory());
        } catch (NamingException e) {
            String msg = "LDAP naming error while attempting to retrieve authorization for user [" + principals + "].";
            throw new AuthorizationException(msg, e);
        }

        return info;
    }

    protected abstract AuthenticationInfo queryForAuthenticationInfo(AuthenticationToken token, LdapContextFactory ldapContextFactory) throws NamingException;

    protected abstract AuthorizationInfo queryForAuthorizationInfo(PrincipalCollection principal, LdapContextFactory ldapContextFactory) throws NamingException;

}

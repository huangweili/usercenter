package com.hwlcn.security.authc;

import com.hwlcn.security.subject.MutablePrincipalCollection;
import com.hwlcn.security.subject.SimplePrincipalCollection;
import com.hwlcn.security.util.ByteSource;
import com.hwlcn.security.subject.PrincipalCollection;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;



public class SimpleAuthenticationInfo implements MergableAuthenticationInfo, SaltedAuthenticationInfo {

    protected PrincipalCollection principals;

    protected Object credentials;

    protected ByteSource credentialsSalt;

    public SimpleAuthenticationInfo() {
    }

    public SimpleAuthenticationInfo(Object principal, Object credentials, String realmName) {
        this.principals = new SimplePrincipalCollection(principal, realmName);
        this.credentials = credentials;
    }


    public SimpleAuthenticationInfo(Object principal, Object hashedCredentials, ByteSource credentialsSalt, String realmName) {
        this.principals = new SimplePrincipalCollection(principal, realmName);
        this.credentials = hashedCredentials;
        this.credentialsSalt = credentialsSalt;
    }

    public SimpleAuthenticationInfo(PrincipalCollection principals, Object credentials) {
        this.principals = new SimplePrincipalCollection(principals);
        this.credentials = credentials;
    }

    public SimpleAuthenticationInfo(PrincipalCollection principals, Object hashedCredentials, ByteSource credentialsSalt) {
        this.principals = new SimplePrincipalCollection(principals);
        this.credentials = hashedCredentials;
        this.credentialsSalt = credentialsSalt;
    }


    public PrincipalCollection getPrincipals() {
        return principals;
    }

    public void setPrincipals(PrincipalCollection principals) {
        this.principals = principals;
    }

    public Object getCredentials() {
        return credentials;
    }

    public void setCredentials(Object credentials) {
        this.credentials = credentials;
    }

    public ByteSource getCredentialsSalt() {
        return credentialsSalt;
    }

    public void setCredentialsSalt(ByteSource salt) {
        this.credentialsSalt = salt;
    }

    @SuppressWarnings("unchecked")
    public void merge(AuthenticationInfo info) {
        if (info == null || info.getPrincipals() == null || info.getPrincipals().isEmpty()) {
            return;
        }

        if (this.principals == null) {
            this.principals = info.getPrincipals();
        } else {
            if (!(this.principals instanceof MutablePrincipalCollection)) {
                this.principals = new SimplePrincipalCollection(this.principals);
            }
            ((MutablePrincipalCollection) this.principals).addAll(info.getPrincipals());
        }

        if (this.credentialsSalt == null && info instanceof SaltedAuthenticationInfo) {
            this.credentialsSalt = ((SaltedAuthenticationInfo) info).getCredentialsSalt();
        }

        Object thisCredentials = getCredentials();
        Object otherCredentials = info.getCredentials();

        if (otherCredentials == null) {
            return;
        }

        if (thisCredentials == null) {
            this.credentials = otherCredentials;
            return;
        }

        if (!(thisCredentials instanceof Collection)) {
            Set newSet = new HashSet();
            newSet.add(thisCredentials);
            setCredentials(newSet);
        }

        Collection credentialCollection = (Collection) getCredentials();
        if (otherCredentials instanceof Collection) {
            credentialCollection.addAll((Collection) otherCredentials);
        } else {
            credentialCollection.add(otherCredentials);
        }
    }

    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SimpleAuthenticationInfo)) return false;

        SimpleAuthenticationInfo that = (SimpleAuthenticationInfo) o;

        if (principals != null ? !principals.equals(that.principals) : that.principals != null) return false;

        return true;
    }

    public int hashCode() {
        return (principals != null ? principals.hashCode() : 0);
    }

    public String toString() {
        return principals.toString();
    }

}

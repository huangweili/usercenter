package com.hwlcn.security.subject;

import com.hwlcn.security.authc.AuthenticationException;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.authz.AuthorizationException;
import com.hwlcn.security.authz.Permission;
import com.hwlcn.security.session.Session;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;


public interface Subject {


    Object getPrincipal();

    PrincipalCollection getPrincipals();


    boolean isPermitted(String permission);

    boolean isPermitted(Permission permission);

    boolean[] isPermitted(String... permissions);

    boolean[] isPermitted(List<Permission> permissions);

    boolean isPermittedAll(String... permissions);

    boolean isPermittedAll(Collection<Permission> permissions);


    void checkPermission(String permission) throws AuthorizationException;

    void checkPermission(Permission permission) throws AuthorizationException;

    void checkPermissions(String... permissions) throws AuthorizationException;

    void checkPermissions(Collection<Permission> permissions) throws AuthorizationException;

    boolean hasRole(String roleIdentifier);

    boolean[] hasRoles(List<String> roleIdentifiers);

    boolean hasAllRoles(Collection<String> roleIdentifiers);

    void checkRole(String roleIdentifier) throws AuthorizationException;

    void checkRoles(Collection<String> roleIdentifiers) throws AuthorizationException;


    void checkRoles(String... roleIdentifiers) throws AuthorizationException;

    void login(AuthenticationToken token) throws AuthenticationException;

    boolean isAuthenticated();

    boolean isRemembered();

    Session getSession();

    Session getSession(boolean create);

    void logout();

    <V> V execute(Callable<V> callable) throws ExecutionException;

    void execute(Runnable runnable);

    <V> Callable<V> associateWith(Callable<V> callable);

    Runnable associateWith(Runnable runnable);

    //模拟身份
    void runAs(PrincipalCollection principals) throws NullPointerException, IllegalStateException;


    boolean isRunAs();


    //获取模拟身份前的数据
    PrincipalCollection getPreviousPrincipals();


    //回复原来的身份
    PrincipalCollection releaseRunAs();


}

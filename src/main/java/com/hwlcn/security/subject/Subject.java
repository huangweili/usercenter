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

    /**
     * Returns this Subject's application-wide uniquely identifying principal, or {@code null} if this
     * Subject is anonymous because it doesn't yet have any associated account data (for example,
     * if they haven't logged in).
     * <p/>
     * The term <em>principal</em> is just a fancy security term for any identifying attribute(s) of an application
     * user, such as a username, or user id, or public key, or anything else you might use in your application to
     * identify a user.
     * <h4>Uniqueness</h4>
     * Although given names and family names (first/last) are technically considered principals as well,
     * Shiro expects the object returned from this method to be an identifying attribute unique across
     * your entire application.
     * <p/>
     * This implies that things like given names and family names are usually poor
     * candidates as return values since they are rarely guaranteed to be unique;  Things often used for this value:
     * <ul>
     * <li>A {@code long} RDBMS surrogate primary key</li>
     * <li>An application-unique username</li>
     * <li>A {@link java.util.UUID UUID}</li>
     * <li>An LDAP Unique ID</li>
     * </ul>
     * or any other similar suitable unique mechanism valuable to your application.
     * <p/>
     * Most implementations will simply return
     * <code>{@link #getPrincipals()}.{@link PrincipalCollection#getPrimaryPrincipal() getPrimaryPrincipal()}</code>
     *
     * @return this Subject's application-specific unique identity.
     * @see PrincipalCollection#getPrimaryPrincipal()
     */
    Object getPrincipal();

    /**
     * Returns this Subject's principals (identifying attributes) in the form of a {@code PrincipalCollection} or
     * {@code null} if this Subject is anonymous because it doesn't yet have any associated account data (for example,
     * if they haven't logged in).
     * <p/>
     * The word &quot;principals&quot; is nothing more than a fancy security term for identifying attributes associated
     * with a Subject, aka, application user.  For example, user id, a surname (family/last name), given (first) name,
     * social security number, nickname, username, etc, are all examples of a principal.
     *
     * @return all of this Subject's principals (identifying attributes).
     * @see #getPrincipal()
     * @see PrincipalCollection#getPrimaryPrincipal()
     */
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

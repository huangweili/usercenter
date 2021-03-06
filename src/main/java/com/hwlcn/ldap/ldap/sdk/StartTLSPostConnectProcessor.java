package com.hwlcn.ldap.ldap.sdk;



import javax.net.ssl.SSLContext;

import com.hwlcn.ldap.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides an implementation of a post-connect processor that can
 * be used to perform StartTLS negotiation on an LDAP connection that is
 * intended to be used in a connection pool.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the StartTLS post-connect
 * processor to create an LDAP connection pool whose connections are secured
 * using StartTLS:
 * <PRE>
 *   SSLUtil sslUtil =
 *        new SSLUtil(new TrustStoreTrustManager("/my/trust/store/file"));
 *   SSLContext sslContext = sslUtil.createSSLContext();
 *
 *   LDAPConnection connection = new LDAPConnection("server.example.com", 389);
 *   ExtendedResult startTLSResult = connection.processExtendedOperation(
 *        new StartTLSExtendedRequest(sslContext);
 *   BindResult bindResult = connection.bind(
 *        "uid=john.doe,ou=People,dc=example,dc=com", "password");
 *
 *   StartTLSPostConnectProcessor startTLSProcessor =
 *        new StartTLSPostConnectProcessor(sslContext);
 *   LDAPConnectionPool pool =
 *        new LDAPConnectionPool(connection, 1, 10, startTLSProcessor);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class StartTLSPostConnectProcessor
       implements PostConnectProcessor
{
  private final SSLContext sslContext;


  public StartTLSPostConnectProcessor(final SSLContext sslContext)
  {
    ensureNotNull(sslContext);

    this.sslContext = sslContext;
  }


  public void processPreAuthenticatedConnection(final LDAPConnection connection)
         throws LDAPException
  {
    final ExtendedResult r = connection.processExtendedOperation(
         new StartTLSExtendedRequest(sslContext));
    if (! r.getResultCode().equals(ResultCode.SUCCESS))
    {
      throw new LDAPException(r);
    }
  }



  public void processPostAuthenticatedConnection(
                   final LDAPConnection connection)
         throws LDAPException
  {
  }
}

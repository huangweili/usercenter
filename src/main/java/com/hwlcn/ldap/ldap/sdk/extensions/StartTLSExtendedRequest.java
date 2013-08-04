
package com.hwlcn.ldap.ldap.sdk.extensions;



import javax.net.ssl.SSLContext;

import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.ExtendedRequest;
import com.hwlcn.ldap.ldap.sdk.ExtendedResult;
import com.hwlcn.ldap.ldap.sdk.InternalSDKHelper;
import com.hwlcn.ldap.ldap.sdk.LDAPConnection;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.ssl.SSLUtil;

import static com.hwlcn.ldap.ldap.sdk.extensions.ExtOpMessages.*;
import static com.hwlcn.ldap.util.Debug.*;



/**
 * This class provides an implementation of the LDAP StartTLS extended request
 * as defined in <A HREF="http://www.ietf.org/rfc/rfc4511.txt">RFC 4511</A>
 * section 4.14.  It may be used to establish a secure communication channel
 * over an otherwise unencrypted connection.
 * <BR><BR>
 * Note that when using the StartTLS extended operation, you should establish
 * a connection to the server's unencrypted LDAP port rather than its secure
 * port.  Then, you can use the StartTLS extended request in order to secure
 * that connection.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example attempts to use the StartTLS extended request in order
 * to secure communication on a previously insecure connection.  In this case,
 * it will use the {@link com.hwlcn.ldap.util.ssl.SSLUtil} class in conjunction
 * with the {@link com.hwlcn.ldap.util.ssl.TrustAllTrustManager} class to
 * simplify the process of performing the SSL negotiation by blindly trusting
 * whatever certificate the server might happen to present.  In real-world
 * applications, if stronger verification is required then it is recommended
 * that you use an {@link javax.net.ssl.SSLContext} that is configured to perform an
 * appropriate level of validation.
 * <PRE>
 *   SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
 *   SSLContext sslContext = sslUtil.createSSLContext();
 *   ExtendedResult extendedResult = connection.processExtendedOperation(
 *        new StartTLSExtendedRequest(sslContext));
 *
 *   // NOTE:  The processExtendedOperation method will only throw an exception
 *   // if a problem occurs while trying to send the request or read the
 *   // response.  It will not throw an exception because of a non-success
 *   // response.
 *
 *   if (extendedResult.getResultCode() == ResultCode.SUCCESS)
 *   {
 *     System.out.println("Communication with the server is now secure.");
 *   }
 *   else
 *   {
 *     System.err.println("An error occurred while attempting to perform " +
 *          "StartTLS negotiation.  The connection can no longer be used.");
 *     connection.close();
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class StartTLSExtendedRequest
       extends ExtendedRequest
{

  public static final String STARTTLS_REQUEST_OID = "1.3.6.1.4.1.1466.20037";


  private static final long serialVersionUID = -3234194603452821233L;

  private final SSLContext sslContext;


  public StartTLSExtendedRequest()
         throws LDAPException
  {
    this(null, null);
  }


  public StartTLSExtendedRequest(final Control[] controls)
         throws LDAPException
  {
    this(null, controls);
  }



  public StartTLSExtendedRequest(final SSLContext sslContext)
         throws LDAPException
  {
    this(sslContext, null);
  }

  public StartTLSExtendedRequest(final SSLContext sslContext,
                                 final Control[] controls)
         throws LDAPException
  {
    super(STARTTLS_REQUEST_OID, controls);

    if (sslContext == null)
    {
      try
      {
        this.sslContext =
             SSLContext.getInstance(SSLUtil.getDefaultSSLProtocol());
        this.sslContext.init(null, null, null);
      }
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_STARTTLS_REQUEST_CANNOT_CREATE_DEFAULT_CONTEXT.get(e), e);
      }
    }
    else
    {
      this.sslContext = sslContext;
    }
  }


  public StartTLSExtendedRequest(final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    this(extendedRequest.getControls());

    if (extendedRequest.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_STARTTLS_REQUEST_HAS_VALUE.get());
    }
  }




  @Override()
  public ExtendedResult process(final LDAPConnection connection,
                                final int depth)
         throws LDAPException
  {
    InternalSDKHelper.setSoTimeout(connection, 50);

    final ExtendedResult result = super.process(connection, depth);
    if (result.getResultCode() == ResultCode.SUCCESS)
    {
      InternalSDKHelper.convertToTLS(connection, sslContext);
    }

    return result;
  }



  @Override()
  public StartTLSExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }


  @Override()
  public StartTLSExtendedRequest duplicate(final Control[] controls)
  {
    try
    {
      final StartTLSExtendedRequest r =
           new StartTLSExtendedRequest(sslContext, controls);
      r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
      return r;
    }
    catch (Exception e)
    {
      debugException(e);
      return null;
    }
  }



  @Override()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_START_TLS.get();
  }



  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("StartTLSExtendedRequest(");

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append("controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}

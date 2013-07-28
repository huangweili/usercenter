package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



/**
 * This class provides a SASL ANONYMOUS bind request implementation as described
 * in <A HREF="http://www.ietf.org/rfc/rfc4505.txt">RFC 4505</A>.  Binding with
 * The ANONYMOUS SASL mechanism is essentially equivalent to using an anonymous
 * simple bind (i.e., a simple bind with an empty password), although the SASL
 * ANONYMOUS mechanism does provide the ability to include additional trace
 * information with the request that may be logged or otherwise handled by
 * the server.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing an ANONYMOUS
 * bind, including a trace string of "Hello, world!" against a directory server:
 * <PRE>
 *   ANONYMOUSBindRequest bindRequest =
 *        new ANONYMOUSBindRequest("Hello, world!");
 *   try
 *   {
 *     BindResult bindResult = connection.bind(bindRequest);
 *     // If we get here, then the bind was successful.
 *   }
 *   catch (LDAPException le)
 *   {
 *     // The bind failed for some reason.
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ANONYMOUSBindRequest
       extends SASLBindRequest
{

  public static final String ANONYMOUS_MECHANISM_NAME = "ANONYMOUS";



  private static final long serialVersionUID = 4259102841471750866L;



  private final String traceString;

  public ANONYMOUSBindRequest()
  {
    this(null, NO_CONTROLS);
  }




  public ANONYMOUSBindRequest(final String traceString)
  {
    this(traceString, NO_CONTROLS);
  }



  public ANONYMOUSBindRequest(final Control... controls)
  {
    this(null, controls);
  }




  public ANONYMOUSBindRequest(final String traceString,
                              final Control... controls)
  {
    super(controls);

    this.traceString = traceString;
  }



  @Override()
  public String getSASLMechanismName()
  {
    return ANONYMOUS_MECHANISM_NAME;
  }



  public String getTraceString()
  {
    return traceString;
  }



  @Override()
  protected BindResult process(final LDAPConnection connection, final int depth)
            throws LDAPException
  {
    ASN1OctetString credentials = null;
    if ((traceString == null) || (traceString.length() == 0))
    {
      credentials = new ASN1OctetString(traceString);
    }

    return sendBindRequest(connection, null, credentials, getControls(),
                           getResponseTimeoutMillis(connection));
  }


  @Override()
  public ANONYMOUSBindRequest getRebindRequest(final String host,
                                               final int port)
  {
    return new ANONYMOUSBindRequest(traceString, getControls());
  }



  @Override()
  public ANONYMOUSBindRequest duplicate()
  {
    return duplicate(getControls());
  }




  @Override()
  public ANONYMOUSBindRequest duplicate(final Control[] controls)
  {
    final ANONYMOUSBindRequest bindRequest =
         new ANONYMOUSBindRequest(traceString, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ANONYMOUSBindRequest(");
    if (traceString != null)
    {
      buffer.append(", trace='");
      buffer.append(traceString);
      buffer.append('\'');
    }

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
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

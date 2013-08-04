package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



/**
 * This class provides a SASL EXTERNAL bind request implementation as described
 * in <A HREF="http://www.ietf.org/rfc/rfc4422.txt">RFC 4422</A>.  The
 * EXTERNAL mechanism is used to authenticate using information that is
 * available outside of the LDAP layer (e.g., a certificate presented by the
 * client during SSL or StartTLS negotiation).
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing an EXTERNAL
 * bind against a directory server:
 * <PRE>
 *   try
 *   {
 *     BindResult bindResult = connection.bind(new EXTERNALBindRequest());
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
public final class EXTERNALBindRequest
       extends SASLBindRequest
{
  public static final String EXTERNAL_MECHANISM_NAME = "EXTERNAL";

  private static final long serialVersionUID = 7520760039662616663L;

  private int messageID = -1;

  private final String authzID;


  public EXTERNALBindRequest()
  {
    this(null, StaticUtils.NO_CONTROLS);
  }

  public EXTERNALBindRequest(final String authzID)
  {
    this(authzID, StaticUtils.NO_CONTROLS);
  }

  public EXTERNALBindRequest(final Control... controls)
  {
    this(null, controls);
  }

  public EXTERNALBindRequest(final String authzID, final Control... controls)
  {
    super(controls);

    this.authzID = authzID;
  }

  public String getAuthorizationID()
  {
    return authzID;
  }

  @Override()
  public String getSASLMechanismName()
  {
    return EXTERNAL_MECHANISM_NAME;
  }



  @Override()
  protected BindResult process(final LDAPConnection connection, final int depth)
            throws LDAPException
  {
    messageID = connection.nextMessageID();

    final ASN1OctetString creds;
    if (authzID == null)
    {
      creds = null;
    }
    else
    {
      creds = new ASN1OctetString(authzID);
    }

    return sendBindRequest(connection, "", creds, getControls(),
                           getResponseTimeoutMillis(connection));
  }


  @Override()
  public EXTERNALBindRequest getRebindRequest(final String host, final int port)
  {
    return new EXTERNALBindRequest(authzID, getControls());
  }

  @Override()
  public int getLastMessageID()
  {
    return messageID;
  }

  @Override()
  public EXTERNALBindRequest duplicate()
  {
    return duplicate(getControls());
  }

  @Override()
  public EXTERNALBindRequest duplicate(final Control[] controls)
  {
    final EXTERNALBindRequest bindRequest =
         new EXTERNALBindRequest(authzID, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("EXTERNALBindRequest(");

    boolean added = false;
    if (authzID != null)
    {
      buffer.append("authzID='");
      buffer.append(authzID);
      buffer.append('\'');
      added = true;
    }

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      if (added)
      {
        buffer.append(", ");
      }

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

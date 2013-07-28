package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides a SASL PLAIN bind request implementation as described in
 * <A HREF="http://www.ietf.org/rfc/rfc4616.txt">RFC 4616</A>.  The SASL PLAIN
 * mechanism allows the client to authenticate with an authentication ID and
 * password, and optionally allows the client to provide an authorization ID for
 * use in performing subsequent operations.
 * <BR><BR>
 * Elements included in a PLAIN bind request include:
 * <UL>
 *   <LI>Authentication ID -- A string which identifies the user that is
 *       attempting to authenticate.  It should be an "authzId" value as
 *       described in section 5.2.1.8 of
 *       <A HREF="http://www.ietf.org/rfc/rfc4513.txt">RFC 4513</A>.  That is,
 *       it should be either "dn:" followed by the distinguished name of the
 *       target user, or "u:" followed by the username.  If the "u:" form is
 *       used, then the mechanism used to resolve the provided username to an
 *       entry may vary from server to server.</LI>
 *   <LI>Authorization ID -- An optional string which specifies an alternate
 *       authorization identity that should be used for subsequent operations
 *       requested on the connection.  Like the authentication ID, the
 *       authorization ID should use the "authzId" syntax.</LI>
 *   <LI>Password -- The clear-text password for the target user.</LI>
 * </UL>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing a PLAIN bind
 * against a directory server with a username of "john.doe" and a password of
 * "password":
 * <PRE>
 *   PLAINBindRequest bindRequest =
 *        new PLAINBindRequest("u:john.doe", "password");
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
public final class PLAINBindRequest
       extends SASLBindRequest
{
  public static final String PLAIN_MECHANISM_NAME = "PLAIN";

    private static final long serialVersionUID = -5186140710317748684L;

private final ASN1OctetString password;
  private final String authenticationID;

  private final String authorizationID;


  public PLAINBindRequest(final String authenticationID, final String password)
  {
    this(authenticationID, null, new ASN1OctetString(password), NO_CONTROLS);

    ensureNotNull(password);
  }



  public PLAINBindRequest(final String authenticationID, final byte[] password)
  {
    this(authenticationID, null, new ASN1OctetString(password), NO_CONTROLS);

    ensureNotNull(password);
  }


  public PLAINBindRequest(final String authenticationID,
                          final ASN1OctetString password)
  {
    this(authenticationID, null, password, NO_CONTROLS);
  }


  public PLAINBindRequest(final String authenticationID,
                          final String authorizationID, final String password)
  {
    this(authenticationID, authorizationID, new ASN1OctetString(password),
         NO_CONTROLS);

    ensureNotNull(password);
  }


  public PLAINBindRequest(final String authenticationID,
                          final String authorizationID, final byte[] password)
  {
    this(authenticationID, authorizationID, new ASN1OctetString(password),
         NO_CONTROLS);

    ensureNotNull(password);
  }


  public PLAINBindRequest(final String authenticationID,
                          final String authorizationID,
                          final ASN1OctetString password)
  {
    this(authenticationID, authorizationID, password, NO_CONTROLS);
  }


  public PLAINBindRequest(final String authenticationID, final String password,
                          final Control... controls)
  {
    this(authenticationID, null, new ASN1OctetString(password), controls);

    ensureNotNull(password);
  }



  public PLAINBindRequest(final String authenticationID, final byte[] password,
                          final Control... controls)
  {
    this(authenticationID, null, new ASN1OctetString(password), controls);

    ensureNotNull(password);
  }


  public PLAINBindRequest(final String authenticationID,
                          final ASN1OctetString password,
                          final Control... controls)
  {
    this(authenticationID, null, password, controls);
  }


  public PLAINBindRequest(final String authenticationID,
                          final String authorizationID, final String password,
                          final Control... controls)
  {
    this(authenticationID, authorizationID, new ASN1OctetString(password),
         controls);

    ensureNotNull(password);
  }


  public PLAINBindRequest(final String authenticationID,
                          final String authorizationID, final byte[] password,
                          final Control... controls)
  {
    this(authenticationID, authorizationID, new ASN1OctetString(password),
         controls);

    ensureNotNull(password);
  }


  public PLAINBindRequest(final String authenticationID,
                          final String authorizationID,
                          final ASN1OctetString password,
                          final Control... controls)
  {
    super(controls);

    ensureNotNull(authenticationID, password);

    this.authenticationID = authenticationID;
    this.authorizationID  = authorizationID;
    this.password         = password;
  }


  @Override()
  public String getSASLMechanismName()
  {
    return PLAIN_MECHANISM_NAME;
  }

  public String getAuthenticationID()
  {
    return authenticationID;
  }


  public String getAuthorizationID()
  {
    return authorizationID;
  }


  public String getPasswordString()
  {
    return password.stringValue();
  }


  public byte[] getPasswordBytes()
  {
    return password.getValue();
  }



  @Override()
  protected BindResult process(final LDAPConnection connection, final int depth)
            throws LDAPException
  {

    final byte[] authZIDBytes  = getBytes(authorizationID);
    final byte[] authNIDBytes  = getBytes(authenticationID);
    final byte[] passwordBytes = password.getValue();
    final byte[] credBytes     = new byte[2 + authZIDBytes.length +
                                    authNIDBytes.length + passwordBytes.length];

    System.arraycopy(authZIDBytes, 0, credBytes, 0, authZIDBytes.length);

    int pos = authZIDBytes.length + 1;
    System.arraycopy(authNIDBytes, 0, credBytes, pos, authNIDBytes.length);

    pos += authNIDBytes.length + 1;
    System.arraycopy(passwordBytes, 0, credBytes, pos, passwordBytes.length);

    return sendBindRequest(connection, "", new ASN1OctetString(credBytes),
                           getControls(), getResponseTimeoutMillis(connection));
  }


  @Override()
  public PLAINBindRequest getRebindRequest(final String host, final int port)
  {
    return new PLAINBindRequest(authenticationID, authorizationID, password,
                                getControls());
  }

  @Override()
  public PLAINBindRequest duplicate()
  {
    return duplicate(getControls());
  }


  @Override()
  public PLAINBindRequest duplicate(final Control[] controls)
  {
    final PLAINBindRequest bindRequest = new PLAINBindRequest(authenticationID,
         authorizationID, password, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("PLAINBindRequest(authenticationID='");
    buffer.append(authenticationID);
    buffer.append('\'');

    if (authorizationID != null)
    {
      buffer.append(", authorizationID='");
      buffer.append(authorizationID);
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

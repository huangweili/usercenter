package com.hwlcn.ldap.ldap.sdk;



import java.util.HashMap;
import java.util.logging.Level;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.util.DebugType;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides a SASL DIGEST-MD5 bind request implementation as
 * described in <A HREF="http://www.ietf.org/rfc/rfc2831.txt">RFC 2831</A>.  The
 * DIGEST-MD5 mechanism can be used to authenticate over an insecure channel
 * without exposing the credentials (although it requires that the server have
 * access to the clear-text password).  It is similar to CRAM-MD5, but provides
 * better security by combining random data from both the client and the server,
 * and allows for greater security and functionality, including the ability to
 * specify an alternate authorization identity and the ability to use data
 * integrity or confidentiality protection.  At present, however, this
 * implementation may only be used for authentication, as it does not yet
 * support integrity or confidentiality.
 * <BR><BR>
 * Elements included in a DIGEST-MD5 bind request include:
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
 *   <LI>Realm -- An optional string which specifies the realm into which the
 *       user should authenticate.</LI>
 *   <LI>Password -- The clear-text password for the target user.</LI>
 * </UL>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing a DIGEST-MD5
 * bind against a directory server with a username of "john.doe" and a password
 * of "password":
 * <PRE>
 *   DIGESTMD5BindRequest bindRequest =
 *        new DIGESTMD5BindRequest("u:john.doe", "password");
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
public final class DIGESTMD5BindRequest
       extends SASLBindRequest
       implements CallbackHandler
{

  public static final String DIGESTMD5_MECHANISM_NAME = "DIGEST-MD5";



  private static final long serialVersionUID = 867592367640540593L;



  private final ASN1OctetString password;

  private int messageID = -1;

  private final String authenticationID;

  private final String authorizationID;

  private final String realm;




  public DIGESTMD5BindRequest(final String authenticationID,
                              final String password)
  {
    this(authenticationID, null, new ASN1OctetString(password), null,
         NO_CONTROLS);

    ensureNotNull(password);
  }

  public DIGESTMD5BindRequest(final String authenticationID,
                              final byte[] password)
  {
    this(authenticationID, null, new ASN1OctetString(password), null,
         NO_CONTROLS);

    ensureNotNull(password);
  }




  public DIGESTMD5BindRequest(final String authenticationID,
                              final ASN1OctetString password)
  {
    this(authenticationID, null, password, null, NO_CONTROLS);
  }




  public DIGESTMD5BindRequest(final String authenticationID,
                              final String authorizationID,
                              final String password, final String realm,
                              final Control... controls)
  {
    this(authenticationID, authorizationID, new ASN1OctetString(password),
         realm, controls);

    ensureNotNull(password);
  }




  public DIGESTMD5BindRequest(final String authenticationID,
                              final String authorizationID,
                              final byte[] password, final String realm,
                              final Control... controls)
  {
    this(authenticationID, authorizationID, new ASN1OctetString(password),
         realm, controls);

    ensureNotNull(password);
  }



  public DIGESTMD5BindRequest(final String authenticationID,
                              final String authorizationID,
                              final ASN1OctetString password,
                              final String realm, final Control... controls)
  {
    super(controls);

    ensureNotNull(authenticationID, password);

    this.authenticationID = authenticationID;
    this.authorizationID  = authorizationID;
    this.password         = password;
    this.realm            = realm;
  }




  @Override()
  public String getSASLMechanismName()
  {
    return DIGESTMD5_MECHANISM_NAME;
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



  public String getRealm()
  {
    return realm;
  }



  @Override()
  protected BindResult process(final LDAPConnection connection, final int depth)
            throws LDAPException
  {
    final String[] mechanisms = { DIGESTMD5_MECHANISM_NAME };

    final HashMap<String,Object> saslProperties = new HashMap<String,Object>();
    saslProperties.put(Sasl.QOP, "auth");
    saslProperties.put(Sasl.SERVER_AUTH, "false");

    final SaslClient saslClient;
    try
    {
      saslClient = Sasl.createSaslClient(mechanisms, authorizationID, "ldap",
                                         connection.getConnectedAddress(),
                                         saslProperties, this);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_DIGESTMD5_CANNOT_CREATE_SASL_CLIENT.get(getExceptionMessage(e)),
           e);
    }

    final SASLHelper helper = new SASLHelper(this, connection,
         DIGESTMD5_MECHANISM_NAME, saslClient, getControls(),
         getResponseTimeoutMillis(connection));

    try
    {
      return helper.processSASLBind();
    }
    finally
    {
      messageID = helper.getMessageID();
    }
  }



  @Override()
  public DIGESTMD5BindRequest getRebindRequest(final String host,
                                               final int port)
  {
    return new DIGESTMD5BindRequest(authenticationID, authorizationID, password,
                                    realm, getControls());
  }


  @InternalUseOnly()
  public void handle(final Callback[] callbacks)
  {
    for (final Callback callback : callbacks)
    {
      if (callback instanceof NameCallback)
      {
        ((NameCallback) callback).setName(authenticationID);
      }
      else if (callback instanceof PasswordCallback)
      {
        ((PasswordCallback) callback).setPassword(
             password.stringValue().toCharArray());
      }
      else if (callback instanceof RealmCallback)
      {
        if (realm != null)
        {
          ((RealmCallback) callback).setText(realm);
        }
      }
      else if (callback instanceof RealmChoiceCallback)
      {
        if (realm != null)
        {
          final RealmChoiceCallback rcc = (RealmChoiceCallback) callback;
          final String[] choices = rcc.getChoices();
          for (int i=0; i < choices.length; i++)
          {
            if (choices[i].equals(realm))
            {
              rcc.setSelectedIndex(i);
              break;
            }
          }
        }
      }
      else
      {
        if (debugEnabled(DebugType.LDAP))
        {
          debug(Level.WARNING, DebugType.LDAP,
                "Unexpected DIGEST-MD5 SASL callback of type " +
                callback.getClass().getName());
        }
      }
    }
  }



  @Override()
  public int getLastMessageID()
  {
    return messageID;
  }



  @Override()
  public DIGESTMD5BindRequest duplicate()
  {
    return duplicate(getControls());
  }


  @Override()
  public DIGESTMD5BindRequest duplicate(final Control[] controls)
  {
    final DIGESTMD5BindRequest bindRequest =
         new DIGESTMD5BindRequest(authenticationID, authorizationID, password,
              realm, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("DIGESTMD5BindRequest(authenticationID='");
    buffer.append(authenticationID);
    buffer.append('\'');

    if (authorizationID != null)
    {
      buffer.append(", authorizationID='");
      buffer.append(authorizationID);
      buffer.append('\'');
    }

    if (realm != null)
    {
      buffer.append(", realm='");
      buffer.append(realm);
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

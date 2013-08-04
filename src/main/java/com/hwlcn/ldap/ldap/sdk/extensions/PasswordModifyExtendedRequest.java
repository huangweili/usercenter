package com.hwlcn.ldap.ldap.sdk.extensions;



import java.util.ArrayList;

import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.ExtendedRequest;
import com.hwlcn.ldap.ldap.sdk.ExtendedResult;
import com.hwlcn.ldap.ldap.sdk.LDAPConnection;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.extensions.ExtOpMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;



/**
 * This class provides an implementation of the LDAP password modify extended
 * request as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc3062.txt">RFC 3062</A>.  It may be used
 * to change the password for a user in the directory, and provides the ability
 * to specify the current password for verification.  It also offers the ability
 * to request that the server generate a new password for the user.
 * <BR><BR>
 * The elements of a password modify extended request include:
 * <UL>
 *   <LI>{@code userIdentity} -- This specifies the user for which to change the
 *       password.  It should generally be the DN for the target user (although
 *       the specification does indicate that some servers may accept other
 *       values).  If no value is provided, then the server will attempt to
 *       change the password for the currently-authenticated user.</LI>
 *   <LI>{@code oldPassword} -- This specifies the current password for the
 *       user.  Some servers may require that the old password be provided when
 *       a user is changing his or her own password as an extra level of
 *       verification, but it is generally not necessary when an administrator
 *       is resetting the password for another user.</LI>
 *   <LI>{@code newPassword} -- This specifies the new password to use for the
 *       user.  If it is not provided, then the server may attempt to generate a
 *       new password for the user, and in that case it will be included in the
 *       {@code generatedPassword} field of the corresponding
 *       {@link com.hwlcn.ldap.ldap.sdk.extensions.PasswordModifyExtendedResult}.  Note that some servers may not
 *       support generating a new password, in which case the client will always
 *       be required to provide it.</LI>
 * </UL>
 * <H2>Example</H2>
 * The following example demonstrates the use of the password modify extended
 * operation to change the password for user
 * "uid=john.doe,ou=People,dc=example,dc=com".  Neither the current password nor
 * a new password will be provided, so the server will generate a new password
 * for the user.
 * <PRE>
 *   PasswordModifyExtendedRequest passwordModifyRequest =
 *        new PasswordModifyExtendedRequest(
 *                 "uid=john.doe,ou=People,dc=example,dc=com", null, null);
 *   PasswordModifyExtendedResult passwordModifyResult =
 *        (PasswordModifyExtendedResult)
 *        connection.processExtendedOperation(passwordModifyRequest);
 *
 *   // NOTE:  The processExtendedOperation method will only throw an exception
 *   // if a problem occurs while trying to send the request or read the
 *   // response.  It will not throw an exception because of a non-success
 *   // response.
 *
 *   if (passwordModifyResult.getResultCode() == ResultCode.SUCCESS)
 *   {
 *     System.out.println("The password change was successful.");
 *     System.out.println("The new password for the user is " +
 *          passwordModifyResult.getGeneratedPassword());
 *   }
 *   else
 *   {
 *     System.err.println("An error occurred while attempting to process " +
 *                        "the password modify extended request.");
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PasswordModifyExtendedRequest
       extends ExtendedRequest
{

  public static final String PASSWORD_MODIFY_REQUEST_OID =
       "1.3.6.1.4.1.4203.1.11.1";

  private static final byte TYPE_USER_IDENTITY = (byte) 0x80;

  private static final byte TYPE_OLD_PASSWORD = (byte) 0x81;

  private static final byte TYPE_NEW_PASSWORD = (byte) 0x82;

  private static final long serialVersionUID = 4965048727456933570L;

  private final ASN1OctetString oldPassword;

  private final ASN1OctetString newPassword;

  private final String userIdentity;

  public PasswordModifyExtendedRequest(final String newPassword)
  {
    this(null, null, newPassword, null);
  }


  public PasswordModifyExtendedRequest(final byte[] newPassword)
  {
    this(null, null, newPassword, null);
  }

  public PasswordModifyExtendedRequest(final String oldPassword,
                                       final String newPassword)
  {
    this(null, oldPassword, newPassword, null);
  }

  public PasswordModifyExtendedRequest(final byte[] oldPassword,
                                       final byte[] newPassword)
  {
    this(null, oldPassword, newPassword, null);
  }

  public PasswordModifyExtendedRequest(final String userIdentity,
                                       final String oldPassword,
                                       final String newPassword)
  {
    this(userIdentity, oldPassword, newPassword, null);
  }

  public PasswordModifyExtendedRequest(final String userIdentity,
                                       final byte[] oldPassword,
                                       final byte[] newPassword)
  {
    this(userIdentity, oldPassword, newPassword, null);
  }


  public PasswordModifyExtendedRequest(final String userIdentity,
                                       final String oldPassword,
                                       final String newPassword,
                                       final Control[] controls)
  {
    super(PASSWORD_MODIFY_REQUEST_OID,
          encodeValue(userIdentity, oldPassword, newPassword), controls);

    this.userIdentity = userIdentity;

    if (oldPassword == null)
    {
      this.oldPassword = null;
    }
    else
    {
      this.oldPassword = new ASN1OctetString(TYPE_OLD_PASSWORD, oldPassword);
    }

    if (newPassword == null)
    {
      this.newPassword = null;
    }
    else
    {
      this.newPassword = new ASN1OctetString(TYPE_NEW_PASSWORD, newPassword);
    }
  }


  public PasswordModifyExtendedRequest(final String userIdentity,
                                       final byte[] oldPassword,
                                       final byte[] newPassword,
                                       final Control[] controls)
  {
    super(PASSWORD_MODIFY_REQUEST_OID,
          encodeValue(userIdentity, oldPassword, newPassword), controls);

    this.userIdentity = userIdentity;

    if (oldPassword == null)
    {
      this.oldPassword = null;
    }
    else
    {
      this.oldPassword = new ASN1OctetString(TYPE_OLD_PASSWORD, oldPassword);
    }

    if (newPassword == null)
    {
      this.newPassword = null;
    }
    else
    {
      this.newPassword = new ASN1OctetString(TYPE_NEW_PASSWORD, newPassword);
    }
  }

  public PasswordModifyExtendedRequest(final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PW_MODIFY_REQUEST_NO_VALUE.get());
    }

    try
    {
      ASN1OctetString oldPW  = null;
      ASN1OctetString newPW  = null;
      String          userID = null;

      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();
      for (final ASN1Element e : elements)
      {
        switch (e.getType())
        {
          case TYPE_USER_IDENTITY:
            userID = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;

          case TYPE_OLD_PASSWORD:
            oldPW = ASN1OctetString.decodeAsOctetString(e);
            break;

          case TYPE_NEW_PASSWORD:
            newPW = ASN1OctetString.decodeAsOctetString(e);
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_PW_MODIFY_REQUEST_INVALID_TYPE.get(
                                         toHex(e.getType())));
        }
      }

      userIdentity = userID;
      oldPassword  = oldPW;
      newPassword  = newPW;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PW_MODIFY_REQUEST_CANNOT_DECODE.get(e), e);
    }
  }

  private static ASN1OctetString encodeValue(final String userIdentity,
                                             final String oldPassword,
                                             final String newPassword)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(3);

    if (userIdentity != null)
    {
      elements.add(new ASN1OctetString(TYPE_USER_IDENTITY, userIdentity));
    }

    if (oldPassword != null)
    {
      elements.add(new ASN1OctetString(TYPE_OLD_PASSWORD, oldPassword));
    }

    if (newPassword != null)
    {
      elements.add(new ASN1OctetString(TYPE_NEW_PASSWORD, newPassword));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }

  private static ASN1OctetString encodeValue(final String userIdentity,
                                             final byte[] oldPassword,
                                             final byte[] newPassword)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(3);

    if (userIdentity != null)
    {
      elements.add(new ASN1OctetString(TYPE_USER_IDENTITY, userIdentity));
    }

    if (oldPassword != null)
    {
      elements.add(new ASN1OctetString(TYPE_OLD_PASSWORD, oldPassword));
    }

    if (newPassword != null)
    {
      elements.add(new ASN1OctetString(TYPE_NEW_PASSWORD, newPassword));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }

  public String getUserIdentity()
  {
    return userIdentity;
  }


  public String getOldPassword()
  {
    if (oldPassword == null)
    {
      return null;
    }
    else
    {
      return oldPassword.stringValue();
    }
  }

  public byte[] getOldPasswordBytes()
  {
    if (oldPassword == null)
    {
      return null;
    }
    else
    {
      return oldPassword.getValue();
    }
  }

  public ASN1OctetString getRawOldPassword()
  {
    return oldPassword;
  }


  public String getNewPassword()
  {
    if (newPassword == null)
    {
      return null;
    }
    else
    {
      return newPassword.stringValue();
    }
  }


  public byte[] getNewPasswordBytes()
  {
    if (newPassword == null)
    {
      return null;
    }
    else
    {
      return newPassword.getValue();
    }
  }

  public ASN1OctetString getRawNewPassword()
  {
    return newPassword;
  }


  @Override()
  public PasswordModifyExtendedResult process(final LDAPConnection connection,
                                              final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new PasswordModifyExtendedResult(extendedResponse);
  }


  @Override()
  public PasswordModifyExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }

  @Override()
  public PasswordModifyExtendedRequest duplicate(final Control[] controls)
  {
    final byte[] oldPWBytes =
         (oldPassword == null) ? null : oldPassword.getValue();
    final byte[] newPWBytes =
         (newPassword == null) ? null : newPassword.getValue();

    final PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(userIdentity, oldPWBytes,
              newPWBytes, controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }


  @Override()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_PASSWORD_MODIFY.get();
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("PasswordModifyExtendedRequest(");

    boolean dataAdded = false;

    if (userIdentity != null)
    {
      buffer.append("userIdentity='");
      buffer.append(userIdentity);
      buffer.append('\'');
      dataAdded = true;
    }

    if (oldPassword != null)
    {
      if (dataAdded)
      {
        buffer.append(", ");
      }

      buffer.append("oldPassword='");
      buffer.append(oldPassword.stringValue());
      buffer.append('\'');
      dataAdded = true;
    }

    if (newPassword != null)
    {
      if (dataAdded)
      {
        buffer.append(", ");
      }

      buffer.append("newPassword='");
      buffer.append(newPassword.stringValue());
      buffer.append('\'');
      dataAdded = true;
    }

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      if (dataAdded)
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

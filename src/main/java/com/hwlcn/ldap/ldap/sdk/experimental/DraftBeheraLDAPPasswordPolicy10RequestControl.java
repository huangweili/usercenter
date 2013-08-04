package com.hwlcn.ldap.ldap.sdk.experimental;



import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.experimental.ExperimentalMessages.*;



/**
 * This class provides an implementation of the password policy request control
 * as described in draft-behera-ldap-password-policy-10.  It may be used to
 * request information related to a user's password policy.  In the UnboundID
 * Directory Server, this control may be included with add, bind, compare,
 * modify, and password modify requests.
 * <BR><BR>
 * The corresponding {@link DraftBeheraLDAPPasswordPolicy10ResponseControl} may
 * include at most one warning from the set of
 * {@link com.hwlcn.ldap.ldap.sdk.experimental.DraftBeheraLDAPPasswordPolicy10WarningType} values and at most one
 * error from the set of {@link com.hwlcn.ldap.ldap.sdk.experimental.DraftBeheraLDAPPasswordPolicy10ErrorType}
 * values.  See the documentation for those classes for more information on the
 * information that may be included.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the password policy request
 * control in conjunction with a bind operation:
 * <PRE>
 *   SimpleBindRequest bindRequest = new SimpleBindRequest(
 *        "uid=john.doe,ou=People,dc=example,dc=com", "password",
 *        new DraftBeheraLDAPPasswordPolicy10RequestControl());
 *
 *   BindResult bindResult;
 *   try
 *   {
 *     bindResult = connection.bind(bindRequest);
 *   }
 *   catch (LDAPException le)
 *   {
 *     // The bind failed.  There may be a password policy response control to
 *     // help tell us why.
 *     bindResult = new BindResult(le.toLDAPResult());
 *   }
 *
 *   DraftBeheraLDAPPasswordPolicy10ResponseControl pwpResponse =
 *        DraftBeheraLDAPPasswordPolicy10ResponseControl.get(bindResult);
 *   if (pwpResponse != null)
 *   {
 *     DraftBeheraLDAPPasswordPolicy10ErrorType errorType =
 *          pwpResponse.getErrorType();
 *     if (errorType != null)
 *     {
 *       System.err.println("Password policy error:  " + errorType.getName());
 *     }
 *
 *     DraftBeheraLDAPPasswordPolicy10WarningType warningType =
 *          pwpResponse.getWarningType();
 *     if (warningType != null)
 *     {
 *       int value = pwpResponse.getWarningValue();
 *       switch (warningType)
 *       {
 *         case TIME_BEFORE_EXPIRATION:
 *           System.err.println("Your password will expire in " + value +
 *                              " seconds.");
 *           break;
 *         case GRACE_LOGINS_REMAINING:
 *           System.err.println("You have " + value +
 *                              " grace logins remaining.");
 *       }
 *     }
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DraftBeheraLDAPPasswordPolicy10RequestControl
       extends Control
{

  public static final String PASSWORD_POLICY_REQUEST_OID =
       "1.3.6.1.4.1.42.2.27.8.5.1";


  private static final long serialVersionUID = 6495056761590890150L;


  public DraftBeheraLDAPPasswordPolicy10RequestControl()
  {
    super(PASSWORD_POLICY_REQUEST_OID, false, null);
  }

  public DraftBeheraLDAPPasswordPolicy10RequestControl(final boolean isCritical)
  {
    super(PASSWORD_POLICY_REQUEST_OID, isCritical, null);
  }

  public DraftBeheraLDAPPasswordPolicy10RequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_REQUEST_HAS_VALUE.get());
    }
  }


  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PW_POLICY_REQUEST.get();
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("PasswordPolicyRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}

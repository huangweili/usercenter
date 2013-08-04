package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.util.Locale;

import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPException
       extends Exception
{

  public static final int SUCCESS = ResultCode.SUCCESS_INT_VALUE;

  public static final int OPERATION_ERROR =
       ResultCode.OPERATIONS_ERROR_INT_VALUE;


  public static final int PROTOCOL_ERROR = ResultCode.PROTOCOL_ERROR_INT_VALUE;


  public static final int TIME_LIMIT_EXCEEDED =
       ResultCode.TIME_LIMIT_EXCEEDED_INT_VALUE;


  public static final int SIZE_LIMIT_EXCEEDED =
       ResultCode.SIZE_LIMIT_EXCEEDED_INT_VALUE;


  public static final int COMPARE_FALSE = ResultCode.COMPARE_FALSE_INT_VALUE;

  public static final int COMPARE_TRUE = ResultCode.COMPARE_TRUE_INT_VALUE;

  public static final int AUTH_METHOD_NOT_SUPPORTED =
       ResultCode.AUTH_METHOD_NOT_SUPPORTED_INT_VALUE;

  public static final int STRONG_AUTH_REQUIRED =
       ResultCode.STRONG_AUTH_REQUIRED_INT_VALUE;


  public static final int LDAP_PARTIAL_RESULTS = 9;


  public static final int REFERRAL = ResultCode.REFERRAL_INT_VALUE;


  public static final int ADMIN_LIMIT_EXCEEDED =
       ResultCode.ADMIN_LIMIT_EXCEEDED_INT_VALUE;


  public static final int UNAVAILABLE_CRITICAL_EXTENSION =
       ResultCode.UNAVAILABLE_CRITICAL_EXTENSION_INT_VALUE;


  public static final int CONFIDENTIALITY_REQUIRED =
       ResultCode.CONFIDENTIALITY_REQUIRED_INT_VALUE;


  public static final int SASL_BIND_IN_PROGRESS =
       ResultCode.SASL_BIND_IN_PROGRESS_INT_VALUE;


  public static final int NO_SUCH_ATTRIBUTE =
       ResultCode.NO_SUCH_ATTRIBUTE_INT_VALUE;



  public static final int UNDEFINED_ATTRIBUTE_TYPE =
       ResultCode.UNDEFINED_ATTRIBUTE_TYPE_INT_VALUE;


  public static final int INAPPROPRIATE_MATCHING =
       ResultCode.INAPPROPRIATE_MATCHING_INT_VALUE;


  public static final int CONSTRAINT_VIOLATION =
       ResultCode.CONSTRAINT_VIOLATION_INT_VALUE;


  public static final int ATTRIBUTE_OR_VALUE_EXISTS =
       ResultCode.ATTRIBUTE_OR_VALUE_EXISTS_INT_VALUE;


  public static final int INVALID_ATTRIBUTE_SYNTAX =
       ResultCode.INVALID_ATTRIBUTE_SYNTAX_INT_VALUE;


  public static final int NO_SUCH_OBJECT = ResultCode.NO_SUCH_OBJECT_INT_VALUE;

  public static final int ALIAS_PROBLEM = ResultCode.ALIAS_PROBLEM_INT_VALUE;


  public static final int INVALID_DN_SYNTAX =
       ResultCode.INVALID_DN_SYNTAX_INT_VALUE;


  public static final int IS_LEAF = 35;


  public static final int ALIAS_DEREFERENCING_PROBLEM =
       ResultCode.ALIAS_DEREFERENCING_PROBLEM_INT_VALUE;


  public static final int INAPPROPRIATE_AUTHENTICATION =
       ResultCode.INAPPROPRIATE_AUTHENTICATION_INT_VALUE;

  public static final int INVALID_CREDENTIALS =
       ResultCode.INVALID_CREDENTIALS_INT_VALUE;



  public static final int INSUFFICIENT_ACCESS_RIGHTS =
       ResultCode.INSUFFICIENT_ACCESS_RIGHTS_INT_VALUE;


  public static final int BUSY = ResultCode.BUSY_INT_VALUE;


  public static final int UNAVAILABLE = ResultCode.UNAVAILABLE_INT_VALUE;


  public static final int UNWILLING_TO_PERFORM =
       ResultCode.UNWILLING_TO_PERFORM_INT_VALUE;


  public static final int LOOP_DETECTED = ResultCode.LOOP_DETECT_INT_VALUE;


  public static final int SORT_CONTROL_MISSING =
       ResultCode.SORT_CONTROL_MISSING_INT_VALUE;



  public static final int INDEX_RANGE_ERROR =
       ResultCode.OFFSET_RANGE_ERROR_INT_VALUE;


  public static final int NAMING_VIOLATION =
       ResultCode.NAMING_VIOLATION_INT_VALUE;


  public static final int OBJECT_CLASS_VIOLATION =
       ResultCode.OBJECT_CLASS_VIOLATION_INT_VALUE;


  public static final int NOT_ALLOWED_ON_NONLEAF =
       ResultCode.NOT_ALLOWED_ON_NONLEAF_INT_VALUE;


  public static final int NOT_ALLOWED_ON_RDN =
       ResultCode.NOT_ALLOWED_ON_RDN_INT_VALUE;


  public static final int ENTRY_ALREADY_EXISTS =
       ResultCode.ENTRY_ALREADY_EXISTS_INT_VALUE;


  public static final int OBJECT_CLASS_MODS_PROHIBITED =
       ResultCode.OBJECT_CLASS_MODS_PROHIBITED_INT_VALUE;


  public static final int AFFECTS_MULTIPLE_DSAS =
       ResultCode.AFFECTS_MULTIPLE_DSAS_INT_VALUE;



  public static final int OTHER = ResultCode.OTHER_INT_VALUE;



  public static final int SERVER_DOWN = ResultCode.SERVER_DOWN_INT_VALUE;


  public static final int LDAP_TIMEOUT = ResultCode.TIMEOUT_INT_VALUE;


  public static final int PARAM_ERROR = ResultCode.PARAM_ERROR_INT_VALUE;


  public static final int CONNECT_ERROR = ResultCode.CONNECT_ERROR_INT_VALUE;


  public static final int LDAP_NOT_SUPPORTED =
       ResultCode.NOT_SUPPORTED_INT_VALUE;


  public static final int CONTROL_NOT_FOUND =
       ResultCode.CONTROL_NOT_FOUND_INT_VALUE;


  public static final int NO_RESULTS_RETURNED =
       ResultCode.NO_RESULTS_RETURNED_INT_VALUE;

  public static final int MORE_RESULTS_TO_RETURN =
       ResultCode.MORE_RESULTS_TO_RETURN_INT_VALUE;

  public static final int CLIENT_LOOP =
       ResultCode.CLIENT_LOOP_INT_VALUE;


  public static final int REFERRAL_LIMIT_EXCEEDED =
       ResultCode.REFERRAL_LIMIT_EXCEEDED_INT_VALUE;


  private static final long serialVersionUID = 1942111440459840394L;


  private final int resultCode;

    private final String matchedDN;

  private final String serverErrorMessage;


  public LDAPException()
  {
    this(null, OTHER, null, null);
  }


  public LDAPException(final String message)
  {
    this(message, OTHER, null, null);
  }


  public LDAPException(final String message, final int resultCode)
  {
    this(message, resultCode, null, null);
  }


  public LDAPException(final String message, final int resultCode,
                       final String serverErrorMessage)
  {
    this(message, resultCode, serverErrorMessage, null);
  }

  public LDAPException(final String message, final int resultCode,
                       final String serverErrorMessage, final String matchedDN)
  {
    super(getMessage(message, serverErrorMessage, resultCode));

    this.resultCode         = resultCode;
    this.serverErrorMessage = serverErrorMessage;
    this.matchedDN          = matchedDN;
  }


  public LDAPException(final com.hwlcn.ldap.ldap.sdk.LDAPException ldapException)
  {
    this(ldapException.getMessage(), ldapException.getResultCode().intValue(),
         ldapException.getMessage(), ldapException.getMatchedDN());
  }


  private static String getMessage(final String message,
                                   final String serverErrorMessage,
                                   final int resultCode)
  {
    if ((message != null) && (message.length() > 0))
    {
      return message;
    }

    if ((serverErrorMessage != null) && (serverErrorMessage.length() > 0))
    {
      return serverErrorMessage;
    }

    return ResultCode.valueOf(resultCode).getName();
  }


  public int getLDAPResultCode()
  {
    return resultCode;
  }


  public String getLDAPErrorMessage()
  {
    return serverErrorMessage;
  }


  public String getMatchedDN()
  {
    return matchedDN;
  }


  public final com.hwlcn.ldap.ldap.sdk.LDAPException toLDAPException()
  {
    return new com.hwlcn.ldap.ldap.sdk.LDAPException(
         ResultCode.valueOf(resultCode), getMessage(), matchedDN, null);
  }


  public String errorCodeToString()
  {
    return ResultCode.valueOf(resultCode).getName();
  }


  public String errorCodeToString(final Locale l)
  {
    return ResultCode.valueOf(resultCode).getName();
  }


  public static String errorCodeToString(final int code)
  {
    return ResultCode.valueOf(code).getName();
  }


  public static String errorCodeToString(final int code, final Locale locale)
  {
    return ResultCode.valueOf(code).getName();
  }


  @Override()
  public String toString()
  {
    return toLDAPException().toString();
  }
}

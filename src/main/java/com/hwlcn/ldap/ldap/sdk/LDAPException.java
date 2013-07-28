package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.ldap.util.LDAPSDKException;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPException
       extends LDAPSDKException
{

  private static final long serialVersionUID = -4257171063946350327L;



  protected static final Control[] NO_CONTROLS = StaticUtils.NO_CONTROLS;


  protected static final String[] NO_REFERRALS = StaticUtils.NO_STRINGS;




  private final Control[] responseControls;

  private final ResultCode resultCode;

  private final String[] referralURLs;

  private final String diagnosticMessage;

  private final String matchedDN;


  public LDAPException(final ResultCode resultCode)
  {
    super(resultCode.getName());

    this.resultCode = resultCode;

    matchedDN         = null;
    diagnosticMessage = null;
    referralURLs      = NO_REFERRALS;
    responseControls  = NO_CONTROLS;
  }




  public LDAPException(final ResultCode resultCode, final Throwable cause)
  {
    super(resultCode.getName(), cause);

    this.resultCode = resultCode;

    matchedDN         = null;
    diagnosticMessage = null;
    referralURLs      = NO_REFERRALS;
    responseControls  = NO_CONTROLS;
  }




  public LDAPException(final ResultCode resultCode, final String errorMessage)
  {
    super(errorMessage);

    this.resultCode = resultCode;

    matchedDN         = null;
    diagnosticMessage = null;
    referralURLs      = NO_REFERRALS;
    responseControls  = NO_CONTROLS;
  }




  public LDAPException(final ResultCode resultCode, final String errorMessage,
                       final Throwable cause)
  {
    super(errorMessage, cause);

    this.resultCode = resultCode;

    matchedDN         = null;
    diagnosticMessage = null;
    referralURLs      = NO_REFERRALS;
    responseControls  = NO_CONTROLS;
  }




  public LDAPException(final ResultCode resultCode, final String errorMessage,
                       final String matchedDN, final String[] referralURLs)
  {
    super(errorMessage);

    this.resultCode = resultCode;
    this.matchedDN  = matchedDN;

    if (referralURLs == null)
    {
      this.referralURLs = NO_REFERRALS;
    }
    else
    {
      this.referralURLs = referralURLs;
    }

    diagnosticMessage = null;
    responseControls  = NO_CONTROLS;
  }


  public LDAPException(final ResultCode resultCode, final String errorMessage,
                       final String matchedDN, final String[] referralURLs,
                       final Throwable cause)
  {
    super(errorMessage, cause);

    this.resultCode = resultCode;
    this.matchedDN  = matchedDN;

    if (referralURLs == null)
    {
      this.referralURLs = NO_REFERRALS;
    }
    else
    {
      this.referralURLs = referralURLs;
    }

    diagnosticMessage = null;
    responseControls  = NO_CONTROLS;
  }




  public LDAPException(final ResultCode resultCode, final String errorMessage,
                       final String matchedDN, final String[] referralURLs,
                       final Control[] controls)
  {
    super(errorMessage);

    this.resultCode = resultCode;
    this.matchedDN  = matchedDN;

    diagnosticMessage = null;

    if (referralURLs == null)
    {
      this.referralURLs = NO_REFERRALS;
    }
    else
    {
      this.referralURLs = referralURLs;
    }

    if (controls == null)
    {
      responseControls = NO_CONTROLS;
    }
    else
    {
      responseControls = controls;
    }
  }



  public LDAPException(final ResultCode resultCode, final String errorMessage,
                       final String matchedDN, final String[] referralURLs,
                       final Control[] controls, final Throwable cause)
  {
    super(errorMessage, cause);

    this.resultCode = resultCode;
    this.matchedDN  = matchedDN;

    diagnosticMessage = null;

    if (referralURLs == null)
    {
      this.referralURLs = NO_REFERRALS;
    }
    else
    {
      this.referralURLs = referralURLs;
    }

    if (controls == null)
    {
      responseControls = NO_CONTROLS;
    }
    else
    {
      responseControls = controls;
    }
  }


  public LDAPException(final LDAPResult ldapResult)
  {
    super((ldapResult.getDiagnosticMessage() == null)
          ? ldapResult.getResultCode().getName()
          : ldapResult.getDiagnosticMessage());

    resultCode        = ldapResult.getResultCode();
    matchedDN         = ldapResult.getMatchedDN();
    diagnosticMessage = ldapResult.getDiagnosticMessage();
    referralURLs      = ldapResult.getReferralURLs();
    responseControls  = ldapResult.getResponseControls();
  }




  public LDAPException(final LDAPResult ldapResult, final Throwable cause)
  {
    super(((ldapResult.getDiagnosticMessage() == null)
           ? ldapResult.getResultCode().getName()
           : ldapResult.getDiagnosticMessage()),
          cause);

    resultCode        = ldapResult.getResultCode();
    matchedDN         = ldapResult.getMatchedDN();
    diagnosticMessage = ldapResult.getDiagnosticMessage();
    referralURLs      = ldapResult.getReferralURLs();
    responseControls  = ldapResult.getResponseControls();
  }




  public LDAPException(final LDAPException e)
  {
    super(e.getMessage(), e.getCause());

    resultCode        = e.getResultCode();
    matchedDN         = e.getMatchedDN();
    diagnosticMessage = e.getDiagnosticMessage();
    referralURLs      = e.getReferralURLs();
    responseControls  = e.getResponseControls();
  }




  public final ResultCode getResultCode()
  {
    return resultCode;
  }



  public final String getMatchedDN()
  {
    return matchedDN;
  }



  public final String getDiagnosticMessage()
  {
    return diagnosticMessage;
  }


  public final String[] getReferralURLs()
  {
    return referralURLs;
  }



  public final boolean hasResponseControl()
  {
    return (responseControls.length > 0);
  }




  public final boolean hasResponseControl(final String oid)
  {
    for (final Control c : responseControls)
    {
      if (c.getOID().equals(oid))
      {
        return true;
      }
    }

    return false;
  }




  public final Control[] getResponseControls()
  {
    return responseControls;
  }



  public final Control getResponseControl(final String oid)
  {
    for (final Control c : responseControls)
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    return null;
  }


  public LDAPResult toLDAPResult()
  {
    if ((diagnosticMessage == null) && (getMessage() != null))
    {
      return new LDAPResult(-1, resultCode, getMessage(), matchedDN,
           referralURLs, responseControls);
    }
    else
    {
      return new LDAPResult(-1, resultCode, diagnosticMessage, matchedDN,
           referralURLs, responseControls);
    }
  }



  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDAPException(resultCode=");
    buffer.append(resultCode);

    final String errorMessage = getMessage();
    if (errorMessage != null)
    {
      buffer.append(", errorMessage='");
      buffer.append(errorMessage);
      buffer.append('\'');
    }

    if (matchedDN != null)
    {
      buffer.append(", matchedDN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

    if (diagnosticMessage != null)
    {
      buffer.append(", diagnosticMessage='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    if (referralURLs.length > 0)
    {
      buffer.append(", referralURLs={");

      for (int i=0; i < referralURLs.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append('\'');
        buffer.append(referralURLs[i]);
        buffer.append('\'');
      }

      buffer.append('}');
    }

    if (responseControls.length > 0)
    {
      buffer.append(", responseControls={");

      for (int i=0; i < responseControls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(responseControls[i]);
      }

      buffer.append('}');
    }

    buffer.append(')');
  }


  @Override()
  public final String getExceptionMessage()
  {
    return toString();
  }
}

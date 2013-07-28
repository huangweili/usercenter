package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.Validator;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GenericSASLBindRequest
       extends SASLBindRequest
{
  private static final long serialVersionUID = 7740968332104559230L;


  private final ASN1OctetString credentials;

  private final String bindDN;

  private final String mechanism;


  public GenericSASLBindRequest(final String bindDN, final String mechanism,
                                final ASN1OctetString credentials,
                                final Control... controls)
  {
    super(controls);

    Validator.ensureNotNull(mechanism);

    this.bindDN      = bindDN;
    this.mechanism   = mechanism;
    this.credentials = credentials;
  }



  public String getBindDN()
  {
    return bindDN;
  }



  @Override()
  public String getSASLMechanismName()
  {
    return mechanism;
  }



  public ASN1OctetString getCredentials()
  {
    return credentials;
  }



  @Override()
  protected BindResult process(final LDAPConnection connection, final int depth)
            throws LDAPException
  {
    return sendBindRequest(connection, bindDN, credentials, getControls(),
         getResponseTimeoutMillis(connection));
  }


  @Override()
  public GenericSASLBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  @Override()
  public GenericSASLBindRequest duplicate(final Control[] controls)
  {
    return new GenericSASLBindRequest(bindDN, mechanism, credentials,
         controls);
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("GenericSASLBindRequest(mechanism='");
    buffer.append(mechanism);
    buffer.append('\'');

    if (bindDN != null)
    {
      buffer.append(", bindDN='");
      buffer.append(bindDN);
      buffer.append('\'');
    }

    if (credentials != null)
    {
      buffer.append(", credentials=byte[");
      buffer.append(credentials.getValueLength());
      buffer.append(']');
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

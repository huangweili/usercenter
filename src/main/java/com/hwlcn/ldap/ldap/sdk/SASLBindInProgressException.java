package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SASLBindInProgressException
       extends LDAPException
{

  private static final long serialVersionUID = 2842513438320459264L;


  private final BindResult bindResult;


  SASLBindInProgressException(final BindResult bindResult)
  {
    super(bindResult);

    this.bindResult = bindResult;
  }


  public BindResult getBindResult()
  {
    return bindResult;
  }



  public ASN1OctetString getServerSASLCredentials()
  {
    return bindResult.getServerSASLCredentials();
  }
}

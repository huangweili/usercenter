package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.ExtendedResult;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPExtendedResponse
       extends LDAPResponse
{

  private static final long serialVersionUID = 7956345950545720834L;

  private final ExtendedResult extendedResult;


  public LDAPExtendedResponse(final ExtendedResult extendedResult)
  {
    super(extendedResult);

    this.extendedResult = extendedResult;
  }



  public String getID()
  {
    return extendedResult.getOID();
  }


  public byte[] getValue()
  {
    final ASN1OctetString value = extendedResult.getValue();
    if (value == null)
    {
      return null;
    }
    else
    {
      return value.getValue();
    }
  }

  public final ExtendedResult toExtendedResult()
  {
    return extendedResult;
  }

  @Override()
  public String toString()
  {
    return extendedResult.toString();
  }
}

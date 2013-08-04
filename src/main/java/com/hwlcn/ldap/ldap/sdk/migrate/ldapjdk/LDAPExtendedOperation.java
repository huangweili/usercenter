package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.ExtendedRequest;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPExtendedOperation
       implements Serializable
{

  private static final long serialVersionUID = 9207085503424216431L;

  private final byte[] value;

  private final String oid;


  public LDAPExtendedOperation(final String id, final byte[] vals)
  {
    oid   = id;
    value = vals;
  }

  public LDAPExtendedOperation(final ExtendedRequest extendedRequest)
  {
    oid = extendedRequest.getOID();

    final ASN1OctetString v = extendedRequest.getValue();
    if (v == null)
    {
      value = null;
    }
    else
    {
      value = v.getValue();
    }
  }


  public String getID()
  {
    return oid;
  }


  public byte[] getValue()
  {
    return value;
  }

  public final ExtendedRequest toExtendedRequest()
  {
    if (value == null)
    {
      return new ExtendedRequest(oid);
    }
    else
    {
      return new ExtendedRequest(oid, new ASN1OctetString(value));
    }
  }


  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();

    buffer.append("LDAPExtendedOperation(id=");
    buffer.append(oid);

    if (value != null)
    {
      buffer.append(", value=byte[");
      buffer.append(value.length);
      buffer.append(']');
    }

    buffer.append(')');

    return buffer.toString();
  }
}

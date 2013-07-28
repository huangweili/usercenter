package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ReadOnlyCompareRequest
       extends ReadOnlyLDAPRequest
{

  String getDN();

  String getAttributeName();

  String getAssertionValue();


  byte[] getAssertionValueBytes();

  ASN1OctetString getRawAssertionValue();

  CompareRequest duplicate();

  CompareRequest duplicate(final Control[] controls);
}

package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface DecodeableControl
       extends Serializable
{

  Control decodeControl(final String oid, final boolean isCritical,
                        final ASN1OctetString value)
          throws LDAPException;
}

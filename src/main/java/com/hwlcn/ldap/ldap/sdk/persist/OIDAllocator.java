
package com.hwlcn.ldap.ldap.sdk.persist;



import java.io.Serializable;

import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class OIDAllocator
       implements Serializable
{

  public abstract String allocateAttributeTypeOID(final String name);



  public abstract String allocateObjectClassOID(final String name);
}

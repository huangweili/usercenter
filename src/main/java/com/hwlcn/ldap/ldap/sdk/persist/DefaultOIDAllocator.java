
package com.hwlcn.ldap.ldap.sdk.persist;



import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DefaultOIDAllocator
       extends OIDAllocator
{

  private static final DefaultOIDAllocator INSTANCE = new DefaultOIDAllocator();



  private static final long serialVersionUID = 4815405566303309719L;


  private DefaultOIDAllocator()
  {

  }


  public static DefaultOIDAllocator getInstance()
  {
    return INSTANCE;
  }



  @Override()
  public String allocateAttributeTypeOID(final String name)
  {
    return StaticUtils.toLowerCase(name) + "-oid";
  }


  @Override()
  public String allocateObjectClassOID(final String name)
  {
    return StaticUtils.toLowerCase(name) + "-oid";
  }
}

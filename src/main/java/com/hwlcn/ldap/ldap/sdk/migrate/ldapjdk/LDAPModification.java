
package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;

import com.hwlcn.ldap.ldap.sdk.Modification;
import com.hwlcn.ldap.ldap.sdk.ModificationType;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPModification
       implements Serializable
{

  public static final int ADD = ModificationType.ADD_INT_VALUE;

  public static final int DELETE = ModificationType.DELETE_INT_VALUE;

  public static final int REPLACE = ModificationType.REPLACE_INT_VALUE;

  private static final long serialVersionUID = 4385895404606128438L;

  private final Modification modification;

  public LDAPModification(final int op, final LDAPAttribute attr)
  {
    modification = new Modification(ModificationType.valueOf(op),
         attr.getName(), attr.getByteValueArray());
  }


  public LDAPModification(final Modification modification)
  {
    this.modification = modification;
  }

  public int getOp()
  {
    return modification.getModificationType().intValue();
  }

  public LDAPAttribute getAttribute()
  {
    return new LDAPAttribute(modification.getAttribute());
  }


  public Modification toModification()
  {
    return modification;
  }


  @Override()
  public String toString()
  {
    return modification.toString();
  }
}

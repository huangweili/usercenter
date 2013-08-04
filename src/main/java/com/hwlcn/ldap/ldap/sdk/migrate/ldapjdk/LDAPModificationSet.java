
package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;

import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotExtensible()
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPModificationSet
       implements Serializable
{

  private static final long serialVersionUID = -1789929614205832665L;


  private final ArrayList<LDAPModification> mods;


  public LDAPModificationSet()
  {
    mods = new ArrayList<LDAPModification>(1);
  }

  public void add(final int op, final LDAPAttribute attr)
  {
    mods.add(new LDAPModification(op, attr));
  }

  public LDAPModification elementAt(final int index)
         throws IndexOutOfBoundsException
  {
    return mods.get(index);
  }


  public void removeElementAt(final int index)
         throws IndexOutOfBoundsException
  {
    mods.remove(index);
  }


  public void remove(final String name)
  {
    final Iterator<LDAPModification> iterator = mods.iterator();
    while (iterator.hasNext())
    {
      final LDAPModification mod = iterator.next();
      if (mod.getAttribute().getName().equalsIgnoreCase(name))
      {
        iterator.remove();
        return;
      }
    }
  }


  public int size()
  {
    return mods.size();
  }

  public LDAPModification[] toArray()
  {
    final LDAPModification[] modArray = new LDAPModification[mods.size()];
    return mods.toArray(modArray);
  }

  @Override()
  public String toString()
  {
    return mods.toString();
  }
}

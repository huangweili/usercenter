package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.util.Enumeration;
import java.util.Iterator;
import java.util.NoSuchElementException;

import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@InternalUseOnly()
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class IterableEnumeration<T>
      implements Enumeration<T>
{
  private final Iterator<T> iterator;



  IterableEnumeration(final Iterable<T> i)
  {
    iterator = i.iterator();
  }



  public boolean hasMoreElements()
  {
    return iterator.hasNext();
  }


  public T nextElement()
         throws NoSuchElementException
  {
    return iterator.next();
  }
}

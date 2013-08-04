
package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;

import java.io.Serializable;
import java.util.Comparator;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReverseComparator<T>
       implements Comparator<T>, Serializable
{

  private static final long serialVersionUID = -4615537960027681276L;

  private final Comparator<T> baseComparator;

  public ReverseComparator()
  {
    baseComparator = null;
  }
  public ReverseComparator(final Comparator<T> baseComparator)
  {
    this.baseComparator = baseComparator;
  }


  @SuppressWarnings("unchecked")
  public int compare(final T o1, final T o2)
  {
    final int baseValue;
    if (baseComparator == null)
    {
      baseValue = ((Comparable<? super T>) o1).compareTo(o2);
    }
    else
    {
      baseValue = baseComparator.compare(o1, o2);
    }

    if (baseValue < 0)
    {
      return 1;
    }
    else if (baseValue > 0)
    {
      return -1;
    }
    else
    {
      return 0;
    }
  }


  @Override()
  public int hashCode()
  {
    if (baseComparator == null)
    {
      return 0;
    }
    else
    {
      return baseComparator.hashCode();
    }
  }



  @Override()
  @SuppressWarnings("unchecked")
  public boolean equals(final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o.getClass().equals(ReverseComparator.class)))
    {
      return false;
    }

    final ReverseComparator<T> c = (ReverseComparator<T>) o;
    if (baseComparator == null)
    {
      return (c.baseComparator == null);
    }
    else
    {
      return baseComparator.equals(c.baseComparator);
    }
  }
}

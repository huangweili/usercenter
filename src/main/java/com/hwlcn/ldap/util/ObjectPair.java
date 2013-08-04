
package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;

import java.io.Serializable;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ObjectPair<F,S>
       implements Serializable
{

  private static final long serialVersionUID = -8610279945233778440L;


  private final F first;

  private final S second;




  public ObjectPair(final F first, final S second)
  {
    this.first  = first;
    this.second = second;
  }



  public F getFirst()
  {
    return first;
  }



  public S getSecond()
  {
    return second;
  }



  @Override()
  public int hashCode()
  {
    int h = 0;

    if (first != null)
    {
      h += first.hashCode();
    }

    if (second != null)
    {
      h += second.hashCode();
    }

    return h;
  }



  @Override()
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

    if (o instanceof ObjectPair)
    {
      final ObjectPair<?,?> p = (ObjectPair<?,?>) o;
      if (first == null)
      {
        if (p.first != null)
        {
          return false;
        }
      }
      else
      {
        if (! first.equals(p.first))
        {
          return false;
        }
      }

      if (second == null)
      {
        if (p.second != null)
        {
          return false;
        }
      }
      else
      {
        if (! second.equals(p.second))
        {
          return false;
        }
      }

      return true;
    }

    return false;
  }




  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }


  public void toString(final StringBuilder buffer)
  {
    buffer.append("ObjectPair(first=");
    buffer.append(String.valueOf(first));
    buffer.append(", second=");
    buffer.append(String.valueOf(second));
    buffer.append(')');
  }
}

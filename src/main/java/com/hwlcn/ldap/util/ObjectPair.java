/*
 * Copyright 2008-2013 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2013 UnboundID Corp.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;

import java.io.Serializable;



/**
 * This class provides a typed pair of objects.  It may be used whenever two
 * objects are required but only one is allowed (e.g., returning two values from
 * a method).
 *
 * @param  <F>  The type of the first object.
 * @param  <S>  The type of the second object.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ObjectPair<F,S>
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8610279945233778440L;



  // The first object in this pair.
  private final F first;

  // The second object in this pair.
  private final S second;



  /**
   * Creates a new object pair with the provided elements.
   *
   * @param  first   The first object in this pair.
   * @param  second  The second object in this pair.
   */
  public ObjectPair(final F first, final S second)
  {
    this.first  = first;
    this.second = second;
  }



  /**
   * Retrieves the first object in  this pair.
   *
   * @return  The first object in this pair.
   */
  public F getFirst()
  {
    return first;
  }



  /**
   * Retrieves the second object in this pair.
   *
   * @return  The second object in this pair.
   */
  public S getSecond()
  {
    return second;
  }



  /**
   * Retrieves a hash code for this object pair.
   *
   * @return  A hash code for this object pair.
   */
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



  /**
   * Indicates whether the provided object is equal to this object pair.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is equal to this object pair,
   *          or {@code false} if not.
   */
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



  /**
   * Retrieves a string representation of this object pair.
   *
   * @return  A string representation of this object pair.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this object pair to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ObjectPair(first=");
    buffer.append(String.valueOf(first));
    buffer.append(", second=");
    buffer.append(String.valueOf(second));
    buffer.append(')');
  }
}

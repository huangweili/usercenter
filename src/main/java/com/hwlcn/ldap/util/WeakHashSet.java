package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;

import java.lang.ref.WeakReference;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class WeakHashSet<T>
       implements Set<T>
{
  private final WeakHashMap<T,WeakReference<T>> m;


  public WeakHashSet()
  {
    m = new WeakHashMap<T,WeakReference<T>>(16);
  }



  public WeakHashSet(final int initialCapacity)
  {
    m = new WeakHashMap<T,WeakReference<T>>(initialCapacity);
  }



  public void clear()
  {
    m.clear();
  }



  public boolean isEmpty()
  {
    return m.isEmpty();
  }




  public int size()
  {
    return m.size();
  }



  public boolean contains(final Object e)
  {
    return m.containsKey(e);
  }




  public boolean containsAll(final Collection<?> c)
  {
    return m.keySet().containsAll(c);
  }



  public T get(final T e)
  {
    final WeakReference<T> r = m.get(e);
    if (r == null)
    {
      return null;
    }
    else
    {
      return r.get();
    }
  }




  public boolean add(final T e)
  {
    if (m.containsKey(e))
    {
      return false;
    }
    else
    {
      m.put(e, new WeakReference<T>(e));
      return true;
    }
  }



  public boolean addAll(final Collection<? extends T> c)
  {
    boolean changed = false;
    for (final T e : c)
    {
      if (! m.containsKey(e))
      {
        m.put(e, new WeakReference<T>(e));
        changed = true;
      }
    }

    return changed;
  }



  public T addAndGet(final T e)
  {
    final WeakReference<T> r = m.get(e);
    if (r != null)
    {
      final T existingElement = r.get();
      if (existingElement != null)
      {
        return existingElement;
      }
    }

    m.put(e, new WeakReference<T>(e));
    return e;
  }



  public boolean remove(final Object e)
  {
    return (m.remove(e) != null);
  }



  public boolean removeAll(final Collection<?> c)
  {
    boolean changed = false;
    for (final Object o : c)
    {
      final Object e = m.remove(o);
      if (e != null)
      {
        changed = true;
      }
    }

    return changed;
  }



  public boolean retainAll(final Collection<?> c)
  {
    boolean changed = false;
    final Iterator<Map.Entry<T,WeakReference<T>>> iterator =
         m.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<T,WeakReference<T>> e = iterator.next();
      if (! c.contains(e.getKey()))
      {
        iterator.remove();
        changed = true;
      }
    }

    return changed;
  }




  public Iterator<T> iterator()
  {
    return m.keySet().iterator();
  }




  public Object[] toArray()
  {
    return m.keySet().toArray();
  }



  public <E> E[] toArray(final E[] a)
  {
    return m.keySet().toArray(a);
  }



  public int hashCode()
  {
    return m.keySet().hashCode();
  }



  public boolean equals(final Object o)
  {
    return ((o != null) && (o instanceof Set) && m.keySet().equals(o));
  }


  @Override()
  public String toString()
  {
    return m.keySet().toString();
  }
}


package com.hwlcn.ldap.util;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.ldap.sdk.ResultCode;



@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ResultCodeCounter
       implements Serializable
{

  private static final long serialVersionUID = -2280620218815022241L;

 private final AtomicReference<ConcurrentHashMap<ResultCode,AtomicLong>> rcMap;

  public ResultCodeCounter()
  {
    rcMap = new AtomicReference<ConcurrentHashMap<ResultCode,AtomicLong>>();
    rcMap.set(new ConcurrentHashMap<ResultCode,AtomicLong>());
  }

  public void increment(final ResultCode resultCode)
  {
    increment(resultCode, 1);
  }


  public void increment(final ResultCode resultCode, final int amount)
  {
    final ConcurrentHashMap<ResultCode,AtomicLong> m = rcMap.get();

    AtomicLong l = m.get(resultCode);
    if (l == null)
    {
      l = new AtomicLong(0L);
      final AtomicLong l2 = m.putIfAbsent(resultCode, l);
      if (l2 != null)
      {
        l = l2;
      }
    }

    l.addAndGet(amount);
  }


  public void reset()
  {
    rcMap.set(new ConcurrentHashMap<ResultCode, AtomicLong>());
  }



  public List<ObjectPair<ResultCode,Long>> getCounts(final boolean reset)
  {
    final ConcurrentHashMap<ResultCode,AtomicLong> m;
    if (reset)
    {
      m = rcMap.getAndSet(new ConcurrentHashMap<ResultCode,AtomicLong>());
    }
    else
    {
      m = new ConcurrentHashMap<ResultCode,AtomicLong>(rcMap.get());
    }


    if (m.isEmpty())
    {
      return Collections.emptyList();
    }


    final TreeMap<Long,TreeMap<Integer,ResultCode>> sortedMap =
         new TreeMap<Long,TreeMap<Integer,ResultCode>>(
              new ReverseComparator<Long>());
    for (final Map.Entry<ResultCode,AtomicLong> e : m.entrySet())
    {
      final long l = e.getValue().longValue();
      TreeMap<Integer,ResultCode> rcByValue = sortedMap.get(l);
      if (rcByValue == null)
      {
        rcByValue = new TreeMap<Integer,ResultCode>();
        sortedMap.put(l, rcByValue);
      }

      final ResultCode rc = e.getKey();
      rcByValue.put(rc.intValue(), rc);
    }


    final ArrayList<ObjectPair<ResultCode,Long>> rcCounts =
         new ArrayList<ObjectPair<ResultCode,Long>>(2*sortedMap.size());
    for (final Map.Entry<Long,TreeMap<Integer,ResultCode>> e :
         sortedMap.entrySet())
    {
      final long count = e.getKey();
      for (final ResultCode rc : e.getValue().values())
      {
        rcCounts.add(new ObjectPair<ResultCode,Long>(rc, count));
      }
    }

    return Collections.unmodifiableList(rcCounts);
  }
}

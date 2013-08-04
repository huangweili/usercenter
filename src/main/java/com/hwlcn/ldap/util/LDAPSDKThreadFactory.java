
package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;


@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPSDKThreadFactory
       implements ThreadFactory
{

  private final AtomicLong threadCounter;

  private final boolean daemon;

  private final String baseName;

  private final ThreadGroup threadGroup;




  public LDAPSDKThreadFactory(final String baseName, final boolean daemon)
  {
    this(baseName, daemon, null);
  }


  public LDAPSDKThreadFactory(final String baseName, final boolean daemon,
                              final ThreadGroup threadGroup)
  {
    this.baseName     = baseName;
    this.daemon       = daemon;
    this.threadGroup  = threadGroup;

    threadCounter = new AtomicLong(1L);
  }

  public Thread newThread(final Runnable r)
  {
    final String name = baseName + ' ' + threadCounter.getAndIncrement();
    final Thread t = new Thread(threadGroup, r, baseName);
    t.setDaemon(daemon);
    return t;
  }
}

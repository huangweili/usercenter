
package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.text.DecimalFormat;
import java.util.concurrent.atomic.AtomicLong;

import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.MOSTLY_THREADSAFE)
public final class LDAPConnectionStatistics
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1096417617572481790L;



  private final AtomicLong numAbandonRequests;

  private final AtomicLong numAddRequests;

  private final AtomicLong numAddResponses;

  private final AtomicLong numBindRequests;
  private final AtomicLong numBindResponses;

  private final AtomicLong numCompareRequests;

  private final AtomicLong numCompareResponses;

  private final AtomicLong numConnects;

  private final AtomicLong numDeleteRequests;

  private final AtomicLong numDeleteResponses;

  private final AtomicLong numDisconnects;

  private final AtomicLong numExtendedRequests;

  private final AtomicLong numExtendedResponses;

  private final AtomicLong numModifyRequests;

  private final AtomicLong numModifyResponses;

 private final AtomicLong numModifyDNRequests;

  private final AtomicLong numModifyDNResponses;

 private final AtomicLong numSearchRequests;

 private final AtomicLong numSearchEntryResponses;

private final AtomicLong numSearchReferenceResponses;

  private final AtomicLong numSearchDoneResponses;

  private final AtomicLong numUnbindRequests;

  private final AtomicLong totalAddResponseTime;

  private final AtomicLong totalBindResponseTime;

  private final AtomicLong totalCompareResponseTime;

  private final AtomicLong totalDeleteResponseTime;

  private final AtomicLong totalExtendedResponseTime;

  private final AtomicLong totalModifyResponseTime;

  private final AtomicLong totalModifyDNResponseTime;

  private final AtomicLong totalSearchResponseTime;



  public LDAPConnectionStatistics()
  {
    numAbandonRequests          = new AtomicLong(0L);
    numAddRequests              = new AtomicLong(0L);
    numAddResponses             = new AtomicLong(0L);
    numBindRequests             = new AtomicLong(0L);
    numBindResponses            = new AtomicLong(0L);
    numCompareRequests          = new AtomicLong(0L);
    numCompareResponses         = new AtomicLong(0L);
    numConnects                 = new AtomicLong(0L);
    numDeleteRequests           = new AtomicLong(0L);
    numDeleteResponses          = new AtomicLong(0L);
    numDisconnects              = new AtomicLong(0L);
    numExtendedRequests         = new AtomicLong(0L);
    numExtendedResponses        = new AtomicLong(0L);
    numModifyRequests           = new AtomicLong(0L);
    numModifyResponses          = new AtomicLong(0L);
    numModifyDNRequests         = new AtomicLong(0L);
    numModifyDNResponses        = new AtomicLong(0L);
    numSearchRequests           = new AtomicLong(0L);
    numSearchEntryResponses     = new AtomicLong(0L);
    numSearchReferenceResponses = new AtomicLong(0L);
    numSearchDoneResponses      = new AtomicLong(0L);
    numUnbindRequests           = new AtomicLong(0L);
    totalAddResponseTime        = new AtomicLong(0L);
    totalBindResponseTime       = new AtomicLong(0L);
    totalCompareResponseTime    = new AtomicLong(0L);
    totalDeleteResponseTime     = new AtomicLong(0L);
    totalExtendedResponseTime   = new AtomicLong(0L);
    totalModifyResponseTime     = new AtomicLong(0L);
    totalModifyDNResponseTime   = new AtomicLong(0L);
    totalSearchResponseTime     = new AtomicLong(0L);
  }



  public void reset()
  {
    numAbandonRequests.set(0L);
    numAddRequests.set(0L);
    numAddResponses.set(0L);
    numBindRequests.set(0L);
    numBindResponses.set(0L);
    numCompareRequests.set(0L);
    numCompareResponses.set(0L);
    numConnects.set(0L);
    numDeleteRequests.set(0L);
    numDeleteResponses.set(0L);
    numDisconnects.set(0L);
    numExtendedRequests.set(0L);
    numExtendedResponses.set(0L);
    numModifyRequests.set(0L);
    numModifyResponses.set(0L);
    numModifyDNRequests.set(0L);
    numModifyDNResponses.set(0L);
    numSearchRequests.set(0L);
    numSearchEntryResponses.set(0L);
    numSearchReferenceResponses.set(0L);
    numSearchDoneResponses.set(0L);
    numUnbindRequests.set(0L);
    totalAddResponseTime.set(0L);
    totalBindResponseTime.set(0L);
    totalCompareResponseTime.set(0L);
    totalDeleteResponseTime.set(0L);
    totalExtendedResponseTime.set(0L);
    totalModifyResponseTime.set(0L);
    totalModifyDNResponseTime.set(0L);
    totalSearchResponseTime.set(0L);
  }




  public long getNumConnects()
  {
    return numConnects.get();
  }



  void incrementNumConnects()
  {
    numConnects.incrementAndGet();
  }



  public long getNumDisconnects()
  {
    return numDisconnects.get();
  }



  void incrementNumDisconnects()
  {
    numDisconnects.incrementAndGet();
  }



  public long getNumAbandonRequests()
  {
    return numAbandonRequests.get();
  }



  void incrementNumAbandonRequests()
  {
    numAbandonRequests.incrementAndGet();
  }



  public long getNumAddRequests()
  {
    return numAddRequests.get();
  }



  void incrementNumAddRequests()
  {
    numAddRequests.incrementAndGet();
  }


  public long getNumAddResponses()
  {
    return numAddResponses.get();
  }



  void incrementNumAddResponses(final long responseTime)
  {
    numAddResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalAddResponseTime.addAndGet(responseTime);
    }
  }


  public long getTotalAddResponseTimeNanos()
  {
    return totalAddResponseTime.get();
  }

  public long getTotalAddResponseTimeMillis()
  {
    return Math.round(totalAddResponseTime.get() / 1000000.0d);
  }



  public double getAverageAddResponseTimeNanos()
  {
    final long totalTime  = totalAddResponseTime.get();
    final long totalCount = numAddResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  public double getAverageAddResponseTimeMillis()
  {
    final long totalTime  = totalAddResponseTime.get();
    final long totalCount = numAddResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1000000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }


  public long getNumBindRequests()
  {
    return numBindRequests.get();
  }


  void incrementNumBindRequests()
  {
    numBindRequests.incrementAndGet();
  }



  public long getNumBindResponses()
  {
    return numBindResponses.get();
  }



  void incrementNumBindResponses(final long responseTime)
  {
    numBindResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalBindResponseTime.addAndGet(responseTime);
    }
  }



  public long getTotalBindResponseTimeNanos()
  {
    return totalBindResponseTime.get();
  }



  public long getTotalBindResponseTimeMillis()
  {
    return Math.round(totalBindResponseTime.get() / 1000000.0d);
  }



  public double getAverageBindResponseTimeNanos()
  {
    final long totalTime  = totalBindResponseTime.get();
    final long totalCount = numBindResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }

  public double getAverageBindResponseTimeMillis()
  {
    final long totalTime  = totalBindResponseTime.get();
    final long totalCount = numBindResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1000000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }


  public long getNumCompareRequests()
  {
    return numCompareRequests.get();
  }




  void incrementNumCompareRequests()
  {
    numCompareRequests.incrementAndGet();
  }


  public long getNumCompareResponses()
  {
    return numCompareResponses.get();
  }


  void incrementNumCompareResponses(final long responseTime)
  {
    numCompareResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalCompareResponseTime.addAndGet(responseTime);
    }
  }

  public long getTotalCompareResponseTimeNanos()
  {
    return totalCompareResponseTime.get();
  }



  public long getTotalCompareResponseTimeMillis()
  {
    return Math.round(totalCompareResponseTime.get() / 1000000.0d);
  }



  public double getAverageCompareResponseTimeNanos()
  {
    final long totalTime  = totalCompareResponseTime.get();
    final long totalCount = numCompareResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }

  public double getAverageCompareResponseTimeMillis()
  {
    final long totalTime  = totalCompareResponseTime.get();
    final long totalCount = numCompareResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1000000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  public long getNumDeleteRequests()
  {
    return numDeleteRequests.get();
  }


  void incrementNumDeleteRequests()
  {
    numDeleteRequests.incrementAndGet();
  }


  public long getNumDeleteResponses()
  {
    return numDeleteResponses.get();
  }


  void incrementNumDeleteResponses(final long responseTime)
  {
    numDeleteResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalDeleteResponseTime.addAndGet(responseTime);
    }
  }



  public long getTotalDeleteResponseTimeNanos()
  {
    return totalDeleteResponseTime.get();
  }



  public long getTotalDeleteResponseTimeMillis()
  {
    return Math.round(totalDeleteResponseTime.get() / 1000000.0d);
  }



  public double getAverageDeleteResponseTimeNanos()
  {
    final long totalTime  = totalDeleteResponseTime.get();
    final long totalCount = numDeleteResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  public double getAverageDeleteResponseTimeMillis()
  {
    final long totalTime  = totalDeleteResponseTime.get();
    final long totalCount = numDeleteResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1000000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  public long getNumExtendedRequests()
  {
    return numExtendedRequests.get();
  }


  void incrementNumExtendedRequests()
  {
    numExtendedRequests.incrementAndGet();
  }




  public long getNumExtendedResponses()
  {
    return numExtendedResponses.get();
  }




  void incrementNumExtendedResponses(final long responseTime)
  {
    numExtendedResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalExtendedResponseTime.addAndGet(responseTime);
    }
  }



  public long getTotalExtendedResponseTimeNanos()
  {
    return totalExtendedResponseTime.get();
  }


  public long getTotalExtendedResponseTimeMillis()
  {
    return Math.round(totalExtendedResponseTime.get() / 1000000.0d);
  }



  public double getAverageExtendedResponseTimeNanos()
  {
    final long totalTime  = totalExtendedResponseTime.get();
    final long totalCount = numExtendedResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }

  public double getAverageExtendedResponseTimeMillis()
  {
    final long totalTime  = totalExtendedResponseTime.get();
    final long totalCount = numExtendedResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1000000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }


  public long getNumModifyRequests()
  {
    return numModifyRequests.get();
  }



  void incrementNumModifyRequests()
  {
    numModifyRequests.incrementAndGet();
  }


  public long getNumModifyResponses()
  {
    return numModifyResponses.get();
  }



  void incrementNumModifyResponses(final long responseTime)
  {
    numModifyResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalModifyResponseTime.addAndGet(responseTime);
    }
  }



  public long getTotalModifyResponseTimeNanos()
  {
    return totalModifyResponseTime.get();
  }



  public long getTotalModifyResponseTimeMillis()
  {
    return Math.round(totalModifyResponseTime.get() / 1000000.0d);
  }




  public double getAverageModifyResponseTimeNanos()
  {
    final long totalTime  = totalModifyResponseTime.get();
    final long totalCount = numModifyResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }

  public double getAverageModifyResponseTimeMillis()
  {
    final long totalTime  = totalModifyResponseTime.get();
    final long totalCount = numModifyResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1000000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }

  public long getNumModifyDNRequests()
  {
    return numModifyDNRequests.get();
  }




  void incrementNumModifyDNRequests()
  {
    numModifyDNRequests.incrementAndGet();
  }



  public long getNumModifyDNResponses()
  {
    return numModifyDNResponses.get();
  }


  void incrementNumModifyDNResponses(final long responseTime)
  {
    numModifyDNResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalModifyDNResponseTime.addAndGet(responseTime);
    }
  }


  public long getTotalModifyDNResponseTimeNanos()
  {
    return totalModifyDNResponseTime.get();
  }




  public long getTotalModifyDNResponseTimeMillis()
  {
    return Math.round(totalModifyDNResponseTime.get() / 1000000.0d);
  }



  public double getAverageModifyDNResponseTimeNanos()
  {
    final long totalTime  = totalModifyDNResponseTime.get();
    final long totalCount = numModifyDNResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }


  public double getAverageModifyDNResponseTimeMillis()
  {
    final long totalTime  = totalModifyDNResponseTime.get();
    final long totalCount = numModifyDNResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1000000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }


  public long getNumSearchRequests()
  {
    return numSearchRequests.get();
  }

  void incrementNumSearchRequests()
  {
    numSearchRequests.incrementAndGet();
  }



  public long getNumSearchEntryResponses()
  {
    return numSearchEntryResponses.get();
  }



  public long getNumSearchReferenceResponses()
  {
    return numSearchReferenceResponses.get();
  }

  public long getNumSearchDoneResponses()
  {
    return numSearchDoneResponses.get();
  }




  void incrementNumSearchResponses(final int numEntries,
                                   final int numReferences,
                                   final long responseTime)
  {
    numSearchEntryResponses.addAndGet(numEntries);
    numSearchReferenceResponses.addAndGet(numReferences);
    numSearchDoneResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalSearchResponseTime.addAndGet(responseTime);
    }
  }



  public long getTotalSearchResponseTimeNanos()
  {
    return totalSearchResponseTime.get();
  }


  public long getTotalSearchResponseTimeMillis()
  {
    return Math.round(totalSearchResponseTime.get() / 1000000.0d);
  }


  public double getAverageSearchResponseTimeNanos()
  {
    final long totalTime  = totalSearchResponseTime.get();
    final long totalCount = numSearchDoneResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  public double getAverageSearchResponseTimeMillis()
  {
    final long totalTime  = totalSearchResponseTime.get();
    final long totalCount = numSearchDoneResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1000000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }


  public long getNumUnbindRequests()
  {
    return numUnbindRequests.get();
  }




  void incrementNumUnbindRequests()
  {
    numUnbindRequests.incrementAndGet();
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
    final long connects          = numConnects.get();
    final long disconnects       = numDisconnects.get();
    final long abandonRequests   = numAbandonRequests.get();
    final long addRequests       = numAddRequests.get();
    final long addResponses      = numAddResponses.get();
    final long addTimes          = totalAddResponseTime.get();
    final long bindRequests      = numBindRequests.get();
    final long bindResponses     = numBindResponses.get();
    final long bindTimes         = totalBindResponseTime.get();
    final long compareRequests   = numCompareRequests.get();
    final long compareResponses  = numCompareResponses.get();
    final long compareTimes      = totalCompareResponseTime.get();
    final long deleteRequests    = numDeleteRequests.get();
    final long deleteResponses   = numDeleteResponses.get();
    final long deleteTimes       = totalDeleteResponseTime.get();
    final long extendedRequests  = numExtendedRequests.get();
    final long extendedResponses = numExtendedResponses.get();
    final long extendedTimes     = totalExtendedResponseTime.get();
    final long modifyRequests    = numModifyRequests.get();
    final long modifyResponses   = numModifyResponses.get();
    final long modifyTimes       = totalModifyResponseTime.get();
    final long modifyDNRequests  = numModifyDNRequests.get();
    final long modifyDNResponses = numModifyDNResponses.get();
    final long modifyDNTimes     = totalModifyDNResponseTime.get();
    final long searchRequests    = numSearchRequests.get();
    final long searchEntries     = numSearchEntryResponses.get();
    final long searchReferences  = numSearchReferenceResponses.get();
    final long searchDone        = numSearchDoneResponses.get();
    final long searchTimes       = totalSearchResponseTime.get();
    final long unbindRequests    = numUnbindRequests.get();

    final DecimalFormat f = new DecimalFormat("0.000");

    buffer.append("LDAPConnectionStatistics(numConnects=");
    buffer.append(connects);
    buffer.append(", numDisconnects=");
    buffer.append(disconnects);

    buffer.append(", numAbandonRequests=");
    buffer.append(abandonRequests);

    buffer.append(", numAddRequests=");
    buffer.append(addRequests);
    buffer.append(", numAddResponses=");
    buffer.append(addResponses);
    buffer.append(", totalAddResponseTimeNanos=");
    buffer.append(addTimes);
    if (addTimes > 0L)
    {
      buffer.append(", averageAddResponseTimeNanos=");
      buffer.append(f.format(1.0d * addResponses / addTimes));
    }

    buffer.append(", numBindRequests=");
    buffer.append(bindRequests);
    buffer.append(", numBindResponses=");
    buffer.append(bindResponses);
    buffer.append(", totalBindResponseTimeNanos=");
    buffer.append(bindTimes);
    if (bindTimes > 0L)
    {
      buffer.append(", averageBindResponseTimeNanos=");
      buffer.append(f.format(1.0d * bindResponses / bindTimes));
    }

    buffer.append(", numCompareRequests=");
    buffer.append(compareRequests);
    buffer.append(", numCompareResponses=");
    buffer.append(compareResponses);
    buffer.append(", totalCompareResponseTimeNanos=");
    buffer.append(compareTimes);
    if (compareTimes > 0L)
    {
      buffer.append(", averageCompareResponseTimeNanos=");
      buffer.append(f.format(1.0d * compareResponses / compareTimes));
    }

    buffer.append(", numDeleteRequests=");
    buffer.append(deleteRequests);
    buffer.append(", numDeleteResponses=");
    buffer.append(deleteResponses);
    buffer.append(", totalDeleteResponseTimeNanos=");
    buffer.append(deleteTimes);
    if (deleteTimes > 0L)
    {
      buffer.append(", averageDeleteResponseTimeNanos=");
      buffer.append(f.format(1.0d * deleteResponses / deleteTimes));
    }

    buffer.append(", numExtendedRequests=");
    buffer.append(extendedRequests);
    buffer.append(", numExtendedResponses=");
    buffer.append(extendedResponses);
    buffer.append(", totalExtendedResponseTimeNanos=");
    buffer.append(extendedTimes);
    if (extendedTimes > 0L)
    {
      buffer.append(", averageExtendedResponseTimeNanos=");
      buffer.append(f.format(1.0d * extendedResponses / extendedTimes));
    }

    buffer.append(", numModifyRequests=");
    buffer.append(modifyRequests);
    buffer.append(", numModifyResponses=");
    buffer.append(modifyResponses);
    buffer.append(", totalModifyResponseTimeNanos=");
    buffer.append(modifyTimes);
    if (modifyTimes > 0L)
    {
      buffer.append(", averageModifyResponseTimeNanos=");
      buffer.append(f.format(1.0d * modifyResponses / modifyTimes));
    }

    buffer.append(", numModifyDNRequests=");
    buffer.append(modifyDNRequests);
    buffer.append(", numModifyDNResponses=");
    buffer.append(modifyDNResponses);
    buffer.append(", totalModifyDNResponseTimeNanos=");
    buffer.append(modifyDNTimes);
    if (modifyDNTimes > 0L)
    {
      buffer.append(", averageModifyDNResponseTimeNanos=");
      buffer.append(f.format(1.0d * modifyDNResponses / modifyDNTimes));
    }

    buffer.append(", numSearchRequests=");
    buffer.append(searchRequests);
    buffer.append(", numSearchEntries=");
    buffer.append(searchEntries);
    buffer.append(", numSearchReferences=");
    buffer.append(searchReferences);
    buffer.append(", numSearchDone=");
    buffer.append(searchDone);
    buffer.append(", totalSearchResponseTimeNanos=");
    buffer.append(searchTimes);
    if (searchTimes > 0L)
    {
      buffer.append(", averageSearchResponseTimeNanos=");
      buffer.append(f.format(1.0d * searchDone / searchTimes));
    }

    buffer.append(", numUnbindRequests=");
    buffer.append(unbindRequests);

    buffer.append(')');
  }
}

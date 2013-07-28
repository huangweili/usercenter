package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class SRVRecordPrioritySet
      implements Serializable
{

  private static final Random SEED_RANDOM = new Random();



  private static final ThreadLocal<Random> RANDOMS = new ThreadLocal<Random>();



  private static final long serialVersionUID = -7722028520625558942L;



  private final long priority;

  private final long totalWeight;

  private final List<SRVRecord> allRecords;

  private final List<SRVRecord> nonzeroWeightRecords;

  private final List<SRVRecord> zeroWeightRecords;


  SRVRecordPrioritySet(final long priority, final List<SRVRecord> records)
  {
    this.priority = priority;

    long w = 0L;

    final ArrayList<SRVRecord> nRecords =
         new ArrayList<SRVRecord>(records.size());
    final ArrayList<SRVRecord> zRecords =
         new ArrayList<SRVRecord>(records.size());

    for (final SRVRecord r : records)
    {
      if (r.getWeight() == 0L)
      {
        zRecords.add(r);
      }
      else
      {
        nRecords.add(r);
        w += r.getWeight();
      }
    }

    totalWeight = w;

    allRecords           = Collections.unmodifiableList(records);
    nonzeroWeightRecords = Collections.unmodifiableList(nRecords);
    zeroWeightRecords    = Collections.unmodifiableList(zRecords);
  }


  long getPriority()
  {
    return priority;
  }


  List<SRVRecord> getOrderedRecords()
  {
    final ArrayList<SRVRecord> records =
         new ArrayList<SRVRecord>(allRecords.size());

    if (! nonzeroWeightRecords.isEmpty())
    {
      if (nonzeroWeightRecords.size() == 1)
      {
        records.addAll(nonzeroWeightRecords);
      }
      else
      {
        Random r = RANDOMS.get();
        if (r == null)
        {
          synchronized (SEED_RANDOM)
          {
            r = new Random(SEED_RANDOM.nextLong());
          }

          RANDOMS.set(r);
        }

        long tw = totalWeight;
        final ArrayList<SRVRecord> rl =
             new ArrayList<SRVRecord>(nonzeroWeightRecords);
        while (! rl.isEmpty())
        {
          long w = ((r.nextLong() & 0x7FFFFFFFFFFFFFFFL) % tw);
          final Iterator<SRVRecord> iterator = rl.iterator();
          while (iterator.hasNext())
          {
            final SRVRecord record = iterator.next();
            if ((w < record.getWeight()) || (! iterator.hasNext()))
            {
              iterator.remove();
              records.add(record);
              tw -= record.getWeight();
              break;
            }
            else
            {
              w -= record.getWeight();
            }
          }
        }
      }
    }

    records.addAll(zeroWeightRecords);
    return records;
  }


  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }


  void toString(final StringBuilder buffer)
  {
    buffer.append("SRVRecordPrioritySet(records={");

    final Iterator<SRVRecord> iterator = allRecords.iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next().toString());
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}

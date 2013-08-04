
package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.ThreadSafety;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;

import static com.hwlcn.ldap.util.Debug.*;



@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FixedRateBarrier
       implements Serializable
{

  private static final long serialVersionUID = -3490156685189909611L;


  private static final long minSleepMillis;

  static
  {


    final List<Long> minSleepMillisMeasurements = new ArrayList<Long>();

    for (int i = 0; i < 11; i++)
    {
      final long timeBefore = System.currentTimeMillis();
      try
      {
        Thread.sleep(1);
      }
      catch (InterruptedException e)
      {
        debugException(e);
      }
      final long sleepMillis = System.currentTimeMillis() - timeBefore;
      minSleepMillisMeasurements.add(sleepMillis);
    }

    Collections.sort(minSleepMillisMeasurements);
    final long medianSleepMillis = minSleepMillisMeasurements.get(
            minSleepMillisMeasurements.size()/2);

    minSleepMillis = Math.max(medianSleepMillis, 1);

    final String message = "Calibrated FixedRateBarrier to use " +
          "minSleepMillis=" + minSleepMillis + ".  " +
          "Minimum sleep measurements = " + minSleepMillisMeasurements;
    debug(Level.INFO, DebugType.OTHER, message);
  }

  private final long intervalDurationNanos;

  private final double millisBetweenIterations;

  private final int perInterval;

  private volatile boolean shutdownRequested = false;

  private long countInThisInterval = 0;
  private long intervalStartNanos = 0;

  private long intervalEndNanos = 0;


  public FixedRateBarrier(final long intervalDurationMs, final int perInterval)
  {
    Validator.ensureTrue(intervalDurationMs > 0,
         "FixedRateBarrier.intervalDurationMs must be at least 1.");
    Validator.ensureTrue(perInterval > 0,
         "FixedRateBarrier.perInterval must be at least 1.");

    this.perInterval = perInterval;

    intervalDurationNanos = 1000L * 1000L * intervalDurationMs;

    millisBetweenIterations = (double)intervalDurationMs/(double)perInterval;
  }



  public synchronized boolean await()
  {
    while (!shutdownRequested)
    {
      final long now = System.nanoTime();

      if ((intervalStartNanos == 0) ||
          (now < intervalStartNanos))
      {
        intervalStartNanos = now;
        intervalEndNanos = intervalStartNanos + intervalDurationNanos;
      }
      else if (now >= intervalEndNanos)
      {
        countInThisInterval = 0;

        if (now < (intervalEndNanos + intervalDurationNanos))
        {

          intervalStartNanos = now;
        }
        else
        {

          intervalStartNanos = intervalEndNanos;
        }
        intervalEndNanos = intervalStartNanos + intervalDurationNanos;
      }

      final long intervalRemaining = intervalEndNanos - now;
      if (intervalRemaining <= 0)
      {

        continue;
      }

      final double intervalFractionRemaining =
           (double) intervalRemaining / intervalDurationNanos;

      final double expectedRemaining = intervalFractionRemaining * perInterval;
      final long actualRemaining = perInterval - countInThisInterval;

      if (actualRemaining >= expectedRemaining)
      {
        countInThisInterval++;
        break;
      }
      else
      {


        final double gapIterations = expectedRemaining - actualRemaining;
        final double remainingMillis =
                millisBetweenIterations * gapIterations;

        if (remainingMillis >= minSleepMillis)
        {
          try
          {
            Thread.sleep((long)remainingMillis);
          }
          catch (InterruptedException e)
          {
            debugException(e);
          }
        }
        else
        {
          Thread.yield();
        }
      }
    }

    return shutdownRequested;
  }


  public void shutdownRequested()
  {
    shutdownRequested = true;
  }


  public boolean isShutdownRequested()
  {
    return shutdownRequested;
  }
}

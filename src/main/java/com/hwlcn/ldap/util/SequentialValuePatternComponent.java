
package com.hwlcn.ldap.util;



import java.text.DecimalFormat;
import java.util.concurrent.atomic.AtomicLong;

final class SequentialValuePatternComponent
      extends ValuePatternComponent
{
  private static final long serialVersionUID = -3553865579642557953L;

  private final AtomicLong nextValue;

  private final long increment;

  private final long lowerBound;

  private final long upperBound;

  private final String formatString;

  private final ThreadLocal<DecimalFormat> decimalFormat;


  SequentialValuePatternComponent(final long lowerBound, final long upperBound,
                                  final long increment,
                                  final String formatString)
  {
    if (lowerBound == upperBound)
    {
      this.lowerBound = lowerBound;
      this.upperBound = upperBound;
      this.increment  = 0L;
    }
    else if (lowerBound > upperBound)
    {
      this.lowerBound = upperBound;
      this.upperBound = lowerBound;

      if (Math.abs(increment) > (lowerBound - upperBound))
      {
        this.increment = 0L;
      }
      else
      {
        this.increment  = -1L * increment;
      }
    }
    else
    {
      this.lowerBound = lowerBound;
      this.upperBound = upperBound;

      if (Math.abs(increment) > (upperBound - lowerBound))
      {
        this.increment = 0L;
      }
      else
      {
        this.increment = increment;
      }
    }

    this.formatString = formatString;
    decimalFormat     = new ThreadLocal<DecimalFormat>();
    nextValue         = new AtomicLong(lowerBound);
  }


  @Override()
  void append(final StringBuilder buffer)
  {
    long value = nextValue.getAndAdd(increment);
    if (value > upperBound)
    {
      if (nextValue.compareAndSet(value+increment, lowerBound))
      {
        value = nextValue.getAndAdd(increment);
      }
      else
      {
        while (true)
        {
          final long v = nextValue.get();
          if ((v < upperBound) || nextValue.compareAndSet(v, lowerBound))
          {
            value = nextValue.getAndAdd(increment);
            break;
          }
        }
      }
    }
    else if (value < lowerBound)
    {
      if (nextValue.compareAndSet(value+increment, upperBound))
      {
        value = nextValue.getAndAdd(increment);
      }
      else
      {
        while (true)
        {
          final long v = nextValue.get();
          if ((v > lowerBound) || nextValue.compareAndSet(v, upperBound))
          {
            value = nextValue.getAndAdd(increment);
            break;
          }
        }
      }
    }

    if (formatString == null)
    {
      buffer.append(value);
    }
    else
    {
      DecimalFormat f = decimalFormat.get();
      if (f == null)
      {
        f = new DecimalFormat(formatString);
        decimalFormat.set(f);
      }

      buffer.append(f.format(value));
    }
  }



  @Override()
  boolean supportsBackReference()
  {
    return true;
  }
}

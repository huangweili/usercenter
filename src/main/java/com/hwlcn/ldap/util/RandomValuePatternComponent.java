
package com.hwlcn.ldap.util;



import java.text.DecimalFormat;
import java.util.Random;


final class RandomValuePatternComponent
      extends ValuePatternComponent
{

  private static final long serialVersionUID = -670528378158953667L;

  private final long lowerBound;

  private final long span;

  private final Random seedRandom;

  private final String formatString;

  private final ThreadLocal<DecimalFormat> decimalFormat;
  private final ThreadLocal<Random> random;


  RandomValuePatternComponent(final long lowerBound, final long upperBound,
                              final long seed, final String formatString)
  {
    if (lowerBound == upperBound)
    {
      this.lowerBound = lowerBound;

      span = 1L;
    }
    else if (lowerBound > upperBound)
    {
      this.lowerBound = upperBound;

      span = lowerBound - upperBound + 1;
    }
    else
    {
      this.lowerBound = lowerBound;

      span = upperBound - lowerBound + 1;
    }

    seedRandom = new Random(seed);
    random     = new ThreadLocal<Random>();

    this.formatString = formatString;
    decimalFormat     = new ThreadLocal<DecimalFormat>();
  }



  @Override()
  void append(final StringBuilder buffer)
  {
    Random r = random.get();
    if (r == null)
    {
      r = new Random(seedRandom.nextLong());
      random.set(r);
    }

    final long value = ((r.nextLong() & 0x7FFFFFFF) % span) + lowerBound;
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

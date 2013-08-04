
package com.hwlcn.ldap.util;



import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Random;

import static com.hwlcn.ldap.util.UtilityMessages.*;


final class HTTPValuePatternComponent
      extends ValuePatternComponent
{

  private static final long serialVersionUID = 8879412445617836376L;


  private final String[] lines;

  private final Random seedRandom;

  private final ThreadLocal<Random> random;



  HTTPValuePatternComponent(final String url, final long seed)
       throws IOException
  {
    seedRandom = new Random(seed);
    random     = new ThreadLocal<Random>();


    final ArrayList<String> lineList = new ArrayList<String>(100);
    final URL parsedURL = new URL(url);
    final HttpURLConnection urlConnection =
         (HttpURLConnection) parsedURL.openConnection();
    final BufferedReader reader = new BufferedReader(new InputStreamReader(
         urlConnection.getInputStream()));

    try
    {
      while (true)
      {
        final String line = reader.readLine();
        if (line == null)
        {
          break;
        }

        lineList.add(line);
      }
    }
    finally
    {
      reader.close();
    }

    if (lineList.isEmpty())
    {
      throw new IOException(ERR_VALUE_PATTERN_COMPONENT_EMPTY_FILE.get());
    }

    lines = new String[lineList.size()];
    lineList.toArray(lines);
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

    buffer.append(lines[r.nextInt(lines.length)]);
  }


  @Override()
  boolean supportsBackReference()
  {
    return true;
  }
}

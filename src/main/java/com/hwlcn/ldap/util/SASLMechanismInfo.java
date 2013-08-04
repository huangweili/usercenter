
package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;

import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SASLMechanismInfo
{
  private final boolean acceptsPassword;

  private final boolean requiresPassword;

  private final List<SASLOption> options;

  private final String description;

  private final String name;


  public SASLMechanismInfo(final String name, final String description,
                           final boolean acceptsPassword,
                           final boolean requiresPassword,
                           final SASLOption... options)
  {
    this.name             = name;
    this.description      = description;
    this.acceptsPassword  = acceptsPassword;
    this.requiresPassword = requiresPassword;

    if ((options == null) || (options.length == 0))
    {
      this.options = Collections.emptyList();
    }
    else
    {
      this.options = Collections.unmodifiableList(Arrays.asList(options));
    }
  }



  public String getName()
  {
    return name;
  }


  public String getDescription()
  {
    return description;
  }



  public boolean acceptsPassword()
  {
    return acceptsPassword;
  }



  public boolean requiresPassword()
  {
    return requiresPassword;
  }


  public List<SASLOption> getOptions()
  {
    return options;
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
    buffer.append("SASLMechanismInfo(name='");
    buffer.append(name);
    buffer.append("', description='");
    buffer.append(description);
    buffer.append("', acceptsPassword=");
    buffer.append(acceptsPassword);
    buffer.append(", requiresPassword=");
    buffer.append(requiresPassword);
    buffer.append(", options={");

    final Iterator<SASLOption> iterator = options.iterator();
    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}

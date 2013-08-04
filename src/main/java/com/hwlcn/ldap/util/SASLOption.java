
package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;

import java.io.Serializable;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SASLOption
       implements Serializable
{

  private static final long serialVersionUID = -683675804002105357L;

  private final boolean isMultiValued;

  private final boolean isRequired;

  private final String description;

  private final String name;



  public SASLOption(final String name, final String description,
                    final boolean isRequired, final boolean isMultiValued)
  {
    this.name          = name;
    this.description   = description;
    this.isRequired    = isRequired;
    this.isMultiValued = isMultiValued;
  }


  public String getName()
  {
    return name;
  }



  public String getDescription()
  {
    return description;
  }



  public boolean isRequired()
  {
    return isRequired;
  }




  public boolean isMultiValued()
  {
    return isMultiValued;
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
    buffer.append("SASLOption(name='");
    buffer.append(name);
    buffer.append("', description='");
    buffer.append(description);
    buffer.append("', isRequired=");
    buffer.append(isRequired);
    buffer.append(", isMultiValued=");
    buffer.append(isMultiValued);
    buffer.append(')');
  }
}

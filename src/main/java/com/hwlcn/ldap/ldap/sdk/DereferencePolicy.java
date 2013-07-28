package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.HashMap;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DereferencePolicy
       implements Serializable
{

  public static final DereferencePolicy NEVER =
       new DereferencePolicy("NEVER", 0);



  public static final DereferencePolicy SEARCHING =
       new DereferencePolicy("SEARCHING", 1);

  public static final DereferencePolicy FINDING =
       new DereferencePolicy("FINDING", 2);


  public static final DereferencePolicy ALWAYS =
       new DereferencePolicy("ALWAYS", 3);



  private static final HashMap<Integer,DereferencePolicy> UNDEFINED_POLICIES =
       new HashMap<Integer,DereferencePolicy>();


  private static final long serialVersionUID = 3722883359911755096L;



  private final int intValue;

  private final String name;



  private DereferencePolicy(final int intValue)
  {
    this.intValue = intValue;

    name = String.valueOf(intValue);
  }


  private DereferencePolicy(final String name, final int intValue)
  {
    this.name     = name;
    this.intValue = intValue;
  }



  public String getName()
  {
    return name;
  }



  public int intValue()
  {
    return intValue;
  }



  public static DereferencePolicy valueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return NEVER;
      case 1:
        return SEARCHING;
      case 2:
        return FINDING;
      case 3:
        return ALWAYS;
      default:
        synchronized (UNDEFINED_POLICIES)
        {
          DereferencePolicy p = UNDEFINED_POLICIES.get(intValue);
          if (p == null)
          {
            p = new DereferencePolicy(intValue);
            UNDEFINED_POLICIES.put(intValue, p);
          }

          return p;
        }
    }
  }



  public static DereferencePolicy[] values()
  {
    return new DereferencePolicy[]
    {
      NEVER,
      SEARCHING,
      FINDING,
      ALWAYS
    };
  }



  @Override()
  public int hashCode()
  {
    return intValue;
  }



  @Override()
  public boolean equals(final Object o)
  {
    if (o == null)
    {
      return false;
    }
    else if (o == this)
    {
      return true;
    }
    else if (o instanceof DereferencePolicy)
    {
      return (intValue == ((DereferencePolicy) o).intValue);
    }
    else
    {
      return false;
    }
  }



  @Override()
  public String toString()
  {
    return name;
  }
}

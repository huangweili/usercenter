package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.HashMap;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ModificationType
       implements Serializable
{
  public static final int ADD_INT_VALUE = 0;

  public static final ModificationType ADD =
       new ModificationType("ADD", ADD_INT_VALUE);

  public static final int DELETE_INT_VALUE = 1;

  public static final ModificationType DELETE =
       new ModificationType("DELETE", DELETE_INT_VALUE);

  public static final int REPLACE_INT_VALUE = 2;

  public static final ModificationType REPLACE =
       new ModificationType("REPLACE", REPLACE_INT_VALUE);

  public static final int INCREMENT_INT_VALUE = 3;

  public static final ModificationType INCREMENT =
       new ModificationType("INCREMENT", INCREMENT_INT_VALUE);


  private static final HashMap<Integer,ModificationType> UNDEFINED_MOD_TYPES =
       new HashMap<Integer,ModificationType>();


  private static final long serialVersionUID = -7863114394728980308L;

  private final int intValue;

  private final String name;


  private ModificationType(final int intValue)
  {
    this.intValue = intValue;

    name = String.valueOf(intValue);
  }


  private ModificationType(final String name, final int intValue)
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

  public static ModificationType valueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return ADD;
      case 1:
        return DELETE;
      case 2:
        return REPLACE;
      case 3:
        return INCREMENT;
      default:
        synchronized (UNDEFINED_MOD_TYPES)
        {
          ModificationType t = UNDEFINED_MOD_TYPES.get(intValue);
          if (t == null)
          {
            t = new ModificationType(intValue);
            UNDEFINED_MOD_TYPES.put(intValue, t);
          }

          return t;
        }
    }
  }

  public static ModificationType definedValueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return ADD;
      case 1:
        return DELETE;
      case 2:
        return REPLACE;
      case 3:
        return INCREMENT;
      default:
        return null;
    }
  }


  public static ModificationType[] values()
  {
    return new ModificationType[]
    {
      ADD,
      DELETE,
      REPLACE,
      INCREMENT
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
    else if (o instanceof ModificationType)
    {
      return (intValue == ((ModificationType) o).intValue);
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

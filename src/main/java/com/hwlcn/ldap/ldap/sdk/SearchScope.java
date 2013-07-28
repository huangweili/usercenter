package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.HashMap;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchScope
       implements Serializable
{
  public static final int BASE_INT_VALUE = 0;

  public static final SearchScope BASE =
       new SearchScope("BASE", BASE_INT_VALUE);

  public static final int ONE_INT_VALUE = 1;

  public static final SearchScope ONE = new SearchScope("ONE", ONE_INT_VALUE);

  public static final int SUB_INT_VALUE = 2;

  public static final SearchScope SUB = new SearchScope("SUB", SUB_INT_VALUE);


  public static final int SUBORDINATE_SUBTREE_INT_VALUE = 3;


  public static final SearchScope SUBORDINATE_SUBTREE =
       new SearchScope("SUBORDINATE_SUBTREE", SUBORDINATE_SUBTREE_INT_VALUE);



  private static final HashMap<Integer,SearchScope> UNDEFINED_SCOPES =
       new HashMap<Integer,SearchScope>();


  private static final long serialVersionUID = 5381929718445793181L;




  private final int intValue;

  private final String name;




  private SearchScope(final int intValue)
  {
    this.intValue = intValue;

    name = String.valueOf(intValue);
  }



  private SearchScope(final String name, final int intValue)
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



  public static SearchScope valueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return BASE;
      case 1:
        return ONE;
      case 2:
        return SUB;
      case 3:
        return SUBORDINATE_SUBTREE;
      default:
        synchronized (UNDEFINED_SCOPES)
        {
          SearchScope s = UNDEFINED_SCOPES.get(intValue);
          if (s == null)
          {
            s = new SearchScope(intValue);
            UNDEFINED_SCOPES.put(intValue, s);
          }

          return s;
        }
    }
  }


  public static SearchScope definedValueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return BASE;
      case 1:
        return ONE;
      case 2:
        return SUB;
      case 3:
        return SUBORDINATE_SUBTREE;
      default:
        return null;
    }
  }


  public static SearchScope[] values()
  {
    return new SearchScope[]
    {
      BASE,
      ONE,
      SUB,
      SUBORDINATE_SUBTREE
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
    else if (o instanceof SearchScope)
    {
      return (intValue == ((SearchScope) o).intValue);
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

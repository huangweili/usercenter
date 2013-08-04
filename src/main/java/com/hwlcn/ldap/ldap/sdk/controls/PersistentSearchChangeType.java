package com.hwlcn.ldap.ldap.sdk.controls;



import java.util.Collection;
import java.util.EnumSet;
import java.util.Set;

import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum PersistentSearchChangeType
{

  ADD("add", 1),

  DELETE("delete", 2),

  MODIFY("modify", 4),

  MODIFY_DN("moddn", 8);

  private final int value;

  private final String name;

  private PersistentSearchChangeType(final String name, final int value)
  {
    this.name  = name;
    this.value = value;
  }

  public String getName()
  {
    return name;
  }

  public int intValue()
  {
    return value;
  }

  public static PersistentSearchChangeType valueOf(final int intValue)
  {
    switch (intValue)
    {
      case 1:
        return ADD;

      case 2:
        return DELETE;

      case 4:
        return MODIFY;

      case 8:
        return MODIFY_DN;

      default:
        return null;
    }
  }

  public static Set<PersistentSearchChangeType> allChangeTypes()
  {
    return EnumSet.allOf(PersistentSearchChangeType.class);
  }

  public static int encodeChangeTypes(
                         final PersistentSearchChangeType... changeTypes)
  {
    int changeTypesValue = 0;

    for (final PersistentSearchChangeType changeType : changeTypes)
    {
      changeTypesValue |= changeType.intValue();
    }

    return changeTypesValue;
  }

  public static int encodeChangeTypes(
       final Collection<PersistentSearchChangeType> changeTypes)
  {
    int changeTypesValue = 0;

    for (final PersistentSearchChangeType changeType : changeTypes)
    {
      changeTypesValue |= changeType.intValue();
    }

    return changeTypesValue;
  }

  public static Set<PersistentSearchChangeType> decodeChangeTypes(
                                                      final int changeTypes)
  {
    final EnumSet<PersistentSearchChangeType> ctSet =
         EnumSet.noneOf(PersistentSearchChangeType.class);

    if ((changeTypes & ADD.intValue()) == ADD.intValue())
    {
      ctSet.add(ADD);
    }

    if ((changeTypes & DELETE.intValue()) == DELETE.intValue())
    {
      ctSet.add(DELETE);
    }

    if ((changeTypes & MODIFY.intValue()) == MODIFY.intValue())
    {
      ctSet.add(MODIFY);
    }

    if ((changeTypes & MODIFY_DN.intValue()) == MODIFY_DN.intValue())
    {
      ctSet.add(MODIFY_DN);
    }

    return ctSet;
  }

  @Override()
  public String toString()
  {
    return name;
  }
}

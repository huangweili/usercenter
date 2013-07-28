package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.concurrent.ConcurrentHashMap;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.StaticUtils.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class CompactAttribute
      implements Serializable
{
  private static final int MAX_CACHED_NAMES = 1000;



  private static final ConcurrentHashMap<String,String> cachedNames =
       new ConcurrentHashMap<String,String>(MAX_CACHED_NAMES);



  private static final long serialVersionUID = 9056952830029621727L;



  private final byte[][] values;

  private final String name;



  CompactAttribute(final Attribute attribute)
  {
    name = internName(attribute.getName());
    values = attribute.getValueByteArrays();
  }



  private static String internName(final String name)
  {
    String s = cachedNames.get(name);
    if (s == null)
    {
      if (cachedNames.size() >= MAX_CACHED_NAMES)
      {
        cachedNames.clear();
      }

      cachedNames.put(name, name);
      s = name;
    }

    return s;
  }



  String getName()
  {
    return name;
  }

  byte[][] getByteValues()
  {
    return values;
  }



  String[] getStringValues()
  {
    final String[] stringValues = new String[values.length];
    for (int i=0; i < values.length; i++)
    {
      stringValues[i] = toUTF8String(values[i]);
    }

    return stringValues;
  }


  Attribute toAttribute()
  {
    return new Attribute(name, values);
  }
}

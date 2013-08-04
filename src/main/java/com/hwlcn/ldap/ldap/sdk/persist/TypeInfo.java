package com.hwlcn.ldap.ldap.sdk.persist;



import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.List;
import java.util.Set;



final class TypeInfo
{
  private final boolean isArray;

  private final boolean isEnum;

  private final boolean isList;

  private final boolean isSet;

  private final boolean isSupported;


  private final Class<?> baseClass;

  private final Class<?> componentType;

  private final Type type;

  TypeInfo(final Type type)
  {
    this.type = type;

    if (type instanceof Class)
    {
      isSupported = true;
      baseClass   = (Class<?>) type;
      isArray     = baseClass.isArray();
      isEnum      = baseClass.isEnum();

      if (isArray)
      {
        componentType = baseClass.getComponentType();
        isList        = false;
        isSet         = false;
      }
      else if (List.class.isAssignableFrom(baseClass))
      {
        componentType = Object.class;
        isList        = true;
        isSet         = false;
      }
      else if (Set.class.isAssignableFrom(baseClass))
      {
        componentType = Object.class;
        isList        = false;
        isSet         = true;
      }
      else
      {
        componentType = null;
        isList        = false;
        isSet         = false;
      }
    }
    else if (type instanceof ParameterizedType)
    {
      final ParameterizedType pt         = (ParameterizedType) type;
      final Type              rawType    = pt.getRawType();
      final Type[]            typeParams = pt.getActualTypeArguments();
      if ((rawType instanceof Class) && (typeParams.length == 1) &&
          (typeParams[0] instanceof Class))
      {
        baseClass     = (Class<?>) rawType;
        componentType = (Class<?>) typeParams[0];

        if (List.class.isAssignableFrom(baseClass))
        {
          isSupported = true;
          isArray     = false;
          isEnum      = false;
          isList      = true;
          isSet       = false;
        }
        else if (Set.class.isAssignableFrom(baseClass))
        {
          isSupported = true;
          isArray     = false;
          isEnum      = false;
          isList      = false;
          isSet       = true;
        }
        else
        {
          isSupported = false;
          isArray     = false;
          isEnum      = false;
          isList      = false;
          isSet       = false;
        }
      }
      else
      {
        isSupported   = false;
        isArray       = false;
        isEnum        = false;
        isList        = false;
        isSet         = false;
        baseClass     = null;
        componentType = null;
      }
    }
    else
    {
      isSupported   = false;
      isArray       = false;
      isEnum        = false;
      isList        = false;
      isSet         = false;
      baseClass     = null;
      componentType = null;
    }
  }


  public Type getType()
  {
    return type;
  }


  public boolean isSupported()
  {
    return isSupported;
  }


  public Class<?> getBaseClass()
  {
    return baseClass;
  }

  public Class<?> getComponentType()
  {
    return componentType;
  }



  public boolean isArray()
  {
    return isArray;
  }


  public boolean isEnum()
  {
    return isEnum;
  }


  public boolean isList()
  {
    return isList;
  }

  public boolean isSet()
  {
    return isSet;
  }


  public boolean isMultiValued()
  {
    return (isArray || isList || isSet);
  }
}

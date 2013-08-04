package com.hwlcn.ldap.ldap.sdk.persist;



import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Type;

import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.schema.AttributeTypeDefinition;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.persist.PersistMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;

@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class ObjectEncoder
       implements Serializable
{

  public abstract boolean supportsType(final Type t);



  public final AttributeTypeDefinition constructAttributeType(final Field f)
         throws LDAPPersistException
  {
    return constructAttributeType(f, DefaultOIDAllocator.getInstance());
  }


  public abstract AttributeTypeDefinition constructAttributeType(final Field f,
                                               final OIDAllocator a)
         throws LDAPPersistException;


  public final AttributeTypeDefinition constructAttributeType(final Method m)
         throws LDAPPersistException
  {
    return constructAttributeType(m, DefaultOIDAllocator.getInstance());
  }


  public abstract AttributeTypeDefinition constructAttributeType(final Method m,
                                               final OIDAllocator a)
         throws LDAPPersistException;


  public abstract boolean supportsMultipleValues(final Field field);



  public abstract boolean supportsMultipleValues(final Method method);


  public abstract Attribute encodeFieldValue(final Field field,
                                             final Object value,
                                             final String name)
         throws LDAPPersistException;


  public abstract Attribute encodeMethodValue(final Method method,
                                              final Object value,
                                              final String name)
         throws LDAPPersistException;



  public abstract void decodeField(final Field field, final Object object,
                                   final Attribute attribute)
         throws LDAPPersistException;


  public void setNull(final Field f, final Object o)
         throws LDAPPersistException
  {
    try
    {
      f.setAccessible(true);

      final Class<?> type = f.getType();
      if (type.equals(Boolean.TYPE))
      {
        f.set(o, Boolean.FALSE);
      }
      else if (type.equals(Byte.TYPE))
      {
        f.set(o, (byte) 0);
      }
      else if (type.equals(Character.TYPE))
      {
        f.set(o, '\u0000');
      }
      else if (type.equals(Double.TYPE))
      {
        f.set(o, 0.0d);
      }
      else if (type.equals(Float.TYPE))
      {
        f.set(o, 0.0f);
      }
      else if (type.equals(Integer.TYPE))
      {
        f.set(o, 0);
      }
      else if (type.equals(Long.TYPE))
      {
        f.set(o, 0L);
      }
      else if (type.equals(Short.TYPE))
      {
        f.set(o, (short) 0);
      }
      else
      {
        f.set(o, null);
      }
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPPersistException(
           ERR_ENCODER_CANNOT_SET_NULL_FIELD_VALUE.get(f.getName(),
                o.getClass().getName(), getExceptionMessage(e)), e);
    }
  }

  public void setNull(final Method m, final Object o)
         throws LDAPPersistException
  {
    try
    {
      m.setAccessible(true);

      final Class<?> type = m.getParameterTypes()[0];
      if (type.equals(Boolean.TYPE))
      {
        m.invoke(o, Boolean.FALSE);
      }
      else if (type.equals(Byte.TYPE))
      {
        m.invoke(o, (byte) 0);
      }
      else if (type.equals(Character.TYPE))
      {
        m.invoke(o, '\u0000');
      }
      else if (type.equals(Double.TYPE))
      {
        m.invoke(o, 0.0d);
      }
      else if (type.equals(Float.TYPE))
      {
        m.invoke(o, 0.0f);
      }
      else if (type.equals(Integer.TYPE))
      {
        m.invoke(o, 0);
      }
      else if (type.equals(Long.TYPE))
      {
        m.invoke(o, 0L);
      }
      else if (type.equals(Short.TYPE))
      {
        m.invoke(o, (short) 0);
      }
      else
      {
        m.invoke(o, type.cast(null));
      }
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPPersistException(
           ERR_ENCODER_CANNOT_SET_NULL_METHOD_VALUE.get(m.getName(),
                o.getClass().getName(), getExceptionMessage(e)), e);
    }
  }


  public abstract void invokeSetter(final Method method, final Object object,
                                    final Attribute attribute)
         throws LDAPPersistException;
}


package com.hwlcn.ldap.ldap.sdk.persist;



import java.io.Serializable;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.List;

import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.persist.PersistMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SetterInfo
       implements Serializable
{

  private static final long serialVersionUID = -1743750276508505946L;


  private final boolean failOnInvalidValue;

  private final boolean failOnTooManyValues;


  private final boolean supportsMultipleValues;

  private final Class<?> containingClass;

  private final Method method;

  private final ObjectEncoder encoder;

  private final String attributeName;


  SetterInfo(final Method m, final Class<?> c)
       throws LDAPPersistException
  {
    ensureNotNull(m, c);

    method = m;
    m.setAccessible(true);

    final LDAPSetter  a = m.getAnnotation(LDAPSetter.class);
    if (a == null)
    {
      throw new LDAPPersistException(ERR_SETTER_INFO_METHOD_NOT_ANNOTATED.get(
           m.getName(), c.getName()));
    }

    final LDAPObject o = c.getAnnotation(LDAPObject.class);
    if (o == null)
    {
      throw new LDAPPersistException(ERR_SETTER_INFO_CLASS_NOT_ANNOTATED.get(
           c.getName()));
    }

    containingClass    = c;
    failOnInvalidValue = a.failOnInvalidValue();

    final Type[] params = m.getGenericParameterTypes();
    if (params.length != 1)
    {
      throw new LDAPPersistException(
           ERR_SETTER_INFO_METHOD_DOES_NOT_TAKE_ONE_ARGUMENT.get(m.getName(),
                c.getName()));
    }

    try
    {
      encoder = a.encoderClass().newInstance();
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPPersistException(ERR_SETTER_INFO_CANNOT_GET_ENCODER.get(
           a.encoderClass().getName(), m.getName(), c.getName(),
           getExceptionMessage(e)), e);
    }

    if (! encoder.supportsType(params[0]))
    {
      throw new LDAPPersistException(
           ERR_SETTER_INFO_ENCODER_UNSUPPORTED_TYPE.get(
                encoder.getClass().getName(), m.getName(), c.getName(),
                String.valueOf(params[0])));
    }

    supportsMultipleValues = encoder.supportsMultipleValues(m);
    if (supportsMultipleValues)
    {
      failOnTooManyValues = false;
    }
    else
    {
      failOnTooManyValues = a.failOnTooManyValues();
    }

    final String attrName = a.attribute();
    if ((attrName == null) || (attrName.length() == 0))
    {
      final String methodName = m.getName();
      if (methodName.startsWith("set") && (methodName.length() >= 4))
      {
        attributeName = toInitialLowerCase(methodName.substring(3));
      }
      else
      {
        throw new LDAPPersistException(ERR_SETTER_INFO_CANNOT_INFER_ATTR.get(
             methodName, c.getName()));
      }
    }
    else
    {
      attributeName = attrName;
    }
  }


  public Method getMethod()
  {
    return method;
  }




  public Class<?> getContainingClass()
  {
    return containingClass;
  }



  public boolean failOnInvalidValue()
  {
    return failOnInvalidValue;
  }



  public boolean failOnTooManyValues()
  {
    return failOnTooManyValues;
  }


  public ObjectEncoder getEncoder()
  {
    return encoder;
  }



  public String getAttributeName()
  {
    return attributeName;
  }



  public boolean supportsMultipleValues()
  {
    return supportsMultipleValues;
  }


  boolean invokeSetter(final Object o, final Entry e,
                       final List<String> failureReasons)
  {
    boolean successful = true;

    final Attribute a = e.getAttribute(attributeName);
    if ((a == null) || (! a.hasValue()))
    {
      try
      {
        encoder.setNull(method, o);
      }
      catch (final LDAPPersistException lpe)
      {
        debugException(lpe);
        successful = false;
        failureReasons.add(lpe.getMessage());
      }

      return successful;
    }

    if (failOnTooManyValues && (a.size() > 1))
    {
      successful = false;
      failureReasons.add(ERR_SETTER_INFO_METHOD_NOT_MULTIVALUED.get(
           method.getName(), a.getName(), containingClass.getName()));
    }

    try
    {
      encoder.invokeSetter(method, o, a);
    }
    catch (LDAPPersistException lpe)
    {
      debugException(lpe);
      if (failOnInvalidValue)
      {
        successful = false;
        failureReasons.add(lpe.getMessage());
      }
    }

    return successful;
  }
}

package com.hwlcn.ldap.ldap.sdk.persist;



import java.io.Serializable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Type;

import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.schema.AttributeTypeDefinition;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.persist.PersistMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetterInfo
       implements Serializable
{

  private static final long serialVersionUID = 1578187843924054389L;

  private final boolean includeInAdd;

  private final boolean includeInModify;
  private final boolean includeInRDN;

  private final Class<?> containingClass;

  private final FilterUsage filterUsage;

  private final Method method;

  private final ObjectEncoder encoder;

  private final String attributeName;

  private final String[] objectClasses;


  GetterInfo(final Method m, final Class<?> c)
       throws LDAPPersistException
  {
    ensureNotNull(m, c);

    method = m;
    m.setAccessible(true);

    final LDAPGetter  a = m.getAnnotation(LDAPGetter.class);
    if (a == null)
    {
      throw new LDAPPersistException(ERR_GETTER_INFO_METHOD_NOT_ANNOTATED.get(
           m.getName(), c.getName()));
    }

    final LDAPObject o = c.getAnnotation(LDAPObject.class);
    if (o == null)
    {
      throw new LDAPPersistException(ERR_GETTER_INFO_CLASS_NOT_ANNOTATED.get(
           c.getName()));
    }

    containingClass = c;
    includeInRDN    = a.inRDN();
    includeInAdd    = (includeInRDN || a.inAdd());
    includeInModify = ((! includeInRDN) && a.inModify());
    filterUsage     = a.filterUsage();

    final int modifiers = m.getModifiers();
    if (Modifier.isStatic(modifiers))
    {
      throw new LDAPPersistException(ERR_GETTER_INFO_METHOD_STATIC.get(
           m.getName(), c.getName()));
    }

    final Type[] params = m.getGenericParameterTypes();
    if (params.length > 0)
    {
      throw new LDAPPersistException(ERR_GETTER_INFO_METHOD_TAKES_ARGUMENTS.get(
           m.getName(), c.getName()));
    }

    try
    {
      encoder = a.encoderClass().newInstance();
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPPersistException(ERR_GETTER_INFO_CANNOT_GET_ENCODER.get(
           a.encoderClass().getName(), m.getName(), c.getName(),
           getExceptionMessage(e)), e);
    }

    if (! encoder.supportsType(m.getGenericReturnType()))
    {
      throw new LDAPPersistException(
           ERR_GETTER_INFO_ENCODER_UNSUPPORTED_TYPE.get(
                encoder.getClass().getName(), m.getName(), c.getName(),
                String.valueOf(m.getGenericReturnType())));
    }

    final String structuralClass;
    if (o.structuralClass().length() == 0)
    {
      structuralClass = getUnqualifiedClassName(c);
    }
    else
    {
      structuralClass = o.structuralClass();
    }

    final String[] ocs = a.objectClass();
    if ((ocs == null) || (ocs.length == 0))
    {
      objectClasses = new String[] { structuralClass };
    }
    else
    {
      objectClasses = ocs;
    }

    for (final String s : objectClasses)
    {
      if (! s.equalsIgnoreCase(structuralClass))
      {
        boolean found = false;
        for (final String oc : o.auxiliaryClass())
        {
          if (s.equalsIgnoreCase(oc))
          {
            found = true;
            break;
          }
        }

        if (! found)
        {
          throw new LDAPPersistException(ERR_GETTER_INFO_INVALID_OC.get(
               m.getName(), c.getName(), s));
        }
      }
    }

    final String attrName = a.attribute();
    if ((attrName == null) || (attrName.length() == 0))
    {
      final String methodName = m.getName();
      if (methodName.startsWith("get") && (methodName.length() >= 4))
      {
        attributeName = toInitialLowerCase(methodName.substring(3));
      }
      else
      {
        throw new LDAPPersistException(ERR_GETTER_INFO_CANNOT_INFER_ATTR.get(
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




  public boolean includeInAdd()
  {
    return includeInAdd;
  }



  public boolean includeInModify()
  {
    return includeInModify;
  }



  public boolean includeInRDN()
  {
    return includeInRDN;
  }


  public FilterUsage getFilterUsage()
  {
    return filterUsage;
  }



  public ObjectEncoder getEncoder()
  {
    return encoder;
  }




  public String getAttributeName()
  {
    return attributeName;
  }

  public String[] getObjectClasses()
  {
    return objectClasses;
  }



  AttributeTypeDefinition constructAttributeType()
       throws LDAPPersistException
  {
    return constructAttributeType(DefaultOIDAllocator.getInstance());
  }



  AttributeTypeDefinition constructAttributeType(final OIDAllocator a)
       throws LDAPPersistException
  {
    return encoder.constructAttributeType(method, a);
  }



  Attribute encode(final Object o)
            throws LDAPPersistException
  {
    try
    {
      final Object methodValue = method.invoke(o);
      if (methodValue == null)
      {
        return null;
      }

      return encoder.encodeMethodValue(method, methodValue, attributeName);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPPersistException(ERR_GETTER_INFO_CANNOT_ENCODE.get(
           method.getName(), containingClass.getName(), getExceptionMessage(e)),
           e);
    }
  }
}

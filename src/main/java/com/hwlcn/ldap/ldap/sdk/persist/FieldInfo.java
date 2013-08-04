package com.hwlcn.ldap.ldap.sdk.persist;



import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.List;

import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.Entry;
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
public final class FieldInfo
       implements Serializable
{

  private static final long serialVersionUID = -5715642176677596417L;


  private final boolean failOnInvalidValue;


  private final boolean failOnTooManyValues;

  private final boolean includeInAdd;

  private final boolean includeInModify;

  private final boolean includeInRDN;

  private final boolean isRequiredForDecode;

  private final boolean isRequiredForEncode;

  private final boolean lazilyLoad;

  private final boolean supportsMultipleValues;

  private final Class<?> containingClass;

  private final Field field;

  private final FilterUsage filterUsage;

  private final ObjectEncoder encoder;

  private final String attributeName;

  private final String[] defaultDecodeValues;

  private final String[] defaultEncodeValues;

  private final String[] objectClasses;


  FieldInfo(final Field f, final Class<?> c)
       throws LDAPPersistException
  {
    ensureNotNull(f, c);

    field = f;
    f.setAccessible(true);

    final LDAPField  a = f.getAnnotation(LDAPField.class);
    if (a == null)
    {
      throw new LDAPPersistException(ERR_FIELD_INFO_FIELD_NOT_ANNOTATED.get(
           f.getName(), c.getName()));
    }

    final LDAPObject o = c.getAnnotation(LDAPObject.class);
    if (o == null)
    {
      throw new LDAPPersistException(ERR_FIELD_INFO_CLASS_NOT_ANNOTATED.get(
           c.getName()));
    }

    containingClass     = c;
    failOnInvalidValue  = a.failOnInvalidValue();
    includeInRDN        = a.inRDN();
    includeInAdd        = (includeInRDN || a.inAdd());
    includeInModify     = ((! includeInRDN) && a.inModify());
    filterUsage         = a.filterUsage();
    lazilyLoad          = a.lazilyLoad();
    isRequiredForDecode = (a.requiredForDecode() && (! lazilyLoad));
    isRequiredForEncode = (includeInRDN || a.requiredForEncode());
    defaultDecodeValues = a.defaultDecodeValue();
    defaultEncodeValues = a.defaultEncodeValue();

    if (lazilyLoad)
    {
      if (defaultDecodeValues.length > 0)
      {
        throw new LDAPPersistException(
             ERR_FIELD_INFO_LAZY_WITH_DEFAULT_DECODE.get(f.getName(),
                  c.getName()));
      }

      if (defaultEncodeValues.length > 0)
      {
        throw new LDAPPersistException(
             ERR_FIELD_INFO_LAZY_WITH_DEFAULT_ENCODE.get(f.getName(),
                  c.getName()));
      }

      if (includeInRDN)
      {
        throw new LDAPPersistException(ERR_FIELD_INFO_LAZY_IN_RDN.get(
             f.getName(), c.getName()));
      }
    }

    final int modifiers = f.getModifiers();
    if (Modifier.isFinal(modifiers))
    {
      throw new LDAPPersistException(ERR_FIELD_INFO_FIELD_FINAL.get(
           f.getName(), c.getName()));
    }

    if (Modifier.isStatic(modifiers))
    {
      throw new LDAPPersistException(ERR_FIELD_INFO_FIELD_STATIC.get(
           f.getName(), c.getName()));
    }

    try
    {
      encoder = a.encoderClass().newInstance();
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPPersistException(ERR_FIELD_INFO_CANNOT_GET_ENCODER.get(
           a.encoderClass().getName(), f.getName(), c.getName(),
           getExceptionMessage(e)), e);
    }

    if (! encoder.supportsType(f.getGenericType()))
    {
      throw new LDAPPersistException(
           ERR_FIELD_INFO_ENCODER_UNSUPPORTED_TYPE.get(
                encoder.getClass().getName(), f.getName(), c.getName(),
                f.getGenericType()));
    }

    supportsMultipleValues = encoder.supportsMultipleValues(f);
    if (supportsMultipleValues)
    {
      failOnTooManyValues = false;
    }
    else
    {
      failOnTooManyValues = a.failOnTooManyValues();
      if (defaultDecodeValues.length > 1)
      {
        throw new LDAPPersistException(
             ERR_FIELD_INFO_UNSUPPORTED_MULTIPLE_DEFAULT_DECODE_VALUES.get(
                  f.getName(), c.getName()));
      }

      if (defaultEncodeValues.length > 1)
      {
        throw new LDAPPersistException(
             ERR_FIELD_INFO_UNSUPPORTED_MULTIPLE_DEFAULT_ENCODE_VALUES.get(
                  f.getName(), c.getName()));
      }
    }

    final String attrName = a.attribute();
    if ((attrName == null) || (attrName.length() == 0))
    {
      attributeName = f.getName();
    }
    else
    {
      attributeName = attrName;
    }

    final StringBuilder invalidReason = new StringBuilder();
    if (! PersistUtils.isValidLDAPName(attributeName, true, invalidReason))
    {
      throw new LDAPPersistException(ERR_FIELD_INFO_INVALID_ATTR_NAME.get(
           f.getName(), c.getName(), invalidReason.toString()));
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
          throw new LDAPPersistException(ERR_FIELD_INFO_INVALID_OC.get(
               f.getName(), c.getName(), s));
        }
      }
    }
  }



  public Field getField()
  {
    return field;
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



  public boolean isRequiredForDecode()
  {
    return isRequiredForDecode;
  }


  public boolean isRequiredForEncode()
  {
    return isRequiredForEncode;
  }


  public boolean lazilyLoad()
  {
    return lazilyLoad;
  }


  public ObjectEncoder getEncoder()
  {
    return encoder;
  }

  public String getAttributeName()
  {
    return attributeName;
  }


  public String[] getDefaultDecodeValues()
  {
    return defaultDecodeValues;
  }



  public String[] getDefaultEncodeValues()
  {
    return defaultEncodeValues;
  }


  public String[] getObjectClasses()
  {
    return objectClasses;
  }


  public boolean supportsMultipleValues()
  {
    return supportsMultipleValues;
  }


  AttributeTypeDefinition constructAttributeType()
       throws LDAPPersistException
  {
    return constructAttributeType(DefaultOIDAllocator.getInstance());
  }


  AttributeTypeDefinition constructAttributeType(final OIDAllocator a)
       throws LDAPPersistException
  {
    return encoder.constructAttributeType(field, a);
  }


  Attribute encode(final Object o, final boolean ignoreRequiredFlag)
            throws LDAPPersistException
  {
    try
    {
      final Object fieldValue = field.get(o);
      if (fieldValue == null)
      {
        if (defaultEncodeValues.length > 0)
        {
          return new Attribute(attributeName, defaultEncodeValues);
        }

        if (isRequiredForEncode && (! ignoreRequiredFlag))
        {
          throw new LDAPPersistException(
               ERR_FIELD_INFO_MISSING_REQUIRED_VALUE.get(field.getName(),
                    containingClass.getName()));
        }

        return null;
      }

      return encoder.encodeFieldValue(field, fieldValue, attributeName);
    }
    catch (LDAPPersistException lpe)
    {
      debugException(lpe);
      throw lpe;
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPPersistException(ERR_FIELD_INFO_CANNOT_ENCODE.get(
           field.getName(), containingClass.getName(), getExceptionMessage(e)),
           e);
    }
  }


  boolean decode(final Object o, final Entry e,
                 final List<String> failureReasons)
  {
    boolean successful = true;

    Attribute a = e.getAttribute(attributeName);
    if ((a == null) || (! a.hasValue()))
    {
      if (defaultDecodeValues.length > 0)
      {
        a = new Attribute(attributeName, defaultDecodeValues);
      }
      else
      {
        if (isRequiredForDecode)
        {
          successful = false;
          failureReasons.add(ERR_FIELD_INFO_MISSING_REQUIRED_ATTRIBUTE.get(
               containingClass.getName(), e.getDN(), attributeName,
               field.getName()));
        }

        try
        {
          encoder.setNull(field, o);
        }
        catch (final LDAPPersistException lpe)
        {
          debugException(lpe);
          successful = false;
          failureReasons.add(lpe.getMessage());
        }

        return successful;
      }
    }

    if (failOnTooManyValues && (a.size() > 1))
    {
      successful = false;
      failureReasons.add(ERR_FIELD_INFO_FIELD_NOT_MULTIVALUED.get(a.getName(),
           field.getName(), containingClass.getName()));
    }

    try
    {
      encoder.decodeField(field, o, a);
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

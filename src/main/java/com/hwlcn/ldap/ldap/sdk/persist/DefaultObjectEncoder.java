
package com.hwlcn.ldap.ldap.sdk.persist;



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.hwlcn.ldap.ldap.matchingrules.MatchingRule;
import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.DN;
import com.hwlcn.ldap.ldap.sdk.Filter;
import com.hwlcn.ldap.ldap.sdk.LDAPURL;
import com.hwlcn.ldap.ldap.sdk.RDN;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.schema.AttributeTypeDefinition;
import com.hwlcn.ldap.ldap.sdk.schema.AttributeUsage;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.persist.PersistMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DefaultObjectEncoder
       extends ObjectEncoder
{

  private static final long serialVersionUID = -4566874784628920022L;


  public DefaultObjectEncoder()
  {
    super();
  }

  @Override()
  public boolean supportsType(final Type t)
  {
    final TypeInfo typeInfo = new TypeInfo(t);
    if (! typeInfo.isSupported())
    {
      return false;
    }

    final Class<?> baseClass = typeInfo.getBaseClass();

    if (supportsTypeInternal(baseClass))
    {
      return true;
    }

    final Class<?> componentType = typeInfo.getComponentType();
    if (componentType == null)
    {
      return false;
    }

    if (typeInfo.isArray())
    {
      return supportsTypeInternal(componentType);
    }

    if (typeInfo.isList())
    {
      return (isSupportedListType(baseClass) &&
           supportsTypeInternal(componentType));
    }

    if (typeInfo.isSet())
    {
      return (isSupportedSetType(baseClass) &&
           supportsTypeInternal(componentType));
    }

    return false;
  }


  private static boolean supportsTypeInternal(final Class<?> c)
  {
    if (c.equals(AtomicInteger.class) ||
        c.equals(AtomicLong.class) ||
        c.equals(BigDecimal.class) ||
        c.equals(BigInteger.class) ||
        c.equals(Boolean.class) ||
        c.equals(Boolean.TYPE) ||
        c.equals(Date.class) ||
        c.equals(DN.class) ||
        c.equals(Double.class) ||
        c.equals(Double.TYPE) ||
        c.equals(Filter.class) ||
        c.equals(Float.class) ||
        c.equals(Float.TYPE) ||
        c.equals(Integer.class) ||
        c.equals(Integer.TYPE) ||
        c.equals(LDAPURL.class) ||
        c.equals(Long.class) ||
        c.equals(Long.TYPE) ||
        c.equals(RDN.class) ||
        c.equals(Short.class) ||
        c.equals(Short.TYPE) ||
        c.equals(String.class) ||
        c.equals(StringBuffer.class) ||
        c.equals(StringBuilder.class) ||
        c.equals(URI.class) ||
        c.equals(URL.class) ||
        c.equals(UUID.class))
    {
      return true;
    }

    if (c.isArray())
    {
      final Class<?> t = c.getComponentType();
      if (t.equals(Byte.TYPE) ||
          t.equals(Character.TYPE))
      {
        return true;
      }
    }

    if (c.isEnum())
    {
      return true;
    }

    if (Serializable.class.isAssignableFrom(c))
    {
      return (! (c.isArray() || Collection.class.isAssignableFrom(c)));
    }

    return false;
  }



  private static boolean isSupportedListType(final Class<?> t)
  {
    return (t.equals(List.class) ||
            t.equals(ArrayList.class) ||
            t.equals(LinkedList.class) ||
            t.equals(CopyOnWriteArrayList.class));
  }



  @SuppressWarnings("rawtypes")
  private static List<?> createList(final Class<?> t, final int size)
  {
    if (t.equals(List.class) || t.equals(ArrayList.class))
    {
      return new ArrayList(size);
    }
    else if (t.equals(LinkedList.class))
    {
      return new LinkedList();
    }
    else if (t.equals(CopyOnWriteArrayList.class))
    {
      return new CopyOnWriteArrayList();
    }

    return null;
  }



  private static boolean isSupportedSetType(final Class<?> t)
  {
    return (t.equals(Set.class) ||
            t.equals(HashSet.class) ||
            t.equals(LinkedHashSet.class) ||
            t.equals(TreeSet.class) ||
            t.equals(CopyOnWriteArraySet.class));
  }



  @SuppressWarnings("rawtypes")
  private static Set<?> createSet(final Class<?> t, final int size)
  {
    if (t.equals(Set.class) || t.equals(LinkedHashSet.class))
    {
      return new LinkedHashSet(size);
    }
    else if (t.equals(HashSet.class))
    {
      return new HashSet(size);
    }
    else if (t.equals(TreeSet.class))
    {
      return new TreeSet();
    }
    else if (t.equals(CopyOnWriteArraySet.class))
    {
      return new CopyOnWriteArraySet();
    }

    return null;
  }


  @Override()
  public AttributeTypeDefinition constructAttributeType(final Field f,
                                      final OIDAllocator a)
         throws LDAPPersistException
  {
    final LDAPField at = f.getAnnotation(LDAPField.class);

    final String attrName;
    if (at.attribute().length() == 0)
    {
      attrName = f.getName();
    }
    else
    {
      attrName = at.attribute();
    }

    final String oid = a.allocateAttributeTypeOID(attrName);

    final TypeInfo typeInfo = new TypeInfo(f.getGenericType());
    if (! typeInfo.isSupported())
    {
      throw new LDAPPersistException(ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
           String.valueOf(typeInfo.getType())));
    }

    final boolean isSingleValued = (! supportsMultipleValues(typeInfo));

    final String syntaxOID;
    if (isSingleValued)
    {
      syntaxOID = getSyntaxOID(typeInfo.getBaseClass());
    }
    else
    {
      syntaxOID = getSyntaxOID(typeInfo.getComponentType());
    }

    final MatchingRule mr = MatchingRule.selectMatchingRuleForSyntax(syntaxOID);
    return new AttributeTypeDefinition(oid, new String[] { attrName }, null,
         false, null, mr.getEqualityMatchingRuleNameOrOID(),
         mr.getOrderingMatchingRuleNameOrOID(),
         mr.getSubstringMatchingRuleNameOrOID(), syntaxOID, isSingleValued,
         false, false, AttributeUsage.USER_APPLICATIONS, null);
  }



  @Override()
  public AttributeTypeDefinition constructAttributeType(final Method m,
                                      final OIDAllocator a)
         throws LDAPPersistException
  {
    final LDAPGetter at = m.getAnnotation(LDAPGetter.class);

    final String attrName;
    if (at.attribute().length() == 0)
    {
      attrName = toInitialLowerCase(m.getName().substring(3));
    }
    else
    {
      attrName = at.attribute();
    }

    final String oid = a.allocateAttributeTypeOID(attrName);

    final TypeInfo typeInfo = new TypeInfo(m.getGenericReturnType());
    if (! typeInfo.isSupported())
    {
      throw new LDAPPersistException(ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
           String.valueOf(typeInfo.getType())));
    }

    final boolean isSingleValued = (! supportsMultipleValues(typeInfo));

    final String syntaxOID;
    if (isSingleValued)
    {
      syntaxOID = getSyntaxOID(typeInfo.getBaseClass());
    }
    else
    {
      syntaxOID = getSyntaxOID(typeInfo.getComponentType());
    }

    return new AttributeTypeDefinition(oid, new String[] { attrName }, null,
         false, null, null, null, null, syntaxOID, isSingleValued, false, false,
         AttributeUsage.USER_APPLICATIONS, null);
  }




  private static String getSyntaxOID(final Class<?> t)
  {
    if (t.equals(BigDecimal.class) ||
        t.equals(Double.class) ||
        t.equals(Double.TYPE) ||
        t.equals(Float.class) ||
        t.equals(Float.TYPE) ||
        t.equals(String.class) ||
        t.equals(StringBuffer.class) ||
        t.equals(StringBuilder.class) ||
        t.equals(URI.class) ||
        t.equals(URL.class) ||
        t.equals(Filter.class) ||
        t.equals(LDAPURL.class))
    {
      return "1.3.6.1.4.1.1466.115.121.1.15";
    }
    else if (t.equals(AtomicInteger.class) ||
        t.equals(AtomicLong.class) ||
        t.equals(BigInteger.class) ||
        t.equals(Integer.class) ||
        t.equals(Integer.TYPE) ||
        t.equals(Long.class) ||
        t.equals(Long.TYPE) ||
        t.equals(Short.class) ||
        t.equals(Short.TYPE))
    {
      return "1.3.6.1.4.1.1466.115.121.1.27";
    }
    else if (t.equals(UUID.class))
    {
      return "1.3.6.1.4.1.1466.115.121.1.15";
    }
    else if (t.equals(DN.class) ||
             t.equals(RDN.class))
    {
      return "1.3.6.1.4.1.1466.115.121.1.12";
    }
    else if (t.equals(Boolean.class) ||
             t.equals(Boolean.TYPE))
    {
      return "1.3.6.1.4.1.1466.115.121.1.7";
    }
    else if (t.equals(Date.class))
    {
      return "1.3.6.1.4.1.1466.115.121.1.24";
    }
    else if (t.isArray())
    {
      final Class<?> ct = t.getComponentType();
      if (ct.equals(Byte.TYPE))
      {
        return "1.3.6.1.4.1.1466.115.121.1.40";
      }
      else if (ct.equals(Character.TYPE))
      {
        return "1.3.6.1.4.1.1466.115.121.1.15";
      }
    }
    else if (t.isEnum())
    {
      return "1.3.6.1.4.1.1466.115.121.1.15";
    }
    else if (Serializable.class.isAssignableFrom(t))
    {
      return "1.3.6.1.4.1.1466.115.121.1.40";
    }

    return null;
  }

  @Override()
  public boolean supportsMultipleValues(final Field field)
  {
    return supportsMultipleValues(new TypeInfo(field.getGenericType()));
  }


  @Override()
  public boolean supportsMultipleValues(final Method method)
  {
    final Type[] paramTypes = method.getGenericParameterTypes();
    if (paramTypes.length != 1)
    {
      return false;
    }

    return supportsMultipleValues(new TypeInfo(paramTypes[0]));
  }



  private static boolean supportsMultipleValues(final TypeInfo t)
  {
    if (t.isArray())
    {
      final Class<?> componentType = t.getComponentType();
      return (! (componentType.equals(Byte.TYPE) ||
                 componentType.equals(Character.TYPE)));
    }
    else
    {
      return t.isMultiValued();
    }
  }


  @Override()
  public Attribute encodeFieldValue(final Field field, final Object value,
                                    final String name)
         throws LDAPPersistException
  {
    return encodeValue(field.getGenericType(), value, name);
  }


  @Override()
  public Attribute encodeMethodValue(final Method method, final Object value,
                                     final String name)
         throws LDAPPersistException
  {
    return encodeValue(method.getGenericReturnType(), value, name);
  }




  private static Attribute encodeValue(final Type type, final Object value,
                                       final String name)
         throws LDAPPersistException
  {
    final TypeInfo typeInfo = new TypeInfo(type);

    final Class<?> c = typeInfo.getBaseClass();
    if (c.equals(AtomicInteger.class) ||
        c.equals(AtomicLong.class) ||
        c.equals(BigDecimal.class) ||
        c.equals(BigInteger.class) ||
        c.equals(Double.class) ||
        c.equals(Double.TYPE) ||
        c.equals(Float.class) ||
        c.equals(Float.TYPE) ||
        c.equals(Integer.class) ||
        c.equals(Integer.TYPE) ||
        c.equals(Long.class) ||
        c.equals(Long.TYPE) ||
        c.equals(Short.class) ||
        c.equals(Short.TYPE) ||
        c.equals(String.class) ||
        c.equals(StringBuffer.class) ||
        c.equals(StringBuilder.class) ||
        c.equals(UUID.class) ||
        c.equals(DN.class) ||
        c.equals(Filter.class) ||
        c.equals(LDAPURL.class) ||
        c.equals(RDN.class))
    {
      return new Attribute(name, String.valueOf(value));
    }
    else if (value instanceof URI)
    {
      final URI uri = (URI) value;
      return new Attribute(name, uri.toASCIIString());
    }
    else if (value instanceof URL)
    {
      final URL url = (URL) value;
      return new Attribute(name, url.toExternalForm());
    }
    else if (value instanceof byte[])
    {
      return new Attribute(name, (byte[]) value);
    }
    else if (value instanceof char[])
    {
      return new Attribute(name, new String((char[]) value));
    }
    else if (c.equals(Boolean.class) || c.equals(Boolean.TYPE))
    {
      final Boolean b = (Boolean) value;
      if (b)
      {
        return new Attribute(name, "TRUE");
      }
      else
      {
        return new Attribute(name, "FALSE");
      }
    }
    else if (c.equals(Date.class))
    {
      final Date d = (Date) value;
      return new Attribute(name, encodeGeneralizedTime(d));
    }
    else if (typeInfo.isArray())
    {
      return encodeArray(typeInfo.getComponentType(), value, name);
    }
    else if (typeInfo.isEnum())
    {
      final Enum<?> e = (Enum<?>) value;
      return new Attribute(name, e.name());
    }
    else if (Collection.class.isAssignableFrom(c))
    {
      return encodeCollection(typeInfo.getComponentType(),
           (Collection<?>) value, name);
    }
    else if (Serializable.class.isAssignableFrom(c))
    {
      try
      {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(value);
        oos.close();
        return new Attribute(name, baos.toByteArray());
      }
      catch (final Exception e)
      {
        debugException(e);
        throw new LDAPPersistException(
             ERR_DEFAULT_ENCODER_CANNOT_SERIALIZE.get(name,
                  getExceptionMessage(e)),
             e);
      }
    }

    throw new LDAPPersistException(ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
         String.valueOf(type)));
  }



  private static Attribute encodeArray(final Class<?> arrayType,
                                       final Object arrayObject,
                                       final String attributeName)
          throws LDAPPersistException
  {
    final ASN1OctetString[] values =
         new ASN1OctetString[Array.getLength(arrayObject)];
    for (int i=0; i < values.length; i++)
    {
      final Object o = Array.get(arrayObject, i);
      if (arrayType.equals(AtomicInteger.class) ||
          arrayType.equals(AtomicLong.class) ||
          arrayType.equals(BigDecimal.class) ||
          arrayType.equals(BigInteger.class) ||
          arrayType.equals(Double.class) ||
          arrayType.equals(Double.TYPE) ||
          arrayType.equals(Float.class) ||
          arrayType.equals(Float.TYPE) ||
          arrayType.equals(Integer.class) ||
          arrayType.equals(Integer.TYPE) ||
          arrayType.equals(Long.class) ||
          arrayType.equals(Long.TYPE) ||
          arrayType.equals(Short.class) ||
          arrayType.equals(Short.TYPE) ||
          arrayType.equals(String.class) ||
          arrayType.equals(StringBuffer.class) ||
          arrayType.equals(StringBuilder.class) ||
          arrayType.equals(UUID.class) ||
          arrayType.equals(DN.class) ||
          arrayType.equals(Filter.class) ||
          arrayType.equals(LDAPURL.class) ||
          arrayType.equals(RDN.class))
      {
        values[i] = new ASN1OctetString(String.valueOf(o));
      }
      else if (arrayType.equals(URI.class))
      {
        final URI uri = (URI) o;
        values[i] = new ASN1OctetString(uri.toASCIIString());
      }
      else if (arrayType.equals(URL.class))
      {
        final URL url = (URL) o;
        values[i] = new ASN1OctetString(url.toExternalForm());
      }
      else if (o instanceof byte[])
      {
        values[i] = new ASN1OctetString((byte[]) o);
      }
      else if (o instanceof char[])
      {
        values[i] = new ASN1OctetString(new String((char[]) o));
      }
      else if (arrayType.equals(Boolean.class) ||
               arrayType.equals(Boolean.TYPE))
      {
        final Boolean b = (Boolean) o;
        if (b)
        {
          values[i] = new ASN1OctetString("TRUE");
        }
        else
        {
          values[i] = new ASN1OctetString("FALSE");
        }
      }
      else if (arrayType.equals(Date.class))
      {
        final Date d = (Date) o;
        values[i] = new ASN1OctetString(encodeGeneralizedTime(d));
      }
      else if (arrayType.isEnum())
      {
        final Enum<?> e = (Enum<?>) o;
        values[i] = new ASN1OctetString(e.name());
      }
      else if (Serializable.class.isAssignableFrom(arrayType))
      {
        try
        {
          final ByteArrayOutputStream baos = new ByteArrayOutputStream();
          final ObjectOutputStream oos = new ObjectOutputStream(baos);
          oos.writeObject(o);
          oos.close();
          values[i] = new ASN1OctetString(baos.toByteArray());
        }
        catch (final Exception e)
        {
          debugException(e);
          throw new LDAPPersistException(
               ERR_DEFAULT_ENCODER_CANNOT_SERIALIZE.get(attributeName,
                    getExceptionMessage(e)),
               e);
        }
      }
      else
      {
        throw new LDAPPersistException(ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
             arrayType.getName()));
      }
    }

    return new Attribute(attributeName,
         CaseIgnoreStringMatchingRule.getInstance(), values);
  }




  private static Attribute encodeCollection(final Class<?> genericType,
                                            final Collection<?> collection,
                                            final String attributeName)
          throws LDAPPersistException
  {
    final ASN1OctetString[] values = new ASN1OctetString[collection.size()];

    int i=0;
    for (final Object o : collection)
    {
      if (genericType.equals(AtomicInteger.class) ||
          genericType.equals(AtomicLong.class) ||
          genericType.equals(BigDecimal.class) ||
          genericType.equals(BigInteger.class) ||
          genericType.equals(Double.class) ||
          genericType.equals(Double.TYPE) ||
          genericType.equals(Float.class) ||
          genericType.equals(Float.TYPE) ||
          genericType.equals(Integer.class) ||
          genericType.equals(Integer.TYPE) ||
          genericType.equals(Long.class) ||
          genericType.equals(Long.TYPE) ||
          genericType.equals(Short.class) ||
          genericType.equals(Short.TYPE) ||
          genericType.equals(String.class) ||
          genericType.equals(StringBuffer.class) ||
          genericType.equals(StringBuilder.class) ||
          genericType.equals(UUID.class) ||
          genericType.equals(DN.class) ||
          genericType.equals(Filter.class) ||
          genericType.equals(LDAPURL.class) ||
          genericType.equals(RDN.class))
      {
        values[i] = new ASN1OctetString(String.valueOf(o));
      }
      else if (genericType.equals(URI.class))
      {
        final URI uri = (URI) o;
        values[i] = new ASN1OctetString(uri.toASCIIString());
      }
      else if (genericType.equals(URL.class))
      {
        final URL url = (URL) o;
        values[i] = new ASN1OctetString(url.toExternalForm());
      }
      else if (o instanceof byte[])
      {
        values[i] = new ASN1OctetString((byte[]) o);
      }
      else if (o instanceof char[])
      {
        values[i] = new ASN1OctetString(new String((char[]) o));
      }
      else if (genericType.equals(Boolean.class) ||
               genericType.equals(Boolean.TYPE))
      {
        final Boolean b = (Boolean) o;
        if (b)
        {
          values[i] = new ASN1OctetString("TRUE");
        }
        else
        {
          values[i] = new ASN1OctetString("FALSE");
        }
      }
      else if (genericType.equals(Date.class))
      {
        final Date d = (Date) o;
        values[i] = new ASN1OctetString(encodeGeneralizedTime(d));
      }
      else if (genericType.isEnum())
      {
        final Enum<?> e = (Enum<?>) o;
        values[i] = new ASN1OctetString(e.name());
      }
      else if (Serializable.class.isAssignableFrom(genericType))
      {
        try
        {
          final ByteArrayOutputStream baos = new ByteArrayOutputStream();
          final ObjectOutputStream oos = new ObjectOutputStream(baos);
          oos.writeObject(o);
          oos.close();
          values[i] = new ASN1OctetString(baos.toByteArray());
        }
        catch (final Exception e)
        {
          debugException(e);
          throw new LDAPPersistException(
               ERR_DEFAULT_ENCODER_CANNOT_SERIALIZE.get(attributeName,
                    getExceptionMessage(e)),
               e);
        }
      }
      else
      {
        throw new LDAPPersistException(ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
             genericType.getName()));
      }

      i++;
    }

    return new Attribute(attributeName,
         CaseIgnoreStringMatchingRule.getInstance(), values);
  }


  @Override()
  public void decodeField(final Field field, final Object object,
                          final Attribute attribute)
         throws LDAPPersistException
  {
    field.setAccessible(true);
    final TypeInfo typeInfo = new TypeInfo(field.getGenericType());

    try
    {
      final Class<?> baseClass = typeInfo.getBaseClass();
      final Object newValue = getValue(baseClass, attribute, 0);
      if (newValue != null)
      {
        field.set(object, newValue);
        return;
      }

      if (typeInfo.isArray())
      {
        final Class<?> componentType = typeInfo.getComponentType();
        final ASN1OctetString[] values = attribute.getRawValues();
        final Object arrayObject =
             Array.newInstance(componentType, values.length);
        for (int i=0; i < values.length; i++)
        {
          final Object o = getValue(componentType, attribute, i);
          if (o == null)
          {
            throw new LDAPPersistException(
                 ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
                      componentType.getName()));
          }
          Array.set(arrayObject, i, o);
        }

        field.set(object, arrayObject);
        return;
      }
      else if (typeInfo.isList() && isSupportedListType(baseClass))
      {
        final Class<?> componentType = typeInfo.getComponentType();
        if (componentType == null)
        {
          throw new LDAPPersistException(
               ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(baseClass.getName()));
        }

        final ASN1OctetString[] values = attribute.getRawValues();
        final List<?> l = createList(baseClass, values.length);
        for (int i=0; i < values.length; i++)
        {
          final Object o = getValue(componentType, attribute, i);
          if (o == null)
          {
            throw new LDAPPersistException(
                 ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
                      componentType.getName()));
          }

          invokeAdd(l, o);
        }

        field.set(object, l);
        return;
      }
      else if (typeInfo.isSet() && isSupportedSetType(baseClass))
      {
        final Class<?> componentType = typeInfo.getComponentType();
        if (componentType == null)
        {
          throw new LDAPPersistException(
               ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(baseClass.getName()));
        }

        final ASN1OctetString[] values = attribute.getRawValues();
        final Set<?> l = createSet(baseClass, values.length);
        for (int i=0; i < values.length; i++)
        {
          final Object o = getValue(componentType, attribute, i);
          if (o == null)
          {
            throw new LDAPPersistException(
                 ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
                      componentType.getName()));
          }

          invokeAdd(l, o);
        }

        field.set(object, l);
        return;
      }

      throw new LDAPPersistException(ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
           baseClass.getName()));
    }
    catch (LDAPPersistException lpe)
    {
      debugException(lpe);
      throw lpe;
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPPersistException(getExceptionMessage(e), e);
    }
  }



  @Override()
  public void invokeSetter(final Method method, final Object object,
                           final Attribute attribute)
         throws LDAPPersistException
  {
    final TypeInfo typeInfo =
         new TypeInfo(method.getGenericParameterTypes()[0]);
    final Class<?> baseClass = typeInfo.getBaseClass();
    method.setAccessible(true);

    try
    {
      final Object newValue = getValue(baseClass, attribute, 0);
      if (newValue != null)
      {
        method.invoke(object, newValue);
        return;
      }

      if (typeInfo.isArray())
      {
        final Class<?> componentType = typeInfo.getComponentType();
        final ASN1OctetString[] values = attribute.getRawValues();
        final Object arrayObject =
             Array.newInstance(componentType, values.length);
        for (int i=0; i < values.length; i++)
        {
          final Object o = getValue(componentType, attribute, i);
          if (o == null)
          {
            throw new LDAPPersistException(
                 ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
                      componentType.getName()));
          }
          Array.set(arrayObject, i, o);
        }

        method.invoke(object, arrayObject);
        return;
      }
      else if (typeInfo.isList() && isSupportedListType(baseClass))
      {
        final Class<?> componentType = typeInfo.getComponentType();
        if (componentType == null)
        {
          throw new LDAPPersistException(
               ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(baseClass.getName()));
        }

        final ASN1OctetString[] values = attribute.getRawValues();
        final List<?> l = createList(baseClass, values.length);
        for (int i=0; i < values.length; i++)
        {
          final Object o = getValue(componentType, attribute, i);
          if (o == null)
          {
            throw new LDAPPersistException(
                 ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
                      componentType.getName()));
          }

          invokeAdd(l, o);
        }

        method.invoke(object, l);
        return;
      }
      else if (typeInfo.isSet() && isSupportedSetType(baseClass))
      {
        final Class<?> componentType = typeInfo.getComponentType();
        if (componentType == null)
        {
          throw new LDAPPersistException(
               ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(baseClass.getName()));
        }

        final ASN1OctetString[] values = attribute.getRawValues();
        final Set<?> s = createSet(baseClass, values.length);
        for (int i=0; i < values.length; i++)
        {
          final Object o = getValue(componentType, attribute, i);
          if (o == null)
          {
            throw new LDAPPersistException(
                 ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
                      componentType.getName()));
          }

          invokeAdd(s, o);
        }

        method.invoke(object, s);
        return;
      }

      throw new LDAPPersistException(ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
           baseClass.getName()));
    }
    catch (LDAPPersistException lpe)
    {
      debugException(lpe);
      throw lpe;
    }
    catch (Throwable t)
    {
      debugException(t);

      if (t instanceof InvocationTargetException)
      {
        t = ((InvocationTargetException) t).getTargetException();
      }

      throw new LDAPPersistException(getExceptionMessage(t), t);
    }
  }



  @SuppressWarnings("unchecked")
  private static Object getValue(final Class<?> t, final Attribute a,
                                 final int p)
          throws LDAPPersistException
  {
    final ASN1OctetString v = a.getRawValues()[p];

    if (t.equals(AtomicInteger.class))
    {
      return new AtomicInteger(Integer.valueOf(v.stringValue()));
    }
    else if (t.equals(AtomicLong.class))
    {
      return new AtomicLong(Long.valueOf(v.stringValue()));
    }
    else if (t.equals(BigDecimal.class))
    {
      return new BigDecimal(v.stringValue());
    }
    else if (t.equals(BigInteger.class))
    {
      return new BigInteger(v.stringValue());
    }
    else if (t.equals(Double.class) || t.equals(Double.TYPE))
    {
      return Double.valueOf(v.stringValue());
    }
    else if (t.equals(Float.class) || t.equals(Float.TYPE))
    {
      return Float.valueOf(v.stringValue());
    }
    else if (t.equals(Integer.class) || t.equals(Integer.TYPE))
    {
      return Integer.valueOf(v.stringValue());
    }
    else if (t.equals(Long.class) || t.equals(Long.TYPE))
    {
      return Long.valueOf(v.stringValue());
    }
    else if (t.equals(Short.class) || t.equals(Short.TYPE))
    {
      return Short.valueOf(v.stringValue());
    }
    else if (t.equals(String.class))
    {
      return String.valueOf(v.stringValue());
    }
    else if (t.equals(StringBuffer.class))
    {
      return new StringBuffer(v.stringValue());
    }
    else if (t.equals(StringBuilder.class))
    {
      return new StringBuilder(v.stringValue());
    }
    else if (t.equals(URI.class))
    {
      try
      {
        return new URI(v.stringValue());
      }
      catch (final Exception e)
      {
        debugException(e);
        throw new LDAPPersistException(
             ERR_DEFAULT_ENCODER_VALUE_INVALID_URI.get(v.stringValue(),
                  getExceptionMessage(e)), e);
      }
    }
    else if (t.equals(URL.class))
    {
      try
      {
        return new URL(v.stringValue());
      }
      catch (final Exception e)
      {
        debugException(e);
        throw new LDAPPersistException(
             ERR_DEFAULT_ENCODER_VALUE_INVALID_URL.get(v.stringValue(),
                  getExceptionMessage(e)), e);
      }
    }
    else if (t.equals(UUID.class))
    {
      try
      {
        return UUID.fromString(v.stringValue());
      }
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPPersistException(
             ERR_DEFAULT_ENCODER_VALUE_INVALID_UUID.get(v.stringValue(),
                  getExceptionMessage(e)), e);
      }
    }
    else if (t.equals(DN.class))
    {
      try
      {
        return new DN(v.stringValue());
      }
      catch (LDAPException le)
      {
        debugException(le);
        throw new LDAPPersistException(le.getMessage(), le);
      }
    }
    else if (t.equals(Filter.class))
    {
      try
      {
        return Filter.create(v.stringValue());
      }
      catch (LDAPException le)
      {
        debugException(le);
        throw new LDAPPersistException(le.getMessage(), le);
      }
    }
    else if (t.equals(LDAPURL.class))
    {
      try
      {
        return new LDAPURL(v.stringValue());
      }
      catch (LDAPException le)
      {
        debugException(le);
        throw new LDAPPersistException(le.getMessage(), le);
      }
    }
    else if (t.equals(RDN.class))
    {
      try
      {
        return new RDN(v.stringValue());
      }
      catch (LDAPException le)
      {
        debugException(le);
        throw new LDAPPersistException(le.getMessage(), le);
      }
    }
    else if (t.equals(Boolean.class) || t.equals(Boolean.TYPE))
    {
      final String s = v.stringValue();
      if (s.equalsIgnoreCase("TRUE"))
      {
        return Boolean.TRUE;
      }
      else if (s.equalsIgnoreCase("FALSE"))
      {
        return Boolean.FALSE;
      }
      else
      {
        throw new LDAPPersistException(
             ERR_DEFAULT_ENCODER_VALUE_INVALID_BOOLEAN.get(s));
      }
    }
    else if (t.equals(Date.class))
    {
      try
      {
        return decodeGeneralizedTime(v.stringValue());
      }
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPPersistException(
             ERR_DEFAULT_ENCODER_VALUE_INVALID_DATE.get(v.stringValue(),
                  e.getMessage()), e);
      }
    }
    else if (t.isArray())
    {
      final Class<?> componentType = t.getComponentType();
      if (componentType.equals(Byte.TYPE))
      {
        return v.getValue();
      }
      else if (componentType.equals(Character.TYPE))
      {
        return v.stringValue().toCharArray();
      }
    }
    else if (t.isEnum())
    {
      try
      {
        final Class<? extends Enum> enumClass = (Class<? extends Enum>) t;
        return Enum.valueOf(enumClass, v.stringValue());
      }
      catch (final Exception e)
      {
        debugException(e);
        throw new LDAPPersistException(
             ERR_DEFAULT_ENCODER_VALUE_INVALID_ENUM.get(v.stringValue(),
                  getExceptionMessage(e)), e);
      }
    }
    else if (Serializable.class.isAssignableFrom(t))
    {
      // We shouldn't attempt to work on arrays/collections themselves.  Return
      // null and then we'll work on each element.
      if (t.isArray() || Collection.class.isAssignableFrom(t))
      {
        return null;
      }

      try
      {
        final ByteArrayInputStream bais =
             new ByteArrayInputStream(v.getValue());
        final ObjectInputStream ois = new ObjectInputStream(bais);
        final Object o = ois.readObject();
        ois.close();
        return o;
      }
      catch (final Exception e)
      {
        debugException(e);
        throw new LDAPPersistException(
             ERR_DEFAULT_ENCODER_CANNOT_DESERIALIZE.get(a.getName(),
                  getExceptionMessage(e)),
             e);
      }
    }

    return null;
  }



  private static void invokeAdd(final Object l, final Object o)
          throws LDAPPersistException
  {
    final Class<?> c = l.getClass();

    for (final Method m : c.getMethods())
    {
      if (m.getName().equals("add") &&
          (m.getGenericParameterTypes().length == 1))
      {
        try
        {
          m.invoke(l, o);
          return;
        }
        catch (final Exception e)
        {
          debugException(e);
          throw new LDAPPersistException(
               ERR_DEFAULT_ENCODER_CANNOT_ADD.get(getExceptionMessage(e)), e);
        }
      }
    }

    throw new LDAPPersistException(
         ERR_DEFAULT_ENCODER_CANNOT_FIND_ADD_METHOD.get());
  }
}

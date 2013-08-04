package com.hwlcn.ldap.ldap.sdk.schema;



import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;

import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.schema.SchemaMessages.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ObjectClassDefinition
       extends SchemaElement
{
  private static final long serialVersionUID = -3024333376249332728L;

  private final boolean isObsolete;

  private final Map<String,String[]> extensions;

  private final ObjectClassType objectClassType;

  private final String description;

  private final String objectClassString;

  private final String oid;

  private final String[] names;

  private final String[] optionalAttributes;

  private final String[] requiredAttributes;

  private final String[] superiorClasses;


  public ObjectClassDefinition(final String s)
         throws LDAPException
  {
    ensureNotNull(s);

    objectClassString = s.trim();

    final int length = objectClassString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_OC_DECODE_EMPTY.get());
    }
    else if (objectClassString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_OC_DECODE_NO_OPENING_PAREN.get(
                                   objectClassString));
    }

    int pos = skipSpaces(objectClassString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(objectClassString, pos, length, buffer);
    oid = buffer.toString();

    final ArrayList<String>    nameList = new ArrayList<String>(1);
    final ArrayList<String>    supList  = new ArrayList<String>(1);
    final ArrayList<String>    reqAttrs = new ArrayList<String>();
    final ArrayList<String>    optAttrs = new ArrayList<String>();
    final Map<String,String[]> exts     = new LinkedHashMap<String,String[]>();
    Boolean                    obsolete = null;
    ObjectClassType            ocType   = null;
    String                     descr    = null;

    while (true)
    {

      pos = skipSpaces(objectClassString, pos, length);

      final int tokenStartPos = pos;
      while ((pos < length) && (objectClassString.charAt(pos) != ' '))
      {
        pos++;
      }

      String token = objectClassString.substring(tokenStartPos, pos);
      if ((token.length() > 1) && (token.endsWith(")")))
      {
        token = token.substring(0, token.length() - 1);
        pos--;
      }

      final String lowerToken = toLowerCase(token);
      if (lowerToken.equals(")"))
      {
        if (pos < length)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_CLOSE_NOT_AT_END.get(
                                       objectClassString));
        }
        break;
      }
      else if (lowerToken.equals("name"))
      {
        if (nameList.isEmpty())
        {
          pos = skipSpaces(objectClassString, pos, length);
          pos = readQDStrings(objectClassString, pos, length, nameList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_ELEMENTS.get(
                                       objectClassString, "NAME"));
        }
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(objectClassString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(objectClassString, pos, length, buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_ELEMENTS.get(
                                       objectClassString, "DESC"));
        }
      }
      else if (lowerToken.equals("obsolete"))
      {
        if (obsolete == null)
        {
          obsolete = true;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_ELEMENTS.get(
                                       objectClassString, "OBSOLETE"));
        }
      }
      else if (lowerToken.equals("sup"))
      {
        if (supList.isEmpty())
        {
          pos = skipSpaces(objectClassString, pos, length);
          pos = readOIDs(objectClassString, pos, length, supList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_ELEMENTS.get(
                                       objectClassString, "SUP"));
        }
      }
      else if (lowerToken.equals("abstract"))
      {
        if (ocType == null)
        {
          ocType = ObjectClassType.ABSTRACT;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_OC_TYPES.get(
                                       objectClassString));
        }
      }
      else if (lowerToken.equals("structural"))
      {
        if (ocType == null)
        {
          ocType = ObjectClassType.STRUCTURAL;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_OC_TYPES.get(
                                       objectClassString));
        }
      }
      else if (lowerToken.equals("auxiliary"))
      {
        if (ocType == null)
        {
          ocType = ObjectClassType.AUXILIARY;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_OC_TYPES.get(
                                       objectClassString));
        }
      }
      else if (lowerToken.equals("must"))
      {
        if (reqAttrs.isEmpty())
        {
          pos = skipSpaces(objectClassString, pos, length);
          pos = readOIDs(objectClassString, pos, length, reqAttrs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_ELEMENTS.get(
                                       objectClassString, "MUST"));
        }
      }
      else if (lowerToken.equals("may"))
      {
        if (optAttrs.isEmpty())
        {
          pos = skipSpaces(objectClassString, pos, length);
          pos = readOIDs(objectClassString, pos, length, optAttrs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_MULTIPLE_ELEMENTS.get(
                                       objectClassString, "MAY"));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(objectClassString, pos, length);

        final ArrayList<String> valueList = new ArrayList<String>();
        pos = readQDStrings(objectClassString, pos, length, valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_OC_DECODE_DUP_EXT.get(objectClassString,
                                                            token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_OC_DECODE_UNEXPECTED_TOKEN.get(
                                     objectClassString, token));
      }
    }

    description = descr;

    names = new String[nameList.size()];
    nameList.toArray(names);

    superiorClasses = new String[supList.size()];
    supList.toArray(superiorClasses);

    requiredAttributes = new String[reqAttrs.size()];
    reqAttrs.toArray(requiredAttributes);

    optionalAttributes = new String[optAttrs.size()];
    optAttrs.toArray(optionalAttributes);

    isObsolete = (obsolete != null);

    objectClassType = ocType;

    extensions = Collections.unmodifiableMap(exts);
  }

  public ObjectClassDefinition(final String oid, final String[] names,
                               final String description,
                               final boolean isObsolete,
                               final String[] superiorClasses,
                               final ObjectClassType objectClassType,
                               final String[] requiredAttributes,
                               final String[] optionalAttributes,
                               final Map<String,String[]> extensions)
  {
    ensureNotNull(oid);

    this.oid             = oid;
    this.isObsolete      = isObsolete;
    this.description     = description;
    this.objectClassType = objectClassType;

    if (names == null)
    {
      this.names = NO_STRINGS;
    }
    else
    {
      this.names = names;
    }

    if (superiorClasses == null)
    {
      this.superiorClasses = NO_STRINGS;
    }
    else
    {
      this.superiorClasses = superiorClasses;
    }

    if (requiredAttributes == null)
    {
      this.requiredAttributes = NO_STRINGS;
    }
    else
    {
      this.requiredAttributes = requiredAttributes;
    }

    if (optionalAttributes == null)
    {
      this.optionalAttributes = NO_STRINGS;
    }
    else
    {
      this.optionalAttributes = optionalAttributes;
    }

    if (extensions == null)
    {
      this.extensions = Collections.emptyMap();
    }
    else
    {
      this.extensions = Collections.unmodifiableMap(extensions);
    }

    final StringBuilder buffer = new StringBuilder();
    createDefinitionString(buffer);
    objectClassString = buffer.toString();
  }

  private void createDefinitionString(final StringBuilder buffer)
  {
    buffer.append("( ");
    buffer.append(oid);

    if (names.length == 1)
    {
      buffer.append(" NAME '");
      buffer.append(names[0]);
      buffer.append('\'');
    }
    else if (names.length > 1)
    {
      buffer.append(" NAME (");
      for (final String name : names)
      {
        buffer.append(" '");
        buffer.append(name);
        buffer.append('\'');
      }
      buffer.append(" )");
    }

    if (description != null)
    {
      buffer.append(" DESC '");
      encodeValue(description, buffer);
      buffer.append('\'');
    }

    if (isObsolete)
    {
      buffer.append(" OBSOLETE");
    }

    if (superiorClasses.length == 1)
    {
      buffer.append(" SUP ");
      buffer.append(superiorClasses[0]);
    }
    else if (superiorClasses.length > 1)
    {
      buffer.append(" SUP (");
      for (int i=0; i < superiorClasses.length; i++)
      {
        if (i > 0)
        {
          buffer.append(" $ ");
        }
        else
        {
          buffer.append(' ');
        }
        buffer.append(superiorClasses[i]);
      }
      buffer.append(" )");
    }

    if (objectClassType != null)
    {
      buffer.append(' ');
      buffer.append(objectClassType.getName());
    }

    if (requiredAttributes.length == 1)
    {
      buffer.append(" MUST ");
      buffer.append(requiredAttributes[0]);
    }
    else if (requiredAttributes.length > 1)
    {
      buffer.append(" MUST (");
      for (int i=0; i < requiredAttributes.length; i++)
      {
        if (i >0)
        {
          buffer.append(" $ ");
        }
        else
        {
          buffer.append(' ');
        }
        buffer.append(requiredAttributes[i]);
      }
      buffer.append(" )");
    }

    if (optionalAttributes.length == 1)
    {
      buffer.append(" MAY ");
      buffer.append(optionalAttributes[0]);
    }
    else if (optionalAttributes.length > 1)
    {
      buffer.append(" MAY (");
      for (int i=0; i < optionalAttributes.length; i++)
      {
        if (i > 0)
        {
          buffer.append(" $ ");
        }
        else
        {
          buffer.append(' ');
        }
        buffer.append(optionalAttributes[i]);
      }
      buffer.append(" )");
    }

    for (final Map.Entry<String,String[]> e : extensions.entrySet())
    {
      final String   name   = e.getKey();
      final String[] values = e.getValue();
      if (values.length == 1)
      {
        buffer.append(' ');
        buffer.append(name);
        buffer.append(" '");
        encodeValue(values[0], buffer);
        buffer.append('\'');
      }
      else
      {
        buffer.append(' ');
        buffer.append(name);
        buffer.append(" (");
        for (final String value : values)
        {
          buffer.append(" '");
          encodeValue(value, buffer);
          buffer.append('\'');
        }
        buffer.append(" )");
      }
    }

    buffer.append(" )");
  }


  public String getOID()
  {
    return oid;
  }


  public String[] getNames()
  {
    return names;
  }



  public String getNameOrOID()
  {
    if (names.length == 0)
    {
      return oid;
    }
    else
    {
      return names[0];
    }
  }

  public boolean hasNameOrOID(final String s)
  {
    for (final String name : names)
    {
      if (s.equalsIgnoreCase(name))
      {
        return true;
      }
    }

    return s.equalsIgnoreCase(oid);
  }


  public String getDescription()
  {
    return description;
  }


  public boolean isObsolete()
  {
    return isObsolete;
  }

  public String[] getSuperiorClasses()
  {
    return superiorClasses;
  }


  public Set<ObjectClassDefinition> getSuperiorClasses(final Schema schema,
                                                       final boolean recursive)
  {
    final LinkedHashSet<ObjectClassDefinition> ocSet =
         new LinkedHashSet<ObjectClassDefinition>();
    for (final String s : superiorClasses)
    {
      final ObjectClassDefinition d = schema.getObjectClass(s);
      if (d != null)
      {
        ocSet.add(d);
        if (recursive)
        {
          getSuperiorClasses(schema, d, ocSet);
        }
      }
    }

    return Collections.unmodifiableSet(ocSet);
  }

  private static void getSuperiorClasses(final Schema schema,
                                         final ObjectClassDefinition oc,
                                         final Set<ObjectClassDefinition> ocSet)
  {
    for (final String s : oc.superiorClasses)
    {
      final ObjectClassDefinition d = schema.getObjectClass(s);
      if (d != null)
      {
        ocSet.add(d);
        getSuperiorClasses(schema, d, ocSet);
      }
    }
  }

  public ObjectClassType getObjectClassType()
  {
    return objectClassType;
  }


  public ObjectClassType getObjectClassType(final Schema schema)
  {
    if (objectClassType != null)
    {
      return objectClassType;
    }

    for (final String ocName : superiorClasses)
    {
      final ObjectClassDefinition d = schema.getObjectClass(ocName);
      if (d != null)
      {
        return d.getObjectClassType(schema);
      }
    }

    return ObjectClassType.STRUCTURAL;
  }

  public String[] getRequiredAttributes()
  {
    return requiredAttributes;
  }


  public Set<AttributeTypeDefinition> getRequiredAttributes(final Schema schema,
                                           final boolean includeSuperiorClasses)
  {
    final HashSet<AttributeTypeDefinition> attrSet =
         new HashSet<AttributeTypeDefinition>();
    for (final String s : requiredAttributes)
    {
      final AttributeTypeDefinition d = schema.getAttributeType(s);
      if (d != null)
      {
        attrSet.add(d);
      }
    }

    if (includeSuperiorClasses)
    {
      for (final String s : superiorClasses)
      {
        final ObjectClassDefinition d = schema.getObjectClass(s);
        if (d != null)
        {
          getSuperiorRequiredAttributes(schema, d, attrSet);
        }
      }
    }

    return Collections.unmodifiableSet(attrSet);
  }

  private static void getSuperiorRequiredAttributes(final Schema schema,
                           final ObjectClassDefinition oc,
                           final Set<AttributeTypeDefinition> attrSet)
  {
    for (final String s : oc.requiredAttributes)
    {
      final AttributeTypeDefinition d = schema.getAttributeType(s);
      if (d != null)
      {
        attrSet.add(d);
      }
    }

    for (final String s : oc.superiorClasses)
    {
      final ObjectClassDefinition d = schema.getObjectClass(s);
      getSuperiorRequiredAttributes(schema, d, attrSet);
    }
  }

  public String[] getOptionalAttributes()
  {
    return optionalAttributes;
  }


  public Set<AttributeTypeDefinition> getOptionalAttributes(final Schema schema,
                                           final boolean includeSuperiorClasses)
  {
    final HashSet<AttributeTypeDefinition> attrSet =
         new HashSet<AttributeTypeDefinition>();
    for (final String s : optionalAttributes)
    {
      final AttributeTypeDefinition d = schema.getAttributeType(s);
      if (d != null)
      {
        attrSet.add(d);
      }
    }

    if (includeSuperiorClasses)
    {
      final Set<AttributeTypeDefinition> requiredAttrs =
           getRequiredAttributes(schema, true);
      for (final AttributeTypeDefinition d : requiredAttrs)
      {
        attrSet.remove(d);
      }

      for (final String s : superiorClasses)
      {
        final ObjectClassDefinition d = schema.getObjectClass(s);
        if (d != null)
        {
          getSuperiorOptionalAttributes(schema, d, attrSet, requiredAttrs);
        }
      }
    }

    return Collections.unmodifiableSet(attrSet);
  }

  private static void getSuperiorOptionalAttributes(final Schema schema,
                           final ObjectClassDefinition oc,
                           final Set<AttributeTypeDefinition> attrSet,
                           final Set<AttributeTypeDefinition> requiredSet)
  {
    for (final String s : oc.optionalAttributes)
    {
      final AttributeTypeDefinition d = schema.getAttributeType(s);
      if ((d != null) && (! requiredSet.contains(d)))
      {
        attrSet.add(d);
      }
    }

    for (final String s : oc.superiorClasses)
    {
      final ObjectClassDefinition d = schema.getObjectClass(s);
      getSuperiorOptionalAttributes(schema, d, attrSet, requiredSet);
    }
  }


  public Map<String,String[]> getExtensions()
  {
    return extensions;
  }

  @Override()
  public int hashCode()
  {
    return oid.hashCode();
  }

  @Override()
  public boolean equals(final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof ObjectClassDefinition))
    {
      return false;
    }

    final ObjectClassDefinition d = (ObjectClassDefinition) o;
    return (oid.equals(d.oid) &&
         stringsEqualIgnoreCaseOrderIndependent(names, d.names) &&
         stringsEqualIgnoreCaseOrderIndependent(requiredAttributes,
              d.requiredAttributes) &&
         stringsEqualIgnoreCaseOrderIndependent(optionalAttributes,
              d.optionalAttributes) &&
         stringsEqualIgnoreCaseOrderIndependent(superiorClasses,
              d.superiorClasses) &&
         bothNullOrEqual(objectClassType, d.objectClassType) &&
         bothNullOrEqualIgnoreCase(description, d.description) &&
         (isObsolete == d.isObsolete) &&
         extensionsEqual(extensions, d.extensions));
  }


  @Override()
  public String toString()
  {
    return objectClassString;
  }
}

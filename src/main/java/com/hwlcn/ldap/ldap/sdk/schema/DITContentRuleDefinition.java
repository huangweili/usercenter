package com.hwlcn.ldap.ldap.sdk.schema;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.LinkedHashMap;

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
public final class DITContentRuleDefinition
       extends SchemaElement
{

  private static final long serialVersionUID = 3224440505307817586L;

  private final boolean isObsolete;

  private final Map<String,String[]> extensions;

  private final String description;

  private final String ditContentRuleString;

  private final String oid;

  private final String[] auxiliaryClasses;

  private final String[] names;

  private final String[] optionalAttributes;

  private final String[] prohibitedAttributes;

  private final String[] requiredAttributes;

  public DITContentRuleDefinition(final String s)
         throws LDAPException
  {
    ensureNotNull(s);

    ditContentRuleString = s.trim();

    final int length = ditContentRuleString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_DCR_DECODE_EMPTY.get());
    }
    else if (ditContentRuleString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_DCR_DECODE_NO_OPENING_PAREN.get(
                                   ditContentRuleString));
    }


    int pos = skipSpaces(ditContentRuleString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(ditContentRuleString, pos, length, buffer);
    oid = buffer.toString();

    final ArrayList<String>    nameList = new ArrayList<String>(1);
    final ArrayList<String>    reqAttrs = new ArrayList<String>();
    final ArrayList<String>    optAttrs = new ArrayList<String>();
    final ArrayList<String>    notAttrs = new ArrayList<String>();
    final ArrayList<String>    auxOCs   = new ArrayList<String>();
    final Map<String,String[]> exts     = new LinkedHashMap<String,String[]>();
    Boolean obsolete = null;
    String  descr    = null;

    while (true)
    {
      pos = skipSpaces(ditContentRuleString, pos, length);

      final int tokenStartPos = pos;
      while ((pos < length) && (ditContentRuleString.charAt(pos) != ' '))
      {
        pos++;
      }

      String token = ditContentRuleString.substring(tokenStartPos, pos);
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
                                  ERR_DCR_DECODE_CLOSE_NOT_AT_END.get(
                                       ditContentRuleString));
        }
        break;
      }
      else if (lowerToken.equals("name"))
      {
        if (nameList.isEmpty())
        {
          pos = skipSpaces(ditContentRuleString, pos, length);
          pos = readQDStrings(ditContentRuleString, pos, length, nameList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DCR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditContentRuleString, "NAME"));
        }
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(ditContentRuleString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(ditContentRuleString, pos, length, buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DCR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditContentRuleString, "DESC"));
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
                                  ERR_DCR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditContentRuleString, "OBSOLETE"));
        }
      }
      else if (lowerToken.equals("aux"))
      {
        if (auxOCs.isEmpty())
        {
          pos = skipSpaces(ditContentRuleString, pos, length);
          pos = readOIDs(ditContentRuleString, pos, length, auxOCs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DCR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditContentRuleString, "AUX"));
        }
      }
      else if (lowerToken.equals("must"))
      {
        if (reqAttrs.isEmpty())
        {
          pos = skipSpaces(ditContentRuleString, pos, length);
          pos = readOIDs(ditContentRuleString, pos, length, reqAttrs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DCR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditContentRuleString, "MUST"));
        }
      }
      else if (lowerToken.equals("may"))
      {
        if (optAttrs.isEmpty())
        {
          pos = skipSpaces(ditContentRuleString, pos, length);
          pos = readOIDs(ditContentRuleString, pos, length, optAttrs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DCR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditContentRuleString, "MAY"));
        }
      }
      else if (lowerToken.equals("not"))
      {
        if (notAttrs.isEmpty())
        {
          pos = skipSpaces(ditContentRuleString, pos, length);
          pos = readOIDs(ditContentRuleString, pos, length, notAttrs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DCR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditContentRuleString, "NOT"));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(ditContentRuleString, pos, length);

        final ArrayList<String> valueList = new ArrayList<String>();
        pos = readQDStrings(ditContentRuleString, pos, length, valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DCR_DECODE_DUP_EXT.get(
                                       ditContentRuleString, token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_DCR_DECODE_DUP_EXT.get(
                                     ditContentRuleString, token));
      }
    }

    description = descr;

    names = new String[nameList.size()];
    nameList.toArray(names);

    auxiliaryClasses = new String[auxOCs.size()];
    auxOCs.toArray(auxiliaryClasses);

    requiredAttributes = new String[reqAttrs.size()];
    reqAttrs.toArray(requiredAttributes);

    optionalAttributes = new String[optAttrs.size()];
    optAttrs.toArray(optionalAttributes);

    prohibitedAttributes = new String[notAttrs.size()];
    notAttrs.toArray(prohibitedAttributes);

    isObsolete = (obsolete != null);

    extensions = Collections.unmodifiableMap(exts);
  }

  public DITContentRuleDefinition(final String oid, final String[] names,
                                  final String description,
                                  final boolean isObsolete,
                                  final String[] auxiliaryClasses,
                                  final String[] requiredAttributes,
                                  final String[] optionalAttributes,
                                  final String[] prohibitedAttributes,
                                  final Map<String,String[]> extensions)
  {
    ensureNotNull(oid);

    this.oid             = oid;
    this.isObsolete      = isObsolete;
    this.description     = description;

    if (names == null)
    {
      this.names = NO_STRINGS;
    }
    else
    {
      this.names = names;
    }

    if (auxiliaryClasses == null)
    {
      this.auxiliaryClasses = NO_STRINGS;
    }
    else
    {
      this.auxiliaryClasses  = auxiliaryClasses;
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

    if (prohibitedAttributes == null)
    {
      this.prohibitedAttributes = NO_STRINGS;
    }
    else
    {
      this.prohibitedAttributes = prohibitedAttributes;
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
    ditContentRuleString = buffer.toString();
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

    if (auxiliaryClasses.length == 1)
    {
      buffer.append(" AUX ");
      buffer.append(auxiliaryClasses[0]);
    }
    else if (auxiliaryClasses.length > 1)
    {
      buffer.append(" AUX (");
      for (int i=0; i < auxiliaryClasses.length; i++)
      {
        if (i >0)
        {
          buffer.append(" $ ");
        }
        else
        {
          buffer.append(' ');
        }
        buffer.append(auxiliaryClasses[i]);
      }
      buffer.append(" )");
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

    if (prohibitedAttributes.length == 1)
    {
      buffer.append(" NOT ");
      buffer.append(prohibitedAttributes[0]);
    }
    else if (prohibitedAttributes.length > 1)
    {
      buffer.append(" NOT (");
      for (int i=0; i < prohibitedAttributes.length; i++)
      {
        if (i > 0)
        {
          buffer.append(" $ ");
        }
        else
        {
          buffer.append(' ');
        }
        buffer.append(prohibitedAttributes[i]);
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


  public String[] getAuxiliaryClasses()
  {
    return auxiliaryClasses;
  }

  public String[] getRequiredAttributes()
  {
    return requiredAttributes;
  }

  public String[] getOptionalAttributes()
  {
    return optionalAttributes;
  }

  public String[] getProhibitedAttributes()
  {
    return prohibitedAttributes;
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

    if (! (o instanceof DITContentRuleDefinition))
    {
      return false;
    }

    final DITContentRuleDefinition d = (DITContentRuleDefinition) o;
    return (oid.equals(d.oid) &&
         stringsEqualIgnoreCaseOrderIndependent(names, d.names) &&
         stringsEqualIgnoreCaseOrderIndependent(auxiliaryClasses,
              d.auxiliaryClasses) &&
         stringsEqualIgnoreCaseOrderIndependent(requiredAttributes,
              d.requiredAttributes) &&
         stringsEqualIgnoreCaseOrderIndependent(optionalAttributes,
              d.optionalAttributes) &&
         stringsEqualIgnoreCaseOrderIndependent(prohibitedAttributes,
              d.prohibitedAttributes) &&
         bothNullOrEqualIgnoreCase(description, d.description) &&
         (isObsolete == d.isObsolete) &&
         extensionsEqual(extensions, d.extensions));
  }


  @Override()
  public String toString()
  {
    return ditContentRuleString;
  }
}

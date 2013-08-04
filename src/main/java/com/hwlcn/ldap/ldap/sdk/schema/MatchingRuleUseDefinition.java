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
public final class MatchingRuleUseDefinition
       extends SchemaElement
{

  private static final long serialVersionUID = 2366143311976256897L;

  private final boolean isObsolete;

  private final Map<String,String[]> extensions;

  private final String description;

  private final String matchingRuleUseString;

  private final String oid;

  private final String[] applicableTypes;

  private final String[] names;


  public MatchingRuleUseDefinition(final String s)
         throws LDAPException
  {
    ensureNotNull(s);

    matchingRuleUseString = s.trim();

    final int length = matchingRuleUseString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MRU_DECODE_EMPTY.get());
    }
    else if (matchingRuleUseString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MRU_DECODE_NO_OPENING_PAREN.get(
                                   matchingRuleUseString));
    }

    int pos = skipSpaces(matchingRuleUseString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(matchingRuleUseString, pos, length, buffer);
    oid = buffer.toString();

    final ArrayList<String> nameList = new ArrayList<String>(1);
    final ArrayList<String> typeList = new ArrayList<String>(1);
    String               descr       = null;
    Boolean              obsolete    = null;
    final Map<String,String[]> exts  = new LinkedHashMap<String,String[]>();

    while (true)
    {
      pos = skipSpaces(matchingRuleUseString, pos, length);

      final int tokenStartPos = pos;
      while ((pos < length) && (matchingRuleUseString.charAt(pos) != ' '))
      {
        pos++;
      }

      String token = matchingRuleUseString.substring(tokenStartPos, pos);
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
                                  ERR_MRU_DECODE_CLOSE_NOT_AT_END.get(
                                       matchingRuleUseString));
        }
        break;
      }
      else if (lowerToken.equals("name"))
      {
        if (nameList.isEmpty())
        {
          pos = skipSpaces(matchingRuleUseString, pos, length);
          pos = readQDStrings(matchingRuleUseString, pos, length, nameList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MRU_DECODE_MULTIPLE_ELEMENTS.get(
                                       matchingRuleUseString, "NAME"));
        }
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(matchingRuleUseString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(matchingRuleUseString, pos, length, buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MRU_DECODE_MULTIPLE_ELEMENTS.get(
                                       matchingRuleUseString, "DESC"));
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
                                  ERR_MRU_DECODE_MULTIPLE_ELEMENTS.get(
                                       matchingRuleUseString, "OBSOLETE"));
        }
      }
      else if (lowerToken.equals("applies"))
      {
        if (typeList.isEmpty())
        {
          pos = skipSpaces(matchingRuleUseString, pos, length);
          pos = readOIDs(matchingRuleUseString, pos, length, typeList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MRU_DECODE_MULTIPLE_ELEMENTS.get(
                                       matchingRuleUseString, "APPLIES"));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(matchingRuleUseString, pos, length);

        final ArrayList<String> valueList = new ArrayList<String>();
        pos = readQDStrings(matchingRuleUseString, pos, length, valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_MRU_DECODE_DUP_EXT.get(
                                       matchingRuleUseString, token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_MRU_DECODE_UNEXPECTED_TOKEN.get(
                                     matchingRuleUseString, token));
      }
    }

    description = descr;

    names = new String[nameList.size()];
    nameList.toArray(names);

    if (typeList.isEmpty())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MRU_DECODE_NO_APPLIES.get(
                                   matchingRuleUseString));
    }

    applicableTypes = new String[typeList.size()];
    typeList.toArray(applicableTypes);

    isObsolete = (obsolete != null);

    extensions = Collections.unmodifiableMap(exts);
  }

  public MatchingRuleUseDefinition(final String oid, final String[] names,
                                   final String description,
                                   final boolean isObsolete,
                                   final String[] applicableTypes,
                                   final Map<String,String[]> extensions)
  {
    ensureNotNull(oid, applicableTypes);
    ensureFalse(applicableTypes.length == 0);

    this.oid             = oid;
    this.description     = description;
    this.isObsolete      = isObsolete;
    this.applicableTypes = applicableTypes;

    if (names == null)
    {
      this.names = NO_STRINGS;
    }
    else
    {
      this.names = names;
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
    matchingRuleUseString = buffer.toString();
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

    if (applicableTypes.length == 1)
    {
      buffer.append(" APPLIES ");
      buffer.append(applicableTypes[0]);
    }
    else if (applicableTypes.length > 1)
    {
      buffer.append(" APPLIES (");
      for (int i=0; i < applicableTypes.length; i++)
      {
        if (i > 0)
        {
          buffer.append(" $");
        }

        buffer.append(' ');
        buffer.append(applicableTypes[i]);
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

  public String[] getApplicableAttributeTypes()
  {
    return applicableTypes;
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

    if (! (o instanceof MatchingRuleUseDefinition))
    {
      return false;
    }

    final MatchingRuleUseDefinition d = (MatchingRuleUseDefinition) o;
    return (oid.equals(d.oid) &&
         stringsEqualIgnoreCaseOrderIndependent(names, d.names) &&
         stringsEqualIgnoreCaseOrderIndependent(applicableTypes,
              d.applicableTypes) &&
         bothNullOrEqualIgnoreCase(description, d.description) &&
         (isObsolete == d.isObsolete) &&
         extensionsEqual(extensions, d.extensions));
  }

  @Override()
  public String toString()
  {
    return matchingRuleUseString;
  }
}

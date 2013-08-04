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
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AttributeTypeDefinition
       extends SchemaElement
{

  private static final long serialVersionUID = -6688185196734362719L;

  private final AttributeUsage usage;

  private final boolean isCollective;

  private final boolean isNoUserModification;
  private final boolean isObsolete;

  private final boolean isSingleValued;

  private final Map<String,String[]> extensions;

  private final String attributeTypeString;

  private final String description;

  private final String equalityMatchingRule;

  private final String oid;

  private final String orderingMatchingRule;

  private final String substringMatchingRule;

  private final String superiorType;

  private final String syntaxOID;

  private final String[] names;


  public AttributeTypeDefinition(final String s)
         throws LDAPException
  {
    ensureNotNull(s);

    attributeTypeString = s.trim();

    final int length = attributeTypeString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ATTRTYPE_DECODE_EMPTY.get());
    }
    else if (attributeTypeString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ATTRTYPE_DECODE_NO_OPENING_PAREN.get(
                                   attributeTypeString));
    }

    int pos = skipSpaces(attributeTypeString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(attributeTypeString, pos, length, buffer);
    oid = buffer.toString();

    final ArrayList<String> nameList = new ArrayList<String>(1);
    AttributeUsage       attrUsage   = null;
    Boolean              collective  = null;
    Boolean              noUserMod   = null;
    Boolean              obsolete    = null;
    Boolean              singleValue = null;
    final Map<String,String[]> exts  = new LinkedHashMap<String,String[]>();
    String               descr       = null;
    String               eqRule      = null;
    String               ordRule     = null;
    String               subRule     = null;
    String               supType     = null;
    String               synOID      = null;

    while (true)
    {
      pos = skipSpaces(attributeTypeString, pos, length);

      final int tokenStartPos = pos;
      while ((pos < length) && (attributeTypeString.charAt(pos) != ' '))
      {
        pos++;
      }

      String token = attributeTypeString.substring(tokenStartPos, pos);

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
                                  ERR_ATTRTYPE_DECODE_CLOSE_NOT_AT_END.get(
                                       attributeTypeString));
        }
        break;
      }
      else if (lowerToken.equals("name"))
      {
        if (nameList.isEmpty())
        {
          pos = skipSpaces(attributeTypeString, pos, length);
          pos = readQDStrings(attributeTypeString, pos, length, nameList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "NAME"));
        }
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(attributeTypeString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(attributeTypeString, pos, length, buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "DESC"));
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
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "OBSOLETE"));
        }
      }
      else if (lowerToken.equals("sup"))
      {
        if (supType == null)
        {
          pos = skipSpaces(attributeTypeString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(attributeTypeString, pos, length, buffer);
          supType = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "SUP"));
        }
      }
      else if (lowerToken.equals("equality"))
      {
        if (eqRule == null)
        {
          pos = skipSpaces(attributeTypeString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(attributeTypeString, pos, length, buffer);
          eqRule = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "EQUALITY"));
        }
      }
      else if (lowerToken.equals("ordering"))
      {
        if (ordRule == null)
        {
          pos = skipSpaces(attributeTypeString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(attributeTypeString, pos, length, buffer);
          ordRule = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "ORDERING"));
        }
      }
      else if (lowerToken.equals("substr"))
      {
        if (subRule == null)
        {
          pos = skipSpaces(attributeTypeString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(attributeTypeString, pos, length, buffer);
          subRule = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "SUBSTR"));
        }
      }
      else if (lowerToken.equals("syntax"))
      {
        if (synOID == null)
        {
          pos = skipSpaces(attributeTypeString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(attributeTypeString, pos, length, buffer);
          synOID = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "SYNTAX"));
        }
      }
      else if (lowerToken.equals("single-value"))
      {
        if (singleValue == null)
        {
          singleValue = true;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "SINGLE-VALUE"));
        }
      }
      else if (lowerToken.equals("collective"))
      {
        if (collective == null)
        {
          collective = true;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "COLLECTIVE"));
        }
      }
      else if (lowerToken.equals("no-user-modification"))
      {
        if (noUserMod == null)
        {
          noUserMod = true;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString,
                                       "NO-USER-MODIFICATION"));
        }
      }
      else if (lowerToken.equals("usage"))
      {
        if (attrUsage == null)
        {
          pos = skipSpaces(attributeTypeString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(attributeTypeString, pos, length, buffer);

          final String usageStr = toLowerCase(buffer.toString());
          if (usageStr.equals("userapplications"))
          {
            attrUsage = AttributeUsage.USER_APPLICATIONS;
          }
          else if (usageStr.equals("directoryoperation"))
          {
            attrUsage = AttributeUsage.DIRECTORY_OPERATION;
          }
          else if (usageStr.equals("distributedoperation"))
          {
            attrUsage = AttributeUsage.DISTRIBUTED_OPERATION;
          }
          else if (usageStr.equals("dsaoperation"))
          {
            attrUsage = AttributeUsage.DSA_OPERATION;
          }
          else
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_ATTRTYPE_DECODE_INVALID_USAGE.get(
                                         attributeTypeString, usageStr));
          }
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_MULTIPLE_ELEMENTS.get(
                                       attributeTypeString, "USAGE"));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(attributeTypeString, pos, length);

        final ArrayList<String> valueList = new ArrayList<String>();
        pos = readQDStrings(attributeTypeString, pos, length, valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRTYPE_DECODE_DUP_EXT.get(
                                       attributeTypeString, token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_ATTRTYPE_DECODE_UNEXPECTED_TOKEN.get(
                                     attributeTypeString, token));
      }
    }

    description           = descr;
    equalityMatchingRule  = eqRule;
    orderingMatchingRule  = ordRule;
    substringMatchingRule = subRule;
    superiorType          = supType;
    syntaxOID             = synOID;

    names = new String[nameList.size()];
    nameList.toArray(names);

    isObsolete           = (obsolete != null);
    isSingleValued       = (singleValue != null);
    isCollective         = (collective != null);
    isNoUserModification = (noUserMod != null);

    if (attrUsage == null)
    {
      usage = AttributeUsage.USER_APPLICATIONS;
    }
    else
    {
      usage = attrUsage;
    }

    extensions = Collections.unmodifiableMap(exts);
  }




  public AttributeTypeDefinition(final String oid, final String[] names,
                                 final String description,
                                 final boolean isObsolete,
                                 final String superiorType,
                                 final String equalityMatchingRule,
                                 final String orderingMatchingRule,
                                 final String substringMatchingRule,
                                 final String syntaxOID,
                                 final boolean isSingleValued,
                                 final boolean isCollective,
                                 final boolean isNoUserModification,
                                 final AttributeUsage usage,
                                 final Map<String,String[]> extensions)
  {
    ensureNotNull(oid);

    this.oid                   = oid;
    this.description           = description;
    this.isObsolete            = isObsolete;
    this.superiorType          = superiorType;
    this.equalityMatchingRule  = equalityMatchingRule;
    this.orderingMatchingRule  = orderingMatchingRule;
    this.substringMatchingRule = substringMatchingRule;
    this.syntaxOID             = syntaxOID;
    this.isSingleValued        = isSingleValued;
    this.isCollective          = isCollective;
    this.isNoUserModification  = isNoUserModification;

    if (names == null)
    {
      this.names = NO_STRINGS;
    }
    else
    {
      this.names = names;
    }

    if (usage == null)
    {
      this.usage = AttributeUsage.USER_APPLICATIONS;
    }
    else
    {
      this.usage = usage;
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
    attributeTypeString = buffer.toString();
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

    if (superiorType != null)
    {
      buffer.append(" SUP ");
      buffer.append(superiorType);
    }

    if (equalityMatchingRule != null)
    {
      buffer.append(" EQUALITY ");
      buffer.append(equalityMatchingRule);
    }

    if (orderingMatchingRule != null)
    {
      buffer.append(" ORDERING ");
      buffer.append(orderingMatchingRule);
    }

    if (substringMatchingRule != null)
    {
      buffer.append(" SUBSTR ");
      buffer.append(substringMatchingRule);
    }

    if (syntaxOID != null)
    {
      buffer.append(" SYNTAX ");
      buffer.append(syntaxOID);
    }

    if (isSingleValued)
    {
      buffer.append(" SINGLE-VALUE");
    }

    if (isCollective)
    {
      buffer.append(" COLLECTIVE");
    }

    if (isNoUserModification)
    {
      buffer.append(" NO-USER-MODIFICATION");
    }

    buffer.append(" USAGE ");
    buffer.append(usage.getName());

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

  public String getSuperiorType()
  {
    return superiorType;
  }

  public AttributeTypeDefinition getSuperiorType(final Schema schema)
  {
    if (superiorType != null)
    {
      return schema.getAttributeType(superiorType);
    }

    return null;
  }


  public String getEqualityMatchingRule()
  {
    return equalityMatchingRule;
  }


  public String getEqualityMatchingRule(final Schema schema)
  {
    if (equalityMatchingRule == null)
    {
      final AttributeTypeDefinition sup = getSuperiorType(schema);
      if (sup != null)
      {
        return sup.getEqualityMatchingRule(schema);
      }
    }

    return equalityMatchingRule;
  }

  public String getOrderingMatchingRule()
  {
    return orderingMatchingRule;
  }

  public String getOrderingMatchingRule(final Schema schema)
  {
    if (orderingMatchingRule == null)
    {
      final AttributeTypeDefinition sup = getSuperiorType(schema);
      if (sup != null)
      {
        return sup.getOrderingMatchingRule(schema);
      }
    }

    return orderingMatchingRule;
  }

  public String getSubstringMatchingRule()
  {
    return substringMatchingRule;
  }


  public String getSubstringMatchingRule(final Schema schema)
  {
    if (substringMatchingRule == null)
    {
      final AttributeTypeDefinition sup = getSuperiorType(schema);
      if (sup != null)
      {
        return sup.getSubstringMatchingRule(schema);
      }
    }

    return substringMatchingRule;
  }

  public String getSyntaxOID()
  {
    return syntaxOID;
  }

  public String getSyntaxOID(final Schema schema)
  {
    if (syntaxOID == null)
    {
      final AttributeTypeDefinition sup = getSuperiorType(schema);
      if (sup != null)
      {
        return sup.getSyntaxOID(schema);
      }
    }

    return syntaxOID;
  }

  public String getBaseSyntaxOID()
  {
    return getBaseSyntaxOID(syntaxOID);
  }

  public String getBaseSyntaxOID(final Schema schema)
  {
    return getBaseSyntaxOID(getSyntaxOID(schema));
  }

  public static String getBaseSyntaxOID(final String syntaxOID)
  {
    if (syntaxOID == null)
    {
      return null;
    }

    final int curlyPos = syntaxOID.indexOf('{');
    if (curlyPos > 0)
    {
      return syntaxOID.substring(0, curlyPos);
    }
    else
    {
      return syntaxOID;
    }
  }

  public int getSyntaxMinimumUpperBound()
  {
    return getSyntaxMinimumUpperBound(syntaxOID);
  }

  public int getSyntaxMinimumUpperBound(final Schema schema)
  {
    return getSyntaxMinimumUpperBound(getSyntaxOID(schema));
  }

  public static int getSyntaxMinimumUpperBound(final String syntaxOID)
  {
    if (syntaxOID == null)
    {
      return -1;
    }

    final int curlyPos = syntaxOID.indexOf('{');
    if ((curlyPos > 0) && syntaxOID.endsWith("}"))
    {
      try
      {
        return Integer.parseInt(syntaxOID.substring(curlyPos+1,
             syntaxOID.length()-1));
      }
      catch (final Exception e)
      {
        debugException(e);
        return -1;
      }
    }
    else
    {
      return -1;
    }
  }

  public boolean isSingleValued()
  {
    return isSingleValued;
  }


  public boolean isCollective()
  {
    return isCollective;
  }


  public boolean isNoUserModification()
  {
    return isNoUserModification;
  }

  public AttributeUsage getUsage()
  {
    return usage;
  }

  public boolean isOperational()
  {
    return usage.isOperational();
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

    if (! (o instanceof AttributeTypeDefinition))
    {
      return false;
    }

    final AttributeTypeDefinition d = (AttributeTypeDefinition) o;
    return(oid.equals(d.oid) &&
         stringsEqualIgnoreCaseOrderIndependent(names, d.names) &&
         bothNullOrEqual(usage, d.usage) &&
         bothNullOrEqualIgnoreCase(description, d.description) &&
         bothNullOrEqualIgnoreCase(equalityMatchingRule,
              d.equalityMatchingRule) &&
         bothNullOrEqualIgnoreCase(orderingMatchingRule,
              d.orderingMatchingRule) &&
         bothNullOrEqualIgnoreCase(substringMatchingRule,
              d.substringMatchingRule) &&
         bothNullOrEqualIgnoreCase(superiorType, d.superiorType) &&
         bothNullOrEqualIgnoreCase(syntaxOID, d.syntaxOID) &&
         (isCollective == d.isCollective) &&
         (isNoUserModification == d.isNoUserModification) &&
         (isObsolete == d.isObsolete) &&
         (isSingleValued == d.isSingleValued) &&
         extensionsEqual(extensions, d.extensions));
  }

  @Override()
  public String toString()
  {
    return attributeTypeString;
  }
}

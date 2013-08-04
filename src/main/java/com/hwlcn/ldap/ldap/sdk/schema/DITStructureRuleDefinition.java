
package com.hwlcn.ldap.ldap.sdk.schema;



import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
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
public final class DITStructureRuleDefinition
       extends SchemaElement
{

  private static final int[] NO_INTS = new int[0];

  private static final long serialVersionUID = -3233223742542121140L;

  private final boolean isObsolete;

  private final int ruleID;

  private final int[] superiorRuleIDs;

  private final Map<String,String[]> extensions;

  private final String description;

  private final String ditStructureRuleString;

  private final String nameFormID;

  private final String[] names;

  public DITStructureRuleDefinition(final String s)
         throws LDAPException
  {
    ensureNotNull(s);

    ditStructureRuleString = s.trim();
    final int length = ditStructureRuleString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_DSR_DECODE_EMPTY.get());
    }
    else if (ditStructureRuleString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_DSR_DECODE_NO_OPENING_PAREN.get(
                                   ditStructureRuleString));
    }


    int pos = skipSpaces(ditStructureRuleString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(ditStructureRuleString, pos, length, buffer);
    final String ruleIDStr = buffer.toString();
    try
    {
      ruleID = Integer.parseInt(ruleIDStr);
    }
    catch (NumberFormatException nfe)
    {
      debugException(nfe);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_DSR_DECODE_RULE_ID_NOT_INT.get(
                                   ditStructureRuleString),
                              nfe);
    }

    final ArrayList<Integer>   supList  = new ArrayList<Integer>(1);
    final ArrayList<String>    nameList = new ArrayList<String>(1);
    final Map<String,String[]> exts     = new LinkedHashMap<String,String[]>();
    Boolean                    obsolete = null;
    String                     descr    = null;
    String                     nfID     = null;

    while (true)
    {
      pos = skipSpaces(ditStructureRuleString, pos, length);

      final int tokenStartPos = pos;
      while ((pos < length) && (ditStructureRuleString.charAt(pos) != ' '))
      {
        pos++;
      }

      String token = ditStructureRuleString.substring(tokenStartPos, pos);
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
                                  ERR_DSR_DECODE_CLOSE_NOT_AT_END.get(
                                       ditStructureRuleString));
        }
        break;
      }
      else if (lowerToken.equals("name"))
      {
        if (nameList.isEmpty())
        {
          pos = skipSpaces(ditStructureRuleString, pos, length);
          pos = readQDStrings(ditStructureRuleString, pos, length, nameList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DSR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditStructureRuleString, "NAME"));
        }
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(ditStructureRuleString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(ditStructureRuleString, pos, length, buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DSR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditStructureRuleString, "DESC"));
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
                                  ERR_DSR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditStructureRuleString, "OBSOLETE"));
        }
      }
      else if (lowerToken.equals("form"))
      {
        if (nfID == null)
        {
          pos = skipSpaces(ditStructureRuleString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(ditStructureRuleString, pos, length, buffer);
          nfID = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DSR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditStructureRuleString, "FORM"));
        }
      }
      else if (lowerToken.equals("sup"))
      {
        if (supList.isEmpty())
        {
          final ArrayList<String> supStrs = new ArrayList<String>(1);

          pos = skipSpaces(ditStructureRuleString, pos, length);
          pos = readOIDs(ditStructureRuleString, pos, length, supStrs);

          supList.ensureCapacity(supStrs.size());
          for (final String supStr : supStrs)
          {
            try
            {
              supList.add(Integer.parseInt(supStr));
            }
            catch (NumberFormatException nfe)
            {
              debugException(nfe);
              throw new LDAPException(ResultCode.DECODING_ERROR,
                                      ERR_DSR_DECODE_SUP_ID_NOT_INT.get(
                                           ditStructureRuleString),
                                      nfe);
            }
          }
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DSR_DECODE_MULTIPLE_ELEMENTS.get(
                                       ditStructureRuleString, "SUP"));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(ditStructureRuleString, pos, length);

        final ArrayList<String> valueList = new ArrayList<String>();
        pos = readQDStrings(ditStructureRuleString, pos, length, valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_DSR_DECODE_DUP_EXT.get(
                                       ditStructureRuleString, token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_DSR_DECODE_UNEXPECTED_TOKEN.get(
                                     ditStructureRuleString, token));
      }
    }

    description = descr;
    nameFormID  = nfID;

    if (nameFormID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_DSR_DECODE_NO_FORM.get(
                                   ditStructureRuleString));
    }

    names = new String[nameList.size()];
    nameList.toArray(names);

    superiorRuleIDs = new int[supList.size()];
    for (int i=0; i < superiorRuleIDs.length; i++)
    {
      superiorRuleIDs[i] = supList.get(i);
    }

    isObsolete = (obsolete != null);

    extensions = Collections.unmodifiableMap(exts);
  }


  public DITStructureRuleDefinition(final int ruleID, final String[] names,
                                    final String description,
                                    final boolean isObsolete,
                                    final String nameFormID,
                                    final int[] superiorRuleIDs,
                                    final Map<String,String[]> extensions)
  {
    ensureNotNull(nameFormID);

    this.ruleID      = ruleID;
    this.description = description;
    this.isObsolete  = isObsolete;
    this.nameFormID  = nameFormID;

    if (names == null)
    {
      this.names = NO_STRINGS;
    }
    else
    {
      this.names = names;
    }

    if (superiorRuleIDs == null)
    {
      this.superiorRuleIDs = NO_INTS;
    }
    else
    {
      this.superiorRuleIDs = superiorRuleIDs;
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
    ditStructureRuleString = buffer.toString();
  }

  private void createDefinitionString(final StringBuilder buffer)
  {
    buffer.append("( ");
    buffer.append(ruleID);

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

    buffer.append(" FORM ");
    buffer.append(nameFormID);

    if (superiorRuleIDs.length == 1)
    {
      buffer.append(" SUP ");
      buffer.append(superiorRuleIDs[0]);
    }
    else if (superiorRuleIDs.length > 1)
    {
      buffer.append(" SUP (");
      for (final int supID : superiorRuleIDs)
      {
        buffer.append(" $ ");
        buffer.append(supID);
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



  public int getRuleID()
  {
    return ruleID;
  }


  public String[] getNames()
  {
    return names;
  }


  public String getNameOrRuleID()
  {
    if (names.length == 0)
    {
      return String.valueOf(ruleID);
    }
    else
    {
      return names[0];
    }
  }


  public boolean hasNameOrRuleID(final String s)
  {
    for (final String name : names)
    {
      if (s.equalsIgnoreCase(name))
      {
        return true;
      }
    }

    return s.equalsIgnoreCase(String.valueOf(ruleID));
  }


  public String getDescription()
  {
    return description;
  }


  public boolean isObsolete()
  {
    return isObsolete;
  }

  public String getNameFormID()
  {
    return nameFormID;
  }

  public int[] getSuperiorRuleIDs()
  {
    return superiorRuleIDs;
  }


  public Map<String,String[]> getExtensions()
  {
    return extensions;
  }


  @Override()
  public int hashCode()
  {
    return ruleID;
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

    if (! (o instanceof DITStructureRuleDefinition))
    {
      return false;
    }

    final DITStructureRuleDefinition d = (DITStructureRuleDefinition) o;
    if ((ruleID == d.ruleID) &&
         nameFormID.equalsIgnoreCase(d.nameFormID) &&
         stringsEqualIgnoreCaseOrderIndependent(names, d.names) &&
         (isObsolete == d.isObsolete) &&
         extensionsEqual(extensions, d.extensions))
    {
      if (superiorRuleIDs.length != d.superiorRuleIDs.length)
      {
        return false;
      }

      final HashSet<Integer> s1 = new HashSet<Integer>(superiorRuleIDs.length);
      final HashSet<Integer> s2 = new HashSet<Integer>(superiorRuleIDs.length);
      for (final int i : superiorRuleIDs)
      {
        s1.add(i);
      }

      for (final int i : d.superiorRuleIDs)
      {
        s2.add(i);
      }

      return s1.equals(s2);
    }
    else
    {
      return false;
    }
  }

  @Override()
  public String toString()
  {
    return ditStructureRuleString;
  }
}

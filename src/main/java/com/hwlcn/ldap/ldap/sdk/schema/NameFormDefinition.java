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
public final class NameFormDefinition
       extends SchemaElement
{

  private static final long serialVersionUID = -816231530223449984L;

  private final boolean isObsolete;

  private final Map<String,String[]> extensions;

  private final String description;

  private final String nameFormString;

  private final String oid;

  private final String[] names;

  private final String structuralClass;

  private final String[] optionalAttributes;

  private final String[] requiredAttributes;

  public NameFormDefinition(final String s)
         throws LDAPException
  {
    ensureNotNull(s);

    nameFormString = s.trim();

    final int length = nameFormString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_NF_DECODE_EMPTY.get());
    }
    else if (nameFormString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_NF_DECODE_NO_OPENING_PAREN.get(
                                   nameFormString));
    }

    int pos = skipSpaces(nameFormString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(nameFormString, pos, length, buffer);
    oid = buffer.toString();


    final ArrayList<String>    nameList = new ArrayList<String>(1);
    final ArrayList<String>    reqAttrs = new ArrayList<String>();
    final ArrayList<String>    optAttrs = new ArrayList<String>();
    final Map<String,String[]> exts     = new LinkedHashMap<String,String[]>();
    Boolean                    obsolete = null;
    String                     descr    = null;
    String                     oc       = null;

    while (true)
    {
      pos = skipSpaces(nameFormString, pos, length);

      final int tokenStartPos = pos;
      while ((pos < length) && (nameFormString.charAt(pos) != ' '))
      {
        pos++;
      }


      String token = nameFormString.substring(tokenStartPos, pos);
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
                                  ERR_NF_DECODE_CLOSE_NOT_AT_END.get(
                                       nameFormString));
        }
        break;
      }
      else if (lowerToken.equals("name"))
      {
        if (nameList.isEmpty())
        {
          pos = skipSpaces(nameFormString, pos, length);
          pos = readQDStrings(nameFormString, pos, length, nameList);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_NF_DECODE_MULTIPLE_ELEMENTS.get(
                                       nameFormString, "NAME"));
        }
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(nameFormString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(nameFormString, pos, length, buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_NF_DECODE_MULTIPLE_ELEMENTS.get(
                                       nameFormString, "DESC"));
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
                                  ERR_NF_DECODE_MULTIPLE_ELEMENTS.get(
                                       nameFormString, "OBSOLETE"));
        }
      }
      else if (lowerToken.equals("oc"))
      {
        if (oc == null)
        {
          pos = skipSpaces(nameFormString, pos, length);

          buffer = new StringBuilder();
          pos = readOID(nameFormString, pos, length, buffer);
          oc = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_NF_DECODE_MULTIPLE_ELEMENTS.get(
                                       nameFormString, "OC"));
        }
      }
      else if (lowerToken.equals("must"))
      {
        if (reqAttrs.isEmpty())
        {
          pos = skipSpaces(nameFormString, pos, length);
          pos = readOIDs(nameFormString, pos, length, reqAttrs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_NF_DECODE_MULTIPLE_ELEMENTS.get(
                                       nameFormString, "MUST"));
        }
      }
      else if (lowerToken.equals("may"))
      {
        if (optAttrs.isEmpty())
        {
          pos = skipSpaces(nameFormString, pos, length);
          pos = readOIDs(nameFormString, pos, length, optAttrs);
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_NF_DECODE_MULTIPLE_ELEMENTS.get(
                                       nameFormString, "MAY"));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(nameFormString, pos, length);

        final ArrayList<String> valueList = new ArrayList<String>();
        pos = readQDStrings(nameFormString, pos, length, valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_NF_DECODE_DUP_EXT.get(nameFormString,
                                                            token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_NF_DECODE_UNEXPECTED_TOKEN.get(
                                     nameFormString, token));
      }
    }

    description     = descr;
    structuralClass = oc;

    if (structuralClass == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_NF_DECODE_NO_OC.get(nameFormString));
    }

    names = new String[nameList.size()];
    nameList.toArray(names);

    requiredAttributes = new String[reqAttrs.size()];
    reqAttrs.toArray(requiredAttributes);

    if (reqAttrs.isEmpty())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_NF_DECODE_NO_MUST.get(nameFormString));
    }

    optionalAttributes = new String[optAttrs.size()];
    optAttrs.toArray(optionalAttributes);

    isObsolete = (obsolete != null);

    extensions = Collections.unmodifiableMap(exts);
  }


  public NameFormDefinition(final String oid, final String[] names,
                               final String description,
                               final boolean isObsolete,
                               final String structuralClass,
                               final String[] requiredAttributes,
                               final String[] optionalAttributes,
                               final Map<String,String[]> extensions)
  {
    ensureNotNull(oid, structuralClass, requiredAttributes);
    ensureFalse(requiredAttributes.length == 0);

    this.oid                = oid;
    this.isObsolete         = isObsolete;
    this.description        = description;
    this.structuralClass    = structuralClass;
    this.requiredAttributes = requiredAttributes;

    if (names == null)
    {
      this.names = NO_STRINGS;
    }
    else
    {
      this.names = names;
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
    nameFormString = buffer.toString();
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

    buffer.append(" OC ");
    buffer.append(structuralClass);

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

  public String getStructuralClass()
  {
    return structuralClass;
  }

  public String[] getRequiredAttributes()
  {
    return requiredAttributes;
  }

  public String[] getOptionalAttributes()
  {
    return optionalAttributes;
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

    if (! (o instanceof NameFormDefinition))
    {
      return false;
    }

    final NameFormDefinition d = (NameFormDefinition) o;
    return (oid.equals(d.oid) &&
         structuralClass.equalsIgnoreCase(d.structuralClass) &&
         stringsEqualIgnoreCaseOrderIndependent(names, d.names) &&
         stringsEqualIgnoreCaseOrderIndependent(requiredAttributes,
              d.requiredAttributes) &&
         stringsEqualIgnoreCaseOrderIndependent(optionalAttributes,
                   d.optionalAttributes) &&
         bothNullOrEqualIgnoreCase(description, d.description) &&
         (isObsolete == d.isObsolete) &&
         extensionsEqual(extensions, d.extensions));
  }


  @Override()
  public String toString()
  {
    return nameFormString;
  }
}

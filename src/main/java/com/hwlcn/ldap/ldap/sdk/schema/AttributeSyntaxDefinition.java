
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
public final class AttributeSyntaxDefinition
       extends SchemaElement
{

  private static final long serialVersionUID = 8593718232711987488L;

  private final Map<String,String[]> extensions;

  private final String description;

  private final String attributeSyntaxString;

  private final String oid;



  public AttributeSyntaxDefinition(final String s)
         throws LDAPException
  {
    ensureNotNull(s);

    attributeSyntaxString = s.trim();

    final int length = attributeSyntaxString.length();
    if (length == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ATTRSYNTAX_DECODE_EMPTY.get());
    }
    else if (attributeSyntaxString.charAt(0) != '(')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ATTRSYNTAX_DECODE_NO_OPENING_PAREN.get(
                                   attributeSyntaxString));
    }



    int pos = skipSpaces(attributeSyntaxString, 1, length);

    StringBuilder buffer = new StringBuilder();
    pos = readOID(attributeSyntaxString, pos, length, buffer);
    oid = buffer.toString();


    String               descr = null;
    final Map<String,String[]> exts  = new LinkedHashMap<String,String[]>();

    while (true)
    {
      pos = skipSpaces(attributeSyntaxString, pos, length);

      final int tokenStartPos = pos;
      while ((pos < length) && (attributeSyntaxString.charAt(pos) != ' '))
      {
        pos++;
      }

      final String token = attributeSyntaxString.substring(tokenStartPos, pos);
      final String lowerToken = toLowerCase(token);
      if (lowerToken.equals(")"))
      {
        if (pos < length)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRSYNTAX_DECODE_CLOSE_NOT_AT_END.get(
                                       attributeSyntaxString));
        }
        break;
      }
      else if (lowerToken.equals("desc"))
      {
        if (descr == null)
        {
          pos = skipSpaces(attributeSyntaxString, pos, length);

          buffer = new StringBuilder();
          pos = readQDString(attributeSyntaxString, pos, length, buffer);
          descr = buffer.toString();
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRSYNTAX_DECODE_MULTIPLE_DESC.get(
                                       attributeSyntaxString));
        }
      }
      else if (lowerToken.startsWith("x-"))
      {
        pos = skipSpaces(attributeSyntaxString, pos, length);

        final ArrayList<String> valueList = new ArrayList<String>();
        pos = readQDStrings(attributeSyntaxString, pos, length, valueList);

        final String[] values = new String[valueList.size()];
        valueList.toArray(values);

        if (exts.containsKey(token))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRSYNTAX_DECODE_DUP_EXT.get(
                                       attributeSyntaxString, token));
        }

        exts.put(token, values);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_ATTRSYNTAX_DECODE_UNEXPECTED_TOKEN.get(
                                       attributeSyntaxString, token));
      }
    }

    description = descr;
    extensions  = Collections.unmodifiableMap(exts);
  }

  public AttributeSyntaxDefinition(final String oid, final String description,
                                   final Map<String,String[]> extensions)
  {
    ensureNotNull(oid);

    this.oid         = oid;
    this.description = description;

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
    attributeSyntaxString = buffer.toString();
  }

  private void createDefinitionString(final StringBuilder buffer)
  {
    buffer.append("( ");
    buffer.append(oid);

    if (description != null)
    {
      buffer.append(" DESC '");
      encodeValue(description, buffer);
      buffer.append('\'');
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



  public String getDescription()
  {
    return description;
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

    if (! (o instanceof AttributeSyntaxDefinition))
    {
      return false;
    }

    final AttributeSyntaxDefinition d = (AttributeSyntaxDefinition) o;
    return (oid.equals(d.oid) &&
         bothNullOrEqualIgnoreCase(description, d.description) &&
         extensionsEqual(extensions, d.extensions));
  }



  @Override()
  public String toString()
  {
    return attributeSyntaxString;
  }
}

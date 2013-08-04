package com.hwlcn.ldap.ldap.sdk.schema;



import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Map;

import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.schema.SchemaMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;



@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class SchemaElement
       implements Serializable
{

  private static final long serialVersionUID = -8249972237068748580L;

  static int skipSpaces(final String s, final int startPos, final int length)
         throws LDAPException
  {
    int pos = startPos;
    while ((pos < length) && (s.charAt(pos) == ' '))
    {
      pos++;
    }

    if (pos >= length)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SCHEMA_ELEM_SKIP_SPACES_NO_CLOSE_PAREN.get(
                                   s));
    }

    return pos;
  }

  private static int readEscapedHexString(final String s, final int startPos,
                                          final int length,
                                          final StringBuilder buffer)
          throws LDAPException
  {
    int pos    = startPos;

    final ByteBuffer byteBuffer = ByteBuffer.allocate(length - pos);
    while (pos < length)
    {
      byte b;
      switch (s.charAt(pos++))
      {
        case '0':
          b = 0x00;
          break;
        case '1':
          b = 0x10;
          break;
        case '2':
          b = 0x20;
          break;
        case '3':
          b = 0x30;
          break;
        case '4':
          b = 0x40;
          break;
        case '5':
          b = 0x50;
          break;
        case '6':
          b = 0x60;
          break;
        case '7':
          b = 0x70;
          break;
        case '8':
          b = (byte) 0x80;
          break;
        case '9':
          b = (byte) 0x90;
          break;
        case 'a':
        case 'A':
          b = (byte) 0xA0;
          break;
        case 'b':
        case 'B':
          b = (byte) 0xB0;
          break;
        case 'c':
        case 'C':
          b = (byte) 0xC0;
          break;
        case 'd':
        case 'D':
          b = (byte) 0xD0;
          break;
        case 'e':
        case 'E':
          b = (byte) 0xE0;
          break;
        case 'f':
        case 'F':
          b = (byte) 0xF0;
          break;
        default:
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                  ERR_SCHEMA_ELEM_INVALID_HEX_CHAR.get(s,
                                       s.charAt(pos-1), (pos-1)));
      }

      if (pos >= length)
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                ERR_SCHEMA_ELEM_MISSING_HEX_CHAR.get(s));
      }

      switch (s.charAt(pos++))
      {
        case '0':
          // No action is required.
          break;
        case '1':
          b |= 0x01;
          break;
        case '2':
          b |= 0x02;
          break;
        case '3':
          b |= 0x03;
          break;
        case '4':
          b |= 0x04;
          break;
        case '5':
          b |= 0x05;
          break;
        case '6':
          b |= 0x06;
          break;
        case '7':
          b |= 0x07;
          break;
        case '8':
          b |= 0x08;
          break;
        case '9':
          b |= 0x09;
          break;
        case 'a':
        case 'A':
          b |= 0x0A;
          break;
        case 'b':
        case 'B':
          b |= 0x0B;
          break;
        case 'c':
        case 'C':
          b |= 0x0C;
          break;
        case 'd':
        case 'D':
          b |= 0x0D;
          break;
        case 'e':
        case 'E':
          b |= 0x0E;
          break;
        case 'f':
        case 'F':
          b |= 0x0F;
          break;
        default:
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                  ERR_SCHEMA_ELEM_INVALID_HEX_CHAR.get(s,
                                       s.charAt(pos-1), (pos-1)));
      }

      byteBuffer.put(b);
      if (((pos+1) < length) && (s.charAt(pos) == '\\') &&
          isHex(s.charAt(pos+1)))
      {

        pos++;
        continue;
      }
      else
      {
        break;
      }
    }

    byteBuffer.flip();
    final byte[] byteArray = new byte[byteBuffer.limit()];
    byteBuffer.get(byteArray);

    try
    {
      buffer.append(toUTF8String(byteArray));
    }
    catch (final Exception e)
    {
      debugException(e);
      buffer.append(new String(byteArray));
    }

    return pos;
  }

  static int readQDString(final String s, final int startPos, final int length,
                          final StringBuilder buffer)
      throws LDAPException
  {
    if (s.charAt(startPos) != '\'')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SCHEMA_ELEM_EXPECTED_SINGLE_QUOTE.get(s,
                                   startPos));
    }


    int pos = startPos + 1;
    while (pos < length)
    {
      final char c = s.charAt(pos++);
      if (c == '\'')
      {
        break;
      }
      else if (c == '\\')
      {
        if (pos >= length)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_SCHEMA_ELEM_ENDS_WITH_BACKSLASH.get(s));
        }

        pos = readEscapedHexString(s, pos, length, buffer);
      }
      else
      {
        buffer.append(c);
      }
    }

    if ((pos >= length) || ((s.charAt(pos) != ' ') && (s.charAt(pos) != ')')))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SCHEMA_ELEM_NO_CLOSING_PAREN.get(s));
    }

    if (buffer.length() == 0)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SCHEMA_ELEM_EMPTY_QUOTES.get(s));
    }

    return pos;
  }


  static int readQDStrings(final String s, final int startPos, final int length,
                           final ArrayList<String> valueList)
      throws LDAPException
  {

    char c = s.charAt(startPos);
    if (c == '\'')
    {
      final StringBuilder buffer = new StringBuilder();
      final int returnPos = readQDString(s, startPos, length, buffer);
      valueList.add(buffer.toString());
      return returnPos;
    }
    else if (c == '(')
    {
      int pos = startPos + 1;
      while (true)
      {
        pos = skipSpaces(s, pos, length);
        c = s.charAt(pos);
        if (c == ')')
        {
          pos++;
          break;
        }
        else if (c == '\'')
        {
          final StringBuilder buffer = new StringBuilder();
          pos = readQDString(s, pos, length, buffer);
          valueList.add(buffer.toString());
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_SCHEMA_ELEM_EXPECTED_QUOTE_OR_PAREN.get(
                                       s, startPos));
        }
      }

      if (valueList.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_SCHEMA_ELEM_EMPTY_STRING_LIST.get(s));
      }

      if ((pos >= length) ||
          ((s.charAt(pos) != ' ') && (s.charAt(pos) != ')')))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_SCHEMA_ELEM_NO_SPACE_AFTER_QUOTE.get(s));
      }

      return pos;
    }
    else
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SCHEMA_ELEM_EXPECTED_QUOTE_OR_PAREN.get(s,
                                   startPos));
    }
  }


  static int readOID(final String s, final int startPos, final int length,
                     final StringBuilder buffer)
      throws LDAPException
  {
    int pos = startPos;
    boolean lastWasQuote = false;
    while (pos < length)
    {
      final char c = s.charAt(pos);
      if ((c == ' ') || (c == '$') || (c == ')'))
      {
        if (buffer.length() == 0)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_SCHEMA_ELEM_EMPTY_OID.get(s));
        }

        return pos;
      }
      else if (((c >= 'a') && (c <= 'z')) ||
               ((c >= 'A') && (c <= 'Z')) ||
               ((c >= '0') && (c <= '9')) ||
               (c == '-') || (c == '.') || (c == '_') ||
               (c == '{') || (c == '}'))
      {
        if (lastWasQuote)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_SCHEMA_ELEM_UNEXPECTED_CHAR_IN_OID.get(s, (pos-1)));
        }

        buffer.append(c);
      }
      else if (c == '\'')
      {
        if (buffer.length() != 0)
        {
          lastWasQuote = true;
        }
      }
      else
      {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_SCHEMA_ELEM_UNEXPECTED_CHAR_IN_OID.get(s,
                                       pos));
      }

      pos++;
    }


    throw new LDAPException(ResultCode.DECODING_ERROR,
                            ERR_SCHEMA_ELEM_NO_SPACE_AFTER_OID.get(s));
  }


  static int readOIDs(final String s, final int startPos, final int length,
                      final ArrayList<String> valueList)
      throws LDAPException
  {

    char c = s.charAt(startPos);
    if (c == '(')
    {
      int pos = startPos + 1;
      while (true)
      {
        pos = skipSpaces(s, pos, length);
        c = s.charAt(pos);
        if (c == ')')
        {
          pos++;
          break;
        }
        else if (c == '$')
        {
          pos++;
          pos = skipSpaces(s, pos, length);
          final StringBuilder buffer = new StringBuilder();
          pos = readOID(s, pos, length, buffer);
          valueList.add(buffer.toString());
        }
        else if (valueList.isEmpty())
        {
          final StringBuilder buffer = new StringBuilder();
          pos = readOID(s, pos, length, buffer);
          valueList.add(buffer.toString());
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                         ERR_SCHEMA_ELEM_UNEXPECTED_CHAR_IN_OID_LIST.get(s,
                              pos));
        }
      }

      if (valueList.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_SCHEMA_ELEM_EMPTY_OID_LIST.get(s));
      }

      if (pos >= length)
      {

        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_SCHEMA_ELEM_NO_SPACE_AFTER_OID_LIST.get(s));
      }

      return pos;
    }
    else
    {
      final StringBuilder buffer = new StringBuilder();
      final int returnPos = readOID(s, startPos, length, buffer);
      valueList.add(buffer.toString());
      return returnPos;
    }
  }


  static void encodeValue(final String value, final StringBuilder buffer)
  {
    final int length = value.length();
    for (int i=0; i < length; i++)
    {
      final char c = value.charAt(i);
      if ((c < ' ') || (c > '~') || (c == '\\') || (c == '\''))
      {
        hexEncode(c, buffer);
      }
      else
      {
        buffer.append(c);
      }
    }
  }


  public abstract int hashCode();


  public abstract boolean equals(final Object o);


  protected static boolean extensionsEqual(final Map<String,String[]> m1,
                                           final Map<String,String[]> m2)
  {
    if (m1.isEmpty())
    {
      return m2.isEmpty();
    }

    if (m1.size() != m2.size())
    {
      return false;
    }

    for (final Map.Entry<String,String[]> e : m1.entrySet())
    {
      final String[] v1 = e.getValue();
      final String[] v2 = m2.get(e.getKey());
      if (! arraysEqualOrderIndependent(v1, v2))
      {
        return false;
      }
    }

    return true;
  }

  @Override()
  public abstract String toString();
}

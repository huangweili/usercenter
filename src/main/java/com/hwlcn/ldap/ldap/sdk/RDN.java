package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Map;
import java.util.TreeMap;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.matchingrules.MatchingRule;
import com.hwlcn.ldap.ldap.sdk.schema.AttributeTypeDefinition;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RDN
       implements Comparable<RDN>, Comparator<RDN>, Serializable
{

  private static final long serialVersionUID = 2923419812807188487L;


  private final ASN1OctetString[] attributeValues;

  private final Schema schema;

  private volatile String normalizedString;

  private volatile String rdnString;

  private final String[] attributeNames;


  public RDN(final String attributeName, final String attributeValue)
  {
    this(attributeName, attributeValue, null);
  }


  public RDN(final String attributeName, final String attributeValue,
             final Schema schema)
  {
    ensureNotNull(attributeName, attributeValue);

    this.schema = schema;

    attributeNames  = new String[] { attributeName };
    attributeValues =
         new ASN1OctetString[] { new ASN1OctetString(attributeValue) };
  }



  public RDN(final String attributeName, final byte[] attributeValue)
  {
    this(attributeName, attributeValue, null);
  }


  public RDN(final String attributeName, final byte[] attributeValue,
             final Schema schema)
  {
    ensureNotNull(attributeName, attributeValue);

    this.schema = schema;

    attributeNames  = new String[] { attributeName };
    attributeValues =
         new ASN1OctetString[] { new ASN1OctetString(attributeValue) };
  }



  public RDN(final String[] attributeNames, final String[] attributeValues)
  {
    this(attributeNames, attributeValues, null);
  }


  public RDN(final String[] attributeNames, final String[] attributeValues,
             final Schema schema)
  {
    ensureNotNull(attributeNames, attributeValues);
    ensureTrue(attributeNames.length == attributeValues.length,
               "RDN.attributeNames and attributeValues must be the same size.");
    ensureTrue(attributeNames.length > 0,
               "RDN.attributeNames must not be empty.");

    this.attributeNames = attributeNames;
    this.schema         = schema;

    this.attributeValues = new ASN1OctetString[attributeValues.length];
    for (int i=0; i < attributeValues.length; i++)
    {
      this.attributeValues[i] = new ASN1OctetString(attributeValues[i]);
    }
  }



  public RDN(final String[] attributeNames, final byte[][] attributeValues)
  {
    this(attributeNames, attributeValues, null);
  }


  public RDN(final String[] attributeNames, final byte[][] attributeValues,
             final Schema schema)
  {
    ensureNotNull(attributeNames, attributeValues);
    ensureTrue(attributeNames.length == attributeValues.length,
               "RDN.attributeNames and attributeValues must be the same size.");
    ensureTrue(attributeNames.length > 0,
               "RDN.attributeNames must not be empty.");

    this.attributeNames = attributeNames;
    this.schema         = schema;

    this.attributeValues = new ASN1OctetString[attributeValues.length];
    for (int i=0; i < attributeValues.length; i++)
    {
      this.attributeValues[i] = new ASN1OctetString(attributeValues[i]);
    }
  }


  RDN(final String attributeName, final ASN1OctetString attributeValue,
      final Schema schema, final String rdnString)
  {
    this.rdnString = rdnString;
    this.schema    = schema;

    attributeNames  = new String[] { attributeName };
    attributeValues = new ASN1OctetString[] { attributeValue };
  }

  RDN(final String[] attributeNames, final ASN1OctetString[] attributeValues,
      final Schema schema, final String rdnString)
  {
    this.rdnString = rdnString;
    this.schema    = schema;

    this.attributeNames  = attributeNames;
    this.attributeValues = attributeValues;
  }


  public RDN(final String rdnString)
         throws LDAPException
  {
    this(rdnString, (Schema) null);
  }



  public RDN(final String rdnString, final Schema schema)
         throws LDAPException
  {
    ensureNotNull(rdnString);

    this.rdnString = rdnString;
    this.schema    = schema;

    int pos = 0;
    final int length = rdnString.length();

  while ((pos < length) && (rdnString.charAt(pos) == ' '))
    {
      pos++;
    }

    int attrStartPos = pos;
    while (pos < length)
    {
      final char c = rdnString.charAt(pos);
      if ((c == ' ') || (c == '='))
      {
        break;
      }

      pos++;
    }


    String attrName = rdnString.substring(attrStartPos, pos);
    if (attrName.length() == 0)
    {
      throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                              ERR_RDN_NO_ATTR_NAME.get());
    }

    while ((pos < length) && (rdnString.charAt(pos) == ' '))
    {
      pos++;
    }

    if ((pos >= length) || (rdnString.charAt(pos) != '='))
    {
      throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                              ERR_RDN_NO_EQUAL_SIGN.get(attrName));
    }

    pos++;
    while ((pos < length) && (rdnString.charAt(pos) == ' '))
    {
      pos++;
    }


    if (pos >= length)
    {
      throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                              ERR_RDN_NO_ATTR_VALUE.get(attrName));
    }

   ASN1OctetString value;
    if (rdnString.charAt(pos) == '#')
    {

      final byte[] valueArray = readHexString(rdnString, ++pos);
      value = new ASN1OctetString(valueArray);
      pos += (valueArray.length * 2);
    }
    else
    {
      final StringBuilder buffer = new StringBuilder();
      pos = readValueString(rdnString, pos, buffer);
      value = new ASN1OctetString(buffer.toString());
    }


    while ((pos < length) && (rdnString.charAt(pos) == ' '))
    {
      pos++;
    }

    if (pos >= length)
    {
      attributeNames  = new String[] { attrName };
      attributeValues = new ASN1OctetString[] { value };
      return;
    }


    final ArrayList<String> nameList = new ArrayList<String>(5);
    final ArrayList<ASN1OctetString> valueList =
         new ArrayList<ASN1OctetString>(5);
    nameList.add(attrName);
    valueList.add(value);

    if (rdnString.charAt(pos) == '+')
    {
      pos++;
    }
    else
    {
      throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                              ERR_RDN_VALUE_NOT_FOLLOWED_BY_PLUS.get());
    }

    if (pos >= length)
    {
      throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                              ERR_RDN_PLUS_NOT_FOLLOWED_BY_AVP.get());
    }

    int numValues = 1;
    while (pos < length)
    {
      while ((pos < length) && (rdnString.charAt(pos) == ' '))
      {
        pos++;
      }

      attrStartPos = pos;
      while (pos < length)
      {
        final char c = rdnString.charAt(pos);
        if ((c == ' ') || (c == '='))
        {
          break;
        }

        pos++;
      }

      attrName = rdnString.substring(attrStartPos, pos);
      if (attrName.length() == 0)
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                ERR_RDN_NO_ATTR_NAME.get());
      }

      while ((pos < length) && (rdnString.charAt(pos) == ' '))
      {
        pos++;
      }

      if ((pos >= length) || (rdnString.charAt(pos) != '='))
      {

         throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                ERR_RDN_NO_EQUAL_SIGN.get(attrName));
      }

      pos++;
      while ((pos < length) && (rdnString.charAt(pos) == ' '))
      {
        pos++;
      }

      if (pos >= length)
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                ERR_RDN_NO_ATTR_VALUE.get(attrName));
      }


      if (rdnString.charAt(pos) == '#')
      {
        final byte[] valueArray = readHexString(rdnString, ++pos);
        value = new ASN1OctetString(valueArray);
        pos += (valueArray.length * 2);
      }
      else
      {
        final StringBuilder buffer = new StringBuilder();
        pos = readValueString(rdnString, pos, buffer);
        value = new ASN1OctetString(buffer.toString());
      }


      while ((pos < length) && (rdnString.charAt(pos) == ' '))
      {
        pos++;
      }

      nameList.add(attrName);
      valueList.add(value);
      numValues++;

      if (pos >= length)
      {
        break;
      }
      else
      {

        if (rdnString.charAt(pos) == '+')
        {
          pos++;
        }
        else
        {
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                  ERR_RDN_VALUE_NOT_FOLLOWED_BY_PLUS.get());
        }
      }

      if (pos >= length)
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                ERR_RDN_PLUS_NOT_FOLLOWED_BY_AVP.get());
      }
    }

    attributeNames  = new String[numValues];
    attributeValues = new ASN1OctetString[numValues];
    for (int i=0; i < numValues; i++)
    {
      attributeNames[i]  = nameList.get(i);
      attributeValues[i] = valueList.get(i);
    }
  }


  static byte[] readHexString(final String rdnString, final int startPos)
         throws LDAPException
  {
    final int length = rdnString.length();
    int pos = startPos;

    final ByteBuffer buffer = ByteBuffer.allocate(length-pos);
hexLoop:
    while (pos < length)
    {
      byte hexByte;
      switch (rdnString.charAt(pos++))
      {
        case '0':
          hexByte = 0x00;
          break;
        case '1':
          hexByte = 0x10;
          break;
        case '2':
          hexByte = 0x20;
          break;
        case '3':
          hexByte = 0x30;
          break;
        case '4':
          hexByte = 0x40;
          break;
        case '5':
          hexByte = 0x50;
          break;
        case '6':
          hexByte = 0x60;
          break;
        case '7':
          hexByte = 0x70;
          break;
        case '8':
          hexByte = (byte) 0x80;
          break;
        case '9':
          hexByte = (byte) 0x90;
          break;
        case 'a':
        case 'A':
          hexByte = (byte) 0xA0;
          break;
        case 'b':
        case 'B':
          hexByte = (byte) 0xB0;
          break;
        case 'c':
        case 'C':
          hexByte = (byte) 0xC0;
          break;
        case 'd':
        case 'D':
          hexByte = (byte) 0xD0;
          break;
        case 'e':
        case 'E':
          hexByte = (byte) 0xE0;
          break;
        case 'f':
        case 'F':
          hexByte = (byte) 0xF0;
          break;
        case ' ':
        case '+':
        case ',':
        case ';':
          break hexLoop;
        default:
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                  ERR_RDN_INVALID_HEX_CHAR.get(
                                       rdnString.charAt(pos-1), (pos-1)));
      }

      if (pos >= length)
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                ERR_RDN_MISSING_HEX_CHAR.get());
      }

      switch (rdnString.charAt(pos++))
      {
        case '0':
          break;
        case '1':
          hexByte |= 0x01;
          break;
        case '2':
          hexByte |= 0x02;
          break;
        case '3':
          hexByte |= 0x03;
          break;
        case '4':
          hexByte |= 0x04;
          break;
        case '5':
          hexByte |= 0x05;
          break;
        case '6':
          hexByte |= 0x06;
          break;
        case '7':
          hexByte |= 0x07;
          break;
        case '8':
          hexByte |= 0x08;
          break;
        case '9':
          hexByte |= 0x09;
          break;
        case 'a':
        case 'A':
          hexByte |= 0x0A;
          break;
        case 'b':
        case 'B':
          hexByte |= 0x0B;
          break;
        case 'c':
        case 'C':
          hexByte |= 0x0C;
          break;
        case 'd':
        case 'D':
          hexByte |= 0x0D;
          break;
        case 'e':
        case 'E':
          hexByte |= 0x0E;
          break;
        case 'f':
        case 'F':
          hexByte |= 0x0F;
          break;
        default:
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                  ERR_RDN_INVALID_HEX_CHAR.get(
                                       rdnString.charAt(pos-1), (pos-1)));
      }

      buffer.put(hexByte);
    }

    buffer.flip();
    final byte[] valueArray = new byte[buffer.limit()];
    buffer.get(valueArray);
    return valueArray;
  }



  static int readValueString(final String rdnString, final int startPos,
                             final StringBuilder buffer)
          throws LDAPException
  {
    final int bufferLength = buffer.length();
    final int length       = rdnString.length();
    int pos = startPos;

    boolean inQuotes = false;
valueLoop:
    while (pos < length)
    {
      char c = rdnString.charAt(pos);
      switch (c)
      {
        case '\\':

          if ((pos+1) >= length)
          {
            throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                    ERR_RDN_ENDS_WITH_BACKSLASH.get());
          }
          else
          {
            pos++;
            c = rdnString.charAt(pos);
            if (isHex(c))
            {

              pos = readEscapedHexString(rdnString, pos, buffer) - 1;
            }
            else
            {
              buffer.append(c);
            }
          }
          break;

        case '"':
          if (inQuotes)
          {

            pos++;
            while (pos < length)
            {
              c = rdnString.charAt(pos);
              if ((c == '+') || (c == ',') || (c == ';'))
              {
                break;
              }
              else if (c != ' ')
              {
                throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                        ERR_RDN_CHAR_OUTSIDE_QUOTES.get(c,
                                             (pos-1)));
              }

              pos++;
            }

            inQuotes = false;
            break valueLoop;
          }
          else
          {

            if (pos == startPos)
            {
              inQuotes = true;
            }
            else
            {
              throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                      ERR_RDN_UNEXPECTED_DOUBLE_QUOTE.get(pos));
            }
          }
          break;

        case ' ':

          if (inQuotes ||
              (((pos+1) < length) && (rdnString.charAt(pos+1) != ' ')))
          {
            buffer.append(' ');
          }
          break;

        case ',':
        case ';':
        case '+':
          if (inQuotes)
          {
            buffer.append(c);
          }
          else
          {
            break valueLoop;
          }
          break;

        default:
          buffer.append(c);
          break;
      }

      pos++;
    }


    if (inQuotes)
    {
      throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                              ERR_RDN_UNCLOSED_DOUBLE_QUOTE.get());
    }


    int bufferPos = buffer.length() - 1;
    int rdnStrPos = pos - 2;
    while ((bufferPos > 0) && (buffer.charAt(bufferPos) == ' '))
    {
      if (rdnString.charAt(rdnStrPos) == '\\')
      {
        break;
      }
      else
      {
        buffer.deleteCharAt(bufferPos--);
        rdnStrPos--;
      }
    }


    if (buffer.length() == bufferLength)
    {
      throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                              ERR_RDN_EMPTY_VALUE.get());
    }

    return pos;
  }


  private static int readEscapedHexString(final String rdnString,
                                          final int startPos,
                                          final StringBuilder buffer)
          throws LDAPException
  {
    final int length = rdnString.length();
    int pos = startPos;

    final ByteBuffer byteBuffer = ByteBuffer.allocate(length - pos);
    while (pos < length)
    {
      byte b;
      switch (rdnString.charAt(pos++))
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
                                  ERR_RDN_INVALID_HEX_CHAR.get(
                                       rdnString.charAt(pos-1), (pos-1)));
      }

      if (pos >= length)
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                                ERR_RDN_MISSING_HEX_CHAR.get());
      }

      switch (rdnString.charAt(pos++))
      {
        case '0':

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
                                  ERR_RDN_INVALID_HEX_CHAR.get(
                                       rdnString.charAt(pos-1), (pos-1)));
      }

      byteBuffer.put(b);
      if (((pos+1) < length) && (rdnString.charAt(pos) == '\\') &&
          isHex(rdnString.charAt(pos+1)))
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


  public static boolean isValidRDN(final String s)
  {
    try
    {
      new RDN(s);
      return true;
    }
    catch (LDAPException le)
    {
      return false;
    }
  }



  public boolean isMultiValued()
  {
    return (attributeNames.length != 1);
  }


  public String[] getAttributeNames()
  {
    return attributeNames;
  }

  public String[] getAttributeValues()
  {
    final String[] stringValues = new String[attributeValues.length];
    for (int i=0; i < stringValues.length; i++)
    {
      stringValues[i] = attributeValues[i].stringValue();
    }

    return stringValues;
  }


  public byte[][] getByteArrayAttributeValues()
  {
    final byte[][] byteValues = new byte[attributeValues.length][];
    for (int i=0; i < byteValues.length; i++)
    {
      byteValues[i] = attributeValues[i].getValue();
    }

    return byteValues;
  }


  Schema getSchema()
  {
    return schema;
  }


  public boolean hasAttribute(final String attributeName)
  {
    for (final String name : attributeNames)
    {
      if (name.equalsIgnoreCase(attributeName))
      {
        return true;
      }
    }

    return false;
  }



  public boolean hasAttributeValue(final String attributeName,
                                   final String attributeValue)
  {
    for (int i=0; i < attributeNames.length; i++)
    {
      if (attributeNames[i].equalsIgnoreCase(attributeName))
      {
        final Attribute a =
             new Attribute(attributeName, schema, attributeValue);
        final Attribute b = new Attribute(attributeName, schema,
             attributeValues[i].stringValue());

        if (a.equals(b))
        {
          return true;
        }
      }
    }

    return false;
  }


  public boolean hasAttributeValue(final String attributeName,
                                   final byte[] attributeValue)
  {
    for (int i=0; i < attributeNames.length; i++)
    {
      if (attributeNames[i].equalsIgnoreCase(attributeName))
      {
        final Attribute a =
             new Attribute(attributeName, schema, attributeValue);
        final Attribute b = new Attribute(attributeName, schema,
             attributeValues[i].getValue());

        if (a.equals(b))
        {
          return true;
        }
      }
    }

    return false;
  }


  @Override()
  public String toString()
  {
    if (rdnString == null)
    {
      final StringBuilder buffer = new StringBuilder();
      toString(buffer, false);
      rdnString = buffer.toString();
    }

    return rdnString;
  }



  public String toMinimallyEncodedString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer, true);
    return buffer.toString();
  }



  public void toString(final StringBuilder buffer)
  {
    toString(buffer, false);
  }


  public void toString(final StringBuilder buffer,
                       final boolean minimizeEncoding)
  {
    if ((rdnString != null) && (! minimizeEncoding))
    {
      buffer.append(rdnString);
      return;
    }

    for (int i=0; i < attributeNames.length; i++)
    {
      if (i > 0)
      {
        buffer.append('+');
      }

      buffer.append(attributeNames[i]);
      buffer.append('=');


      final String valueString = attributeValues[i].stringValue();
      final int length = valueString.length();
      for (int j=0; j < length; j++)
      {
        final char c = valueString.charAt(j);
        switch (c)
        {
          case '\\':
          case '#':
          case '=':
          case '"':
          case '+':
          case ',':
          case ';':
          case '<':
          case '>':
            buffer.append('\\');
            buffer.append(c);
            break;

          case ' ':

            if ((j == 0) || ((j+1) == length) ||
                (((j+1) < length) && (valueString.charAt(j+1) == ' ')))
            {
              buffer.append("\\ ");
            }
            else
            {
              buffer.append(' ');
            }
            break;

          case '\u0000':
            buffer.append("\\00");
            break;

          default:

            if ((! minimizeEncoding) && ((c < ' ') || (c > '~')))
            {
              hexEncode(c, buffer);
            }
            else
            {
              buffer.append(c);
            }
            break;
        }
      }
    }
  }


  public String toNormalizedString()
  {
    if (normalizedString == null)
    {
      final StringBuilder buffer = new StringBuilder();
      toNormalizedString(buffer);
      normalizedString = buffer.toString();
    }

    return normalizedString;
  }



  public void toNormalizedString(final StringBuilder buffer)
  {
    if (attributeNames.length == 1)
    {
      final String name = normalizeAttrName(attributeNames[0]);
      buffer.append(name);
      buffer.append('=');
      buffer.append(normalizeValue(name, attributeValues[0]));
    }
    else
    {
      final TreeMap<String,ASN1OctetString> valueMap =
           new TreeMap<String,ASN1OctetString>();
      for (int i=0; i < attributeNames.length; i++)
      {
        final String name = normalizeAttrName(attributeNames[i]);
        valueMap.put(name, attributeValues[i]);
      }

      int i=0;
      for (final Map.Entry<String,ASN1OctetString> entry : valueMap.entrySet())
      {
        if (i++ > 0)
        {
          buffer.append('+');
        }

        buffer.append(entry.getKey());
        buffer.append('=');
        buffer.append(normalizeValue(entry.getKey(), entry.getValue()));
      }
    }
  }



  private String normalizeAttrName(final String name)
  {
    String n = name;
    if (schema != null)
    {
      final AttributeTypeDefinition at = schema.getAttributeType(name);
      if (at != null)
      {
        n = at.getNameOrOID();
      }
    }
    return toLowerCase(n);
  }


  public static String normalize(final String s)
         throws LDAPException
  {
    return normalize(s, null);
  }


  public static String normalize(final String s, final Schema schema)
         throws LDAPException
  {
    return new RDN(s, schema).toNormalizedString();
  }



  private StringBuilder normalizeValue(final String attributeName,
                                       final ASN1OctetString value)
  {
    final MatchingRule matchingRule =
         MatchingRule.selectEqualityMatchingRule(attributeName, schema);

    ASN1OctetString rawNormValue;
    try
    {
      rawNormValue = matchingRule.normalize(value);
    }
    catch (final Exception e)
    {
      debugException(e);
      rawNormValue =
           new ASN1OctetString(toLowerCase(value.stringValue()));
    }

    final String valueString = rawNormValue.stringValue();
    final int length = valueString.length();
    final StringBuilder buffer = new StringBuilder(length);

    for (int i=0; i < length; i++)
    {
      final char c = valueString.charAt(i);

      switch (c)
      {
        case '\\':
        case '#':
        case '=':
        case '"':
        case '+':
        case ',':
        case ';':
        case '<':
        case '>':
          buffer.append('\\');
          buffer.append(c);
          break;

        case ' ':
          if ((i == 0) || ((i+1) == length) ||
              (((i+1) < length) && (valueString.charAt(i+1) == ' ')))
          {
            buffer.append("\\ ");
          }
          else
          {
            buffer.append(' ');
          }
          break;

        default:
         if ((c < ' ') || (c > '~'))
          {
            hexEncode(c, buffer);
          }
          else
          {
            buffer.append(c);
          }
          break;
      }
    }

    return buffer;
  }


  @Override()
  public int hashCode()
  {
    return toNormalizedString().hashCode();
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

    if (! (o instanceof RDN))
    {
      return false;
    }

    final RDN rdn = (RDN) o;
    return (toNormalizedString().equals(rdn.toNormalizedString()));
  }



  public boolean equals(final String s)
         throws LDAPException
  {
    if (s == null)
    {
      return false;
    }

    return equals(new RDN(s, schema));
  }


  public static boolean equals(final String s1, final String s2)
         throws LDAPException
  {
    return new RDN(s1).equals(new RDN(s2));
  }


  public int compareTo(final RDN rdn)
  {
    return compare(this, rdn);
  }



  public int compare(final RDN rdn1, final RDN rdn2)
  {
    ensureNotNull(rdn1, rdn2);

    return(rdn1.toNormalizedString().compareTo(rdn2.toNormalizedString()));
  }



  public static int compare(final String s1, final String s2)
         throws LDAPException
  {
    return compare(s1, s2, null);
  }


  public static int compare(final String s1, final String s2,
                            final Schema schema)
         throws LDAPException
  {
    return new RDN(s1, schema).compareTo(new RDN(s2, schema));
  }
}

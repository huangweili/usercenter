package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;

import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1BufferSet;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Enumerated;
import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1Set;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSet;
import com.hwlcn.ldap.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.hwlcn.ldap.util.Base64;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Modification
       implements Serializable
{
  private static final ASN1OctetString[] NO_VALUES = new ASN1OctetString[0];

  private static final byte[][] NO_BYTE_VALUES = new byte[0][];

  private static final long serialVersionUID = 5170107037390858876L;

  private final ASN1OctetString[] values;

  private final ModificationType modificationType;

  private final String attributeName;

  public Modification(final ModificationType modificationType,
                      final String attributeName)
  {
    ensureNotNull(attributeName);

    this.modificationType = modificationType;
    this.attributeName    = attributeName;

    values = NO_VALUES;
  }


  public Modification(final ModificationType modificationType,
                      final String attributeName, final String attributeValue)
  {
    ensureNotNull(attributeName, attributeValue);

    this.modificationType = modificationType;
    this.attributeName    = attributeName;

    values = new ASN1OctetString[] { new ASN1OctetString(attributeValue) };
  }


  public Modification(final ModificationType modificationType,
                      final String attributeName, final byte[] attributeValue)
  {
    ensureNotNull(attributeName, attributeValue);

    this.modificationType = modificationType;
    this.attributeName    = attributeName;

    values = new ASN1OctetString[] { new ASN1OctetString(attributeValue) };
  }


  public Modification(final ModificationType modificationType,
                      final String attributeName,
                      final String... attributeValues)
  {
    ensureNotNull(attributeName, attributeValues);

    this.modificationType = modificationType;
    this.attributeName    = attributeName;

    values = new ASN1OctetString[attributeValues.length];
    for (int i=0; i < values.length; i++)
    {
      values[i] = new ASN1OctetString(attributeValues[i]);
    }
  }


  public Modification(final ModificationType modificationType,
                      final String attributeName,
                      final byte[]... attributeValues)
  {
    ensureNotNull(attributeName, attributeValues);

    this.modificationType = modificationType;
    this.attributeName    = attributeName;

    values = new ASN1OctetString[attributeValues.length];
    for (int i=0; i < values.length; i++)
    {
      values[i] = new ASN1OctetString(attributeValues[i]);
    }
  }


  public Modification(final ModificationType modificationType,
                      final String attributeName,
                      final ASN1OctetString[] attributeValues)
  {
    this.modificationType = modificationType;
    this.attributeName    = attributeName;
    values                = attributeValues;
  }


  public ModificationType getModificationType()
  {
    return modificationType;
  }


  public Attribute getAttribute()
  {
    return new Attribute(attributeName,
                         CaseIgnoreStringMatchingRule.getInstance(), values);
  }


  public String getAttributeName()
  {
    return attributeName;
  }


  public boolean hasValue()
  {
    return (values.length > 0);
  }


  public String[] getValues()
  {
    if (values.length == 0)
    {
      return NO_STRINGS;
    }
    else
    {
      final String[] stringValues = new String[values.length];
      for (int i=0; i < values.length; i++)
      {
        stringValues[i] = values[i].stringValue();
      }

      return stringValues;
    }
  }


  public byte[][] getValueByteArrays()
  {
    if (values.length == 0)
    {
      return NO_BYTE_VALUES;
    }
    else
    {
      final byte[][] byteValues = new byte[values.length][];
      for (int i=0; i < values.length; i++)
      {
        byteValues[i] = values[i].getValue();
      }

      return byteValues;
    }
  }



  public ASN1OctetString[] getRawValues()
  {
    return values;
  }


  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence modSequence = buffer.beginSequence();
    buffer.addEnumerated(modificationType.intValue());

    final ASN1BufferSequence attrSequence = buffer.beginSequence();
    buffer.addOctetString(attributeName);

    final ASN1BufferSet valueSet = buffer.beginSet();
    for (final ASN1OctetString v : values)
    {
      buffer.addElement(v);
    }
    valueSet.end();
    attrSequence.end();
    modSequence.end();
  }


  public ASN1Sequence encode()
  {
    final ASN1Element[] attrElements =
    {
      new ASN1OctetString(attributeName),
      new ASN1Set(values)
    };

    final ASN1Element[] modificationElements =
    {
      new ASN1Enumerated(modificationType.intValue()),
      new ASN1Sequence(attrElements)
    };

    return new ASN1Sequence(modificationElements);
  }


  public static Modification readFrom(final ASN1StreamReader reader)
         throws LDAPException
  {
    try
    {
      ensureNotNull(reader.beginSequence());
      final ModificationType modType =
           ModificationType.valueOf(reader.readEnumerated());

      ensureNotNull(reader.beginSequence());
      final String attrName = reader.readString();

      final ArrayList<ASN1OctetString> valueList =
           new ArrayList<ASN1OctetString>(5);
      final ASN1StreamReaderSet valueSet = reader.beginSet();
      while (valueSet.hasMoreElements())
      {
        valueList.add(new ASN1OctetString(reader.readBytes()));
      }

      final ASN1OctetString[] values = new ASN1OctetString[valueList.size()];
      valueList.toArray(values);

      return new Modification(modType, attrName, values);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MOD_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }


  public static Modification decode(final ASN1Sequence modificationSequence)
         throws LDAPException
  {
    ensureNotNull(modificationSequence);

    final ASN1Element[] modificationElements = modificationSequence.elements();
    if (modificationElements.length != 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MOD_DECODE_INVALID_ELEMENT_COUNT.get(
                                   modificationElements.length));
    }

    final int modType;
    try
    {
      final ASN1Enumerated typeEnumerated =
           ASN1Enumerated.decodeAsEnumerated(modificationElements[0]);
      modType = typeEnumerated.intValue();
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MOD_DECODE_CANNOT_PARSE_MOD_TYPE.get(getExceptionMessage(ae)),
           ae);
    }

    final ASN1Sequence attrSequence;
    try
    {
      attrSequence = ASN1Sequence.decodeAsSequence(modificationElements[1]);
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MOD_DECODE_CANNOT_PARSE_ATTR.get(getExceptionMessage(ae)), ae);
    }

    final ASN1Element[] attrElements = attrSequence.elements();
    if (attrElements.length != 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MOD_DECODE_INVALID_ATTR_ELEMENT_COUNT.get(
                                   attrElements.length));
    }

    final String attrName =
         ASN1OctetString.decodeAsOctetString(attrElements[0]).stringValue();

    final ASN1Set valueSet;
    try
    {
      valueSet = ASN1Set.decodeAsSet(attrElements[1]);
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MOD_DECODE_CANNOT_PARSE_ATTR_VALUE_SET.get(
                                   getExceptionMessage(ae)), ae);
    }

    final ASN1Element[] valueElements = valueSet.elements();
    final ASN1OctetString[] values = new ASN1OctetString[valueElements.length];
    for (int i=0; i < values.length; i++)
    {
      values[i] = ASN1OctetString.decodeAsOctetString(valueElements[i]);
    }

    return new Modification(ModificationType.valueOf(modType), attrName,
                            values);
  }


  @Override()
  public int hashCode()
  {
    int hashCode = modificationType.intValue() +
                   toLowerCase(attributeName).hashCode();

    for (final ASN1OctetString value : values)
    {
      hashCode += value.hashCode();
    }

    return hashCode;
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

    if (! (o instanceof Modification))
    {
      return false;
    }

    final Modification mod = (Modification) o;
    if (modificationType != mod.modificationType)
    {
      return false;
    }

    if (! attributeName.equalsIgnoreCase(mod.attributeName))
    {
      return false;
    }

    if (values.length != mod.values.length)
    {
      return false;
    }

    for (final ASN1OctetString value : values)
    {
      boolean found = false;
      for (int j = 0; j < mod.values.length; j++)
      {
        if (value.equalsIgnoreType(mod.values[j]))
        {
          found = true;
          break;
        }
      }

      if (!found)
      {
        return false;
      }
    }

    return true;
  }


  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDAPModification(type=");

    switch (modificationType.intValue())
    {
      case 0:
        buffer.append("add");
        break;
      case 1:
        buffer.append("delete");
        break;
      case 2:
        buffer.append("replace");
        break;
      case 3:
        buffer.append("increment");
        break;
      default:
        buffer.append(modificationType);
        break;
    }

    buffer.append(", attr=");
    buffer.append(attributeName);

    if (values.length == 0)
    {
      buffer.append(", values={");
    }
    else if (needsBase64Encoding())
    {
      buffer.append(", base64Values={'");

      for (int i=0; i < values.length; i++)
      {
        if (i > 0)
        {
          buffer.append("', '");
        }

        buffer.append(Base64.encode(values[i].getValue()));
      }

      buffer.append('\'');
    }
    else
    {
      buffer.append(", values={'");

      for (int i=0; i < values.length; i++)
      {
        if (i > 0)
        {
          buffer.append("', '");
        }

        buffer.append(values[i].stringValue());
      }

      buffer.append('\'');
    }

    buffer.append("})");
  }

  private boolean needsBase64Encoding()
  {
    for (final ASN1OctetString s : values)
    {
      if (Attribute.needsBase64Encoding(s.getValue()))
      {
        return true;
      }
    }

    return false;
  }
}

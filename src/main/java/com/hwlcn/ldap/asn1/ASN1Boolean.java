package com.hwlcn.ldap.asn1;


import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.asn1.ASN1Constants.*;
import static com.hwlcn.ldap.asn1.ASN1Messages.*;
import static com.hwlcn.ldap.util.Debug.*;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ASN1Boolean
       extends ASN1Element
{

  public static final ASN1Boolean UNIVERSAL_BOOLEAN_FALSE_ELEMENT =
         new ASN1Boolean(false);


  public static final ASN1Boolean UNIVERSAL_BOOLEAN_TRUE_ELEMENT =
         new ASN1Boolean(true);


  private static final long serialVersionUID = 7131700816847855524L;

  private final boolean booleanValue;

  public ASN1Boolean(final boolean booleanValue)
  {
    super(UNIVERSAL_BOOLEAN_TYPE,
          (booleanValue ? BOOLEAN_VALUE_TRUE : BOOLEAN_VALUE_FALSE));

    this.booleanValue = booleanValue;
  }


  public ASN1Boolean(final byte type, final boolean booleanValue)
  {
    super(type, (booleanValue ? BOOLEAN_VALUE_TRUE : BOOLEAN_VALUE_FALSE));

    this.booleanValue = booleanValue;
  }



  private ASN1Boolean(final byte type, final boolean booleanValue,
                      final byte[] value)
  {
    super(type, value);

    this.booleanValue = booleanValue;
  }



  public boolean booleanValue()
  {
    return booleanValue;
  }



  public static ASN1Boolean decodeAsBoolean(final byte[] elementBytes)
         throws ASN1Exception
  {
    try
    {
      int valueStartPos = 2;
      int length = (elementBytes[1] & 0x7F);
      if (length != elementBytes[1])
      {
        final int numLengthBytes = length;

        length = 0;
        for (int i=0; i < numLengthBytes; i++)
        {
          length <<= 8;
          length |= (elementBytes[valueStartPos++] & 0xFF);
        }
      }

      if ((elementBytes.length - valueStartPos) != length)
      {
        throw new ASN1Exception(ERR_ELEMENT_LENGTH_MISMATCH.get(length,
                                     (elementBytes.length - valueStartPos)));
      }

      if (length != 1)
      {
        throw new ASN1Exception(ERR_BOOLEAN_INVALID_LENGTH.get());
      }

      final byte[] value = { elementBytes[valueStartPos] };
      final boolean booleanValue = (value[0] != 0x00);
      return new ASN1Boolean(elementBytes[0], booleanValue, value);
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw ae;
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new ASN1Exception(ERR_ELEMENT_DECODE_EXCEPTION.get(e), e);
    }
  }



  public static ASN1Boolean decodeAsBoolean(final ASN1Element element)
         throws ASN1Exception
  {
    final byte[] value = element.getValue();
    if (value.length != 1)
    {
      throw new ASN1Exception(ERR_BOOLEAN_INVALID_LENGTH.get());
    }

    if (value[0] == 0x00)
    {
      return new ASN1Boolean(element.getType(), false, value);
    }
    else
    {
      return new ASN1Boolean(element.getType(), true, value);
    }
  }


  @Override
  public void toString(final StringBuilder buffer)
  {
    buffer.append(booleanValue);
  }
}

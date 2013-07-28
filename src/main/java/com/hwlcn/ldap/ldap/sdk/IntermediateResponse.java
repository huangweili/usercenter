package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;



@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class IntermediateResponse
       implements Serializable, LDAPResponse
{

  protected static final byte TYPE_INTERMEDIATE_RESPONSE_OID = (byte) 0x80;

  protected static final byte TYPE_INTERMEDIATE_RESPONSE_VALUE = (byte) 0x81;

  private static final Control[] NO_CONTROLS = new Control[0];

  private static final long serialVersionUID = 218434694212935869L;



  private final ASN1OctetString value;

  private final Control[] controls;

  private final int messageID;

  private final String oid;



  public IntermediateResponse(final String oid, final ASN1OctetString value)
  {
    this(-1, oid, value, NO_CONTROLS);
  }



  public IntermediateResponse(final int messageID, final String oid,
                              final ASN1OctetString value)
  {
    this(messageID, oid, value, NO_CONTROLS);
  }



  public IntermediateResponse(final String oid, final ASN1OctetString value,
                              final Control[] controls)
  {
    this(-1, oid, value, controls);
  }


  public IntermediateResponse(final int messageID, final String oid,
                              final ASN1OctetString value,
                              final Control[] controls)
  {
    this.messageID = messageID;
    this.oid       = oid;
    this.value     = value;

    if (controls == null)
    {
      this.controls = NO_CONTROLS;
    }
    else
    {
      this.controls = controls;
    }
  }


  protected IntermediateResponse(
                 final IntermediateResponse intermediateResponse)
  {
    messageID = intermediateResponse.messageID;
    oid       = intermediateResponse.oid;
    value     = intermediateResponse.value;
    controls  = intermediateResponse.controls;
  }




  static IntermediateResponse readFrom(final int messageID,
              final ASN1StreamReaderSequence messageSequence,
              final ASN1StreamReader reader)
         throws LDAPException
  {
    try
    {
      String oid = null;
      ASN1OctetString value = null;

      final ASN1StreamReaderSequence opSequence = reader.beginSequence();
      while (opSequence.hasMoreElements())
      {
        final byte type = (byte) reader.peek();
        switch (type)
        {
          case TYPE_INTERMEDIATE_RESPONSE_OID:
            oid = reader.readString();
            break;
          case TYPE_INTERMEDIATE_RESPONSE_VALUE:
            value = new ASN1OctetString(type, reader.readBytes());
            break;
          default:
        }
      }

      final Control[] controls;
      if (messageSequence.hasMoreElements())
      {
        final ArrayList<Control> controlList = new ArrayList<Control>(1);
        final ASN1StreamReaderSequence controlSequence = reader.beginSequence();
        while (controlSequence.hasMoreElements())
        {
          controlList.add(Control.readFrom(reader));
        }

        controls = new Control[controlList.size()];
        controlList.toArray(controls);
      }
      else
      {
        controls = NO_CONTROLS;
      }

      return new IntermediateResponse(messageID, oid, value, controls);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_INTERMEDIATE_RESPONSE_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }



  public int getMessageID()
  {
    return messageID;
  }


  public final String getOID()
  {
    return oid;
  }



  public final ASN1OctetString getValue()
  {
    return value;
  }



  public final Control[] getControls()
  {
    return controls;
  }


  public final Control getControl(final String oid)
  {
    for (final Control c : controls)
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    return null;
  }


  public String getIntermediateResponseName()
  {
      return oid;
  }



  public String valueToString()
  {
    return null;
  }



  @Override()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  public void toString(final StringBuilder buffer)
  {
    buffer.append("IntermediateResponse(");

    boolean added = false;

    if (messageID >= 0)
    {
      buffer.append("messageID=");
      buffer.append(messageID);
      added = true;
    }

    if (oid != null)
    {
      if (added)
      {
        buffer.append(", ");
      }

      buffer.append("oid='");
      buffer.append(oid);
      buffer.append('\'');
      added = true;
    }

    if (controls.length > 0)
    {
      if (added)
      {
        buffer.append(", ");
      }

      buffer.append("controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}

package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

import com.hwlcn.ldap.asn1.ASN1Boolean;
import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.asn1.ASN1Constants.*;
import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;


@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class Control
       implements Serializable
{

  private static final byte CONTROLS_TYPE = (byte) 0xA0;


  private static final ConcurrentHashMap<String,DecodeableControl>
       decodeableControlMap = new ConcurrentHashMap<String,DecodeableControl>();

  private static final long serialVersionUID = 4440956109070220054L;

  private final ASN1OctetString value;

  private final boolean isCritical;

  private final String oid;



  static
  {
    try
    {
      final Class<?> unboundIDControlHelperClass = Class.forName(
           "com.hwlcn.ldap.ldap.sdk.controls.ControlHelper");
      final Method method = unboundIDControlHelperClass.getMethod(
           "registerDefaultResponseControls");
      method.invoke(null);
    }
    catch (Exception e)
    {

    }

    try
    {
      final Class<?> unboundIDControlHelperClass = Class.forName(
           "com.hwlcn.ldap.ldap.sdk.experimental.ControlHelper");
      final Method method = unboundIDControlHelperClass.getMethod(
           "registerDefaultResponseControls");
      method.invoke(null);
    }
    catch (Exception e)
    {
    }

    try
    {
      final Class<?> unboundIDControlHelperClass = Class.forName(
           "com.hwlcn.ldap.ldap.sdk.unboundidds.controls.ControlHelper");
      final Method method = unboundIDControlHelperClass.getMethod(
           "registerDefaultResponseControls");
      method.invoke(null);
    }
    catch (Exception e)
    {

      try
      {
        final Class<?> experimentalControlHelperClass = Class.forName(
             "com.hwlcn.ldap.ldap.sdk.experimental.ControlHelper");
        final Method method = experimentalControlHelperClass.getMethod(
             "registerNonCommercialResponseControls");
        method.invoke(null);
      }
      catch (Exception e2)
      {
      }
    }
  }


  protected Control()
  {
    oid        = null;
    isCritical = true;
    value      = null;
  }


  protected Control(final Control control)
  {
    oid        = control.oid;
    isCritical = control.isCritical;
    value      = control.value;
  }


  public Control(final String oid)
  {
    ensureNotNull(oid);

    this.oid   = oid;
    isCritical = false;
    value      = null;
  }


  public Control(final String oid, final boolean isCritical)
  {
    ensureNotNull(oid);

    this.oid        = oid;
    this.isCritical = isCritical;
    value           = null;
  }

  public Control(final String oid, final boolean isCritical,
                 final ASN1OctetString value)
  {
    ensureNotNull(oid);

    this.oid        = oid;
    this.isCritical = isCritical;
    this.value      = value;
  }

  public final String getOID()
  {
    return oid;
  }

  public final boolean isCritical()
  {
    return isCritical;
  }

  public final boolean hasValue()
  {
    return (value != null);
  }

  public final ASN1OctetString getValue()
  {
    return value;
  }


  public final void writeTo(final ASN1Buffer writer)
  {
    final ASN1BufferSequence controlSequence = writer.beginSequence();
    writer.addOctetString(oid);

    if (isCritical)
    {
      writer.addBoolean(true);
    }

    if (value != null)
    {
      writer.addOctetString(value.getValue());
    }

    controlSequence.end();
  }


  public final ASN1Sequence encode()
  {
    final ArrayList<ASN1Element> elementList = new ArrayList<ASN1Element>(3);
    elementList.add(new ASN1OctetString(oid));

    if (isCritical)
    {
      elementList.add(new ASN1Boolean(isCritical));
    }

    if (value != null)
    {
      elementList.add(new ASN1OctetString(value.getValue()));
    }

    return new ASN1Sequence(elementList);
  }


  public static Control readFrom(final ASN1StreamReader reader)
         throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence controlSequence = reader.beginSequence();
      final String oid = reader.readString();

      boolean isCritical = false;
      ASN1OctetString value = null;
      while (controlSequence.hasMoreElements())
      {
        final byte type = (byte) reader.peek();
        switch (type)
        {
          case UNIVERSAL_BOOLEAN_TYPE:
            isCritical = reader.readBoolean();
            break;
          case UNIVERSAL_OCTET_STRING_TYPE:
            value = new ASN1OctetString(reader.readBytes());
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_CONTROL_INVALID_TYPE.get(toHex(type)));
        }
      }

      return decode(oid, isCritical, value);
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
           ERR_CONTROL_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }


  public static Control decode(final ASN1Sequence controlSequence)
         throws LDAPException
  {
    final ASN1Element[] elements = controlSequence.elements();

    if ((elements.length < 1) || (elements.length > 3))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CONTROL_DECODE_INVALID_ELEMENT_COUNT.get(
                                   elements.length));
    }

    final String oid =
         ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

    boolean isCritical = false;
    ASN1OctetString value = null;
    if (elements.length == 2)
    {
      switch (elements[1].getType())
      {
        case UNIVERSAL_BOOLEAN_TYPE:
          try
          {
            isCritical =
                 ASN1Boolean.decodeAsBoolean(elements[1]).booleanValue();
          }
          catch (ASN1Exception ae)
          {
            debugException(ae);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_CONTROL_DECODE_CRITICALITY.get(getExceptionMessage(ae)),
                 ae);
          }
          break;

        case UNIVERSAL_OCTET_STRING_TYPE:
          value = ASN1OctetString.decodeAsOctetString(elements[1]);
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_CONTROL_INVALID_TYPE.get(
                                       toHex(elements[1].getType())));
      }
    }
    else if (elements.length == 3)
    {
      try
      {
        isCritical = ASN1Boolean.decodeAsBoolean(elements[1]).booleanValue();
      }
      catch (ASN1Exception ae)
      {
        debugException(ae);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CONTROL_DECODE_CRITICALITY.get(getExceptionMessage(ae)), ae);
      }

      value = ASN1OctetString.decodeAsOctetString(elements[2]);
    }

    return decode(oid, isCritical, value);
  }


  public static Control decode(final String oid, final boolean isCritical,
                               final ASN1OctetString value)
         throws LDAPException
  {
     final DecodeableControl decodeableControl = decodeableControlMap.get(oid);
     if (decodeableControl == null)
     {
       return new Control(oid, isCritical, value);
     }
     else
     {
       try
       {
         return decodeableControl.decodeControl(oid, isCritical, value);
       }
       catch (Exception e)
       {
         debugException(e);
         return new Control(oid, isCritical, value);
       }
     }
  }


  public static ASN1Sequence encodeControls(final Control[] controls)
  {
    final ASN1Sequence[] controlElements = new ASN1Sequence[controls.length];
    for (int i=0; i < controls.length; i++)
    {
      controlElements[i] = controls[i].encode();
    }

    return new ASN1Sequence(CONTROLS_TYPE, controlElements);
  }

  public static Control[] decodeControls(final ASN1Sequence controlSequence)
         throws LDAPException
  {
    final ASN1Element[] controlElements = controlSequence.elements();
    final Control[] controls = new Control[controlElements.length];

    for (int i=0; i < controlElements.length; i++)
    {
      try
      {
        controls[i] = decode(ASN1Sequence.decodeAsSequence(controlElements[i]));
      }
      catch (ASN1Exception ae)
      {
        debugException(ae);
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_CONTROLS_DECODE_ELEMENT_NOT_SEQUENCE.get(
                                     getExceptionMessage(ae)),
                                ae);
      }
    }

    return controls;
  }


  public static void registerDecodeableControl(final String oid,
                          final DecodeableControl controlInstance)
  {
    decodeableControlMap.put(oid, controlInstance);
  }

  public static void deregisterDecodeableControl(final String oid)
  {
    decodeableControlMap.remove(oid);
  }


  @Override()
  public final int hashCode()
  {
    int hashCode = oid.hashCode();

    if (isCritical)
    {
      hashCode++;
    }

    if (value != null)
    {
      hashCode += value.hashCode();
    }

    return hashCode;
  }



  @Override()
  public final boolean equals(final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof Control))
    {
      return false;
    }

    final Control c = (Control) o;
    if (! oid.equals(c.oid))
    {
      return false;
    }

    if (isCritical != c.isCritical)
    {
      return false;
    }

    if (value == null)
    {
      if (c.value != null)
      {
        return false;
      }
    }
    else
    {
      if (c.value == null)
      {
        return false;
      }

      if (! value.equals(c.value))
      {
        return false;
      }
    }


    return true;
  }


  public String getControlName()
  {
    return oid;
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
    buffer.append("Control(oid=");
    buffer.append(oid);
    buffer.append(", isCritical=");
    buffer.append(isCritical);
    buffer.append(", value=");

    if (value == null)
    {
      buffer.append("{null}");
    }
    else
    {
      buffer.append("{byte[");
      buffer.append(value.getValue().length);
      buffer.append("]}");
    }

    buffer.append(')');
  }
}

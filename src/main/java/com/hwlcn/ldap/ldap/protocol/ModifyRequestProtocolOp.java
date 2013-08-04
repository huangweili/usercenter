package com.hwlcn.ldap.ldap.protocol;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.Modification;
import com.hwlcn.ldap.ldap.sdk.ModifyRequest;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.protocol.ProtocolMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ModifyRequestProtocolOp
       implements ProtocolOp
{

  private static final long serialVersionUID = -6294739625253826184L;

  private final List<Modification> modifications;

  private final String dn;


  public ModifyRequestProtocolOp(final String dn,
                                 final List<Modification> modifications)
  {
    this.dn            = dn;
    this.modifications = Collections.unmodifiableList(modifications);
  }


  public ModifyRequestProtocolOp(final ModifyRequest request)
  {
    dn            = request.getDN();
    modifications = request.getModifications();
  }

  ModifyRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      reader.beginSequence();
      dn = reader.readString();
      ensureNotNull(dn);

      final ArrayList<Modification> mods = new ArrayList<Modification>(5);
      final ASN1StreamReaderSequence modSequence = reader.beginSequence();
      while (modSequence.hasMoreElements())
      {
        mods.add(Modification.readFrom(reader));
      }

      modifications = Collections.unmodifiableList(mods);
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
           ERR_MODIFY_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }

  public String getDN()
  {
    return dn;
  }

  public List<Modification> getModifications()
  {
    return modifications;
  }

  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST;
  }

  public ASN1Element encodeProtocolOp()
  {
    final ArrayList<ASN1Element> modElements =
         new ArrayList<ASN1Element>(modifications.size());
    for (final Modification m : modifications)
    {
      modElements.add(m.encode());
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
         new ASN1OctetString(dn),
         new ASN1Sequence(modElements));
  }

  public static ModifyRequestProtocolOp decodeProtocolOp(
                                             final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final String dn =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

      final ASN1Element[] modElements =
           ASN1Sequence.decodeAsSequence(elements[1]).elements();
      final ArrayList<Modification> mods =
           new ArrayList<Modification>(modElements.length);
      for (final ASN1Element e : modElements)
      {
        mods.add(Modification.decode(ASN1Sequence.decodeAsSequence(e)));
      }

      return new ModifyRequestProtocolOp(dn, mods);
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MODIFY_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }

  public void writeTo(final ASN1Buffer writer)
  {
    final ASN1BufferSequence opSequence =
         writer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST);
    writer.addOctetString(dn);

    final ASN1BufferSequence modSequence = writer.beginSequence();
    for (final Modification m : modifications)
    {
      m.writeTo(writer);
    }
    modSequence.end();
    opSequence.end();
  }


  public ModifyRequest toModifyRequest(final Control... controls)
  {
    return new ModifyRequest(dn, modifications, controls);
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
    buffer.append("ModifyRequestProtocolOp(dn='");
    buffer.append(dn);
    buffer.append("', mods={");

    final Iterator<Modification> iterator = modifications.iterator();
    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append("})");
  }
}

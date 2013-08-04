
package com.hwlcn.ldap.ldap.protocol;



import java.io.InterruptedIOException;
import java.io.IOException;
import java.io.Serializable;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Integer;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.InternalSDKHelper;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.protocol.ProtocolMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;


@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPMessage
       implements Serializable
{

  public static final byte PROTOCOL_OP_TYPE_BIND_REQUEST = 0x60;


  public static final byte PROTOCOL_OP_TYPE_BIND_RESPONSE = 0x61;

  public static final byte PROTOCOL_OP_TYPE_UNBIND_REQUEST = 0x42;

  public static final byte PROTOCOL_OP_TYPE_SEARCH_REQUEST = 0x63;


  public static final byte PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY = 0x64;

  public static final byte PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE = 0x73;

  public static final byte PROTOCOL_OP_TYPE_SEARCH_RESULT_DONE = 0x65;

  public static final byte PROTOCOL_OP_TYPE_MODIFY_REQUEST = 0x66;

  public static final byte PROTOCOL_OP_TYPE_MODIFY_RESPONSE = 0x67;

  public static final byte PROTOCOL_OP_TYPE_ADD_REQUEST = 0x68;

  public static final byte PROTOCOL_OP_TYPE_ADD_RESPONSE = 0x69;

  public static final byte PROTOCOL_OP_TYPE_DELETE_REQUEST = 0x4A;

  public static final byte PROTOCOL_OP_TYPE_DELETE_RESPONSE = 0x6B;

  public static final byte PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST = 0x6C;

  public static final byte PROTOCOL_OP_TYPE_MODIFY_DN_RESPONSE = 0x6D;

  public static final byte PROTOCOL_OP_TYPE_COMPARE_REQUEST = 0x6E;

  public static final byte PROTOCOL_OP_TYPE_COMPARE_RESPONSE = 0x6F;

  public static final byte PROTOCOL_OP_TYPE_ABANDON_REQUEST = 0x50;

  public static final byte PROTOCOL_OP_TYPE_EXTENDED_REQUEST = 0x77;

  public static final byte PROTOCOL_OP_TYPE_EXTENDED_RESPONSE = 0x78;

  public static final byte PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE = 0x79;

  public static final byte MESSAGE_TYPE_CONTROLS = (byte) 0xA0;

  private static final long serialVersionUID = 909272448857832592L;

  private final int messageID;

  private final ProtocolOp protocolOp;

  private final List<Control> controls;

  public LDAPMessage(final int messageID, final ProtocolOp protocolOp,
                     final Control... controls)
  {
    this.messageID  = messageID;
    this.protocolOp = protocolOp;

    if (controls == null)
    {
      this.controls = Collections.emptyList();
    }
    else
    {
      this.controls = Collections.unmodifiableList(Arrays.asList(controls));
    }
  }


  public LDAPMessage(final int messageID, final ProtocolOp protocolOp,
                     final List<Control> controls)
  {
    this.messageID  = messageID;
    this.protocolOp = protocolOp;

    if (controls == null)
    {
      this.controls = Collections.emptyList();
    }
    else
    {
      this.controls = Collections.unmodifiableList(controls);
    }
  }


  public int getMessageID()
  {
    return messageID;
  }

  public ProtocolOp getProtocolOp()
  {
    return protocolOp;
  }

  public byte getProtocolOpType()
  {
    return protocolOp.getProtocolOpType();
  }

  public AbandonRequestProtocolOp getAbandonRequestProtocolOp()
         throws ClassCastException
  {
    return (AbandonRequestProtocolOp) protocolOp;
  }



  public AddRequestProtocolOp getAddRequestProtocolOp()
         throws ClassCastException
  {
    return (AddRequestProtocolOp) protocolOp;
  }


  public AddResponseProtocolOp getAddResponseProtocolOp()
         throws ClassCastException
  {
    return (AddResponseProtocolOp) protocolOp;
  }

  public BindRequestProtocolOp getBindRequestProtocolOp()
         throws ClassCastException
  {
    return (BindRequestProtocolOp) protocolOp;
  }

  public BindResponseProtocolOp getBindResponseProtocolOp()
         throws ClassCastException
  {
    return (BindResponseProtocolOp) protocolOp;
  }

  public CompareRequestProtocolOp getCompareRequestProtocolOp()
         throws ClassCastException
  {
    return (CompareRequestProtocolOp) protocolOp;
  }

  public CompareResponseProtocolOp getCompareResponseProtocolOp()
         throws ClassCastException
  {
    return (CompareResponseProtocolOp) protocolOp;
  }

  public DeleteRequestProtocolOp getDeleteRequestProtocolOp()
         throws ClassCastException
  {
    return (DeleteRequestProtocolOp) protocolOp;
  }

  public DeleteResponseProtocolOp getDeleteResponseProtocolOp()
         throws ClassCastException
  {
    return (DeleteResponseProtocolOp) protocolOp;
  }

  public ExtendedRequestProtocolOp getExtendedRequestProtocolOp()
         throws ClassCastException
  {
    return (ExtendedRequestProtocolOp) protocolOp;
  }

  public ExtendedResponseProtocolOp getExtendedResponseProtocolOp()
         throws ClassCastException
  {
    return (ExtendedResponseProtocolOp) protocolOp;
  }



  public ModifyRequestProtocolOp getModifyRequestProtocolOp()
         throws ClassCastException
  {
    return (ModifyRequestProtocolOp) protocolOp;
  }



  public ModifyResponseProtocolOp getModifyResponseProtocolOp()
         throws ClassCastException
  {
    return (ModifyResponseProtocolOp) protocolOp;
  }



  public ModifyDNRequestProtocolOp getModifyDNRequestProtocolOp()
         throws ClassCastException
  {
    return (ModifyDNRequestProtocolOp) protocolOp;
  }


  public ModifyDNResponseProtocolOp getModifyDNResponseProtocolOp()
         throws ClassCastException
  {
    return (ModifyDNResponseProtocolOp) protocolOp;
  }



  public SearchRequestProtocolOp getSearchRequestProtocolOp()
         throws ClassCastException
  {
    return (SearchRequestProtocolOp) protocolOp;
  }



  public SearchResultEntryProtocolOp getSearchResultEntryProtocolOp()
         throws ClassCastException
  {
    return (SearchResultEntryProtocolOp) protocolOp;
  }



  public SearchResultReferenceProtocolOp getSearchResultReferenceProtocolOp()
         throws ClassCastException
  {
    return (SearchResultReferenceProtocolOp) protocolOp;
  }




  public SearchResultDoneProtocolOp getSearchResultDoneProtocolOp()
         throws ClassCastException
  {
    return (SearchResultDoneProtocolOp) protocolOp;
  }



  public UnbindRequestProtocolOp getUnbindRequestProtocolOp()
         throws ClassCastException
  {
    return (UnbindRequestProtocolOp) protocolOp;
  }



  public IntermediateResponseProtocolOp getIntermediateResponseProtocolOp()
         throws ClassCastException
  {
    return (IntermediateResponseProtocolOp) protocolOp;
  }


  public List<Control> getControls()
  {
    return controls;
  }



  public ASN1Element encode()
  {
    if (controls.isEmpty())
    {
      return new ASN1Sequence(
           new ASN1Integer(messageID),
           protocolOp.encodeProtocolOp());
    }
    else
    {
      final Control[] controlArray = new Control[controls.size()];
      controls.toArray(controlArray);

      return new ASN1Sequence(
           new ASN1Integer(messageID),
           protocolOp.encodeProtocolOp(),
           Control.encodeControls(controlArray));
    }
  }



  public static LDAPMessage decode(final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      if ((elements.length < 2) || (elements.length > 3))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MESSAGE_DECODE_VALUE_SEQUENCE_INVALID_ELEMENT_COUNT.get(
                  elements.length));
      }

      final int messageID = ASN1Integer.decodeAsInteger(elements[0]).intValue();

      final ProtocolOp protocolOp;
      switch (elements[1].getType())
      {
        case PROTOCOL_OP_TYPE_ABANDON_REQUEST:
          protocolOp = AbandonRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_ADD_REQUEST:
          protocolOp = AddRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_ADD_RESPONSE:
          protocolOp = AddResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_BIND_REQUEST:
          protocolOp = BindRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_BIND_RESPONSE:
          protocolOp = BindResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_COMPARE_REQUEST:
          protocolOp = CompareRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_COMPARE_RESPONSE:
          protocolOp = CompareResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_DELETE_REQUEST:
          protocolOp = DeleteRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_DELETE_RESPONSE:
          protocolOp = DeleteResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_EXTENDED_REQUEST:
          protocolOp = ExtendedRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_EXTENDED_RESPONSE:
          protocolOp = ExtendedResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE:
          protocolOp =
               IntermediateResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_REQUEST:
          protocolOp = ModifyRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_RESPONSE:
          protocolOp = ModifyResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST:
          protocolOp = ModifyDNRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_DN_RESPONSE:
          protocolOp = ModifyDNResponseProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_REQUEST:
          protocolOp = SearchRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_RESULT_DONE:
          protocolOp = SearchResultDoneProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY:
          protocolOp =
               SearchResultEntryProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE:
          protocolOp =
               SearchResultReferenceProtocolOp.decodeProtocolOp(elements[1]);
          break;
        case PROTOCOL_OP_TYPE_UNBIND_REQUEST:
          protocolOp = UnbindRequestProtocolOp.decodeProtocolOp(elements[1]);
          break;
        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_MESSAGE_DECODE_INVALID_PROTOCOL_OP_TYPE.get(
                    toHex(elements[1].getType())));
      }

      final Control[] controls;
      if (elements.length == 3)
      {
        controls =
             Control.decodeControls(ASN1Sequence.decodeAsSequence(elements[2]));
      }
      else
      {
        controls = null;
      }

      return new LDAPMessage(messageID, protocolOp, controls);
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MESSAGE_DECODE_ERROR.get(getExceptionMessage(e)),
           e);
    }
  }



  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence messageSequence = buffer.beginSequence();
    buffer.addInteger(messageID);
    protocolOp.writeTo(buffer);

    if (! controls.isEmpty())
    {
      final ASN1BufferSequence controlsSequence =
           buffer.beginSequence(MESSAGE_TYPE_CONTROLS);
      for (final Control c : controls)
      {
        c.writeTo(buffer);
      }
      controlsSequence.end();
    }
    messageSequence.end();
  }




  public static LDAPMessage readFrom(final ASN1StreamReader reader,
                                     final boolean ignoreSocketTimeout)
         throws LDAPException
  {
    final ASN1StreamReaderSequence messageSequence;
    try
    {
      reader.setIgnoreSocketTimeout(false, ignoreSocketTimeout);
      messageSequence = reader.beginSequence();
      if (messageSequence == null)
      {
        return null;
      }
    }
    catch (IOException ioe)
    {
      if (! ((ioe instanceof SocketTimeoutException) ||
             (ioe instanceof InterruptedIOException)))
      {
        debugException(ioe);
      }

      throw new LDAPException(ResultCode.SERVER_DOWN,
           ERR_MESSAGE_IO_ERROR.get(getExceptionMessage(ioe)), ioe);
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MESSAGE_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }

    try
    {

      reader.setIgnoreSocketTimeout(ignoreSocketTimeout, ignoreSocketTimeout);
      final int messageID = reader.readInteger();

      final ProtocolOp protocolOp;
      final byte protocolOpType = (byte) reader.peek();
      switch (protocolOpType)
      {
        case PROTOCOL_OP_TYPE_BIND_REQUEST:
          protocolOp = new BindRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_BIND_RESPONSE:
          protocolOp = new BindResponseProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_UNBIND_REQUEST:
          protocolOp = new UnbindRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_REQUEST:
          protocolOp = new SearchRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY:
          protocolOp = new SearchResultEntryProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE:
          protocolOp = new SearchResultReferenceProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_SEARCH_RESULT_DONE:
          protocolOp = new SearchResultDoneProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_REQUEST:
          protocolOp = new ModifyRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_RESPONSE:
          protocolOp = new ModifyResponseProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_ADD_REQUEST:
          protocolOp = new AddRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_ADD_RESPONSE:
          protocolOp = new AddResponseProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_DELETE_REQUEST:
          protocolOp = new DeleteRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_DELETE_RESPONSE:
          protocolOp = new DeleteResponseProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST:
          protocolOp = new ModifyDNRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_MODIFY_DN_RESPONSE:
          protocolOp = new ModifyDNResponseProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_COMPARE_REQUEST:
          protocolOp = new CompareRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_COMPARE_RESPONSE:
          protocolOp = new CompareResponseProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_ABANDON_REQUEST:
          protocolOp = new AbandonRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_EXTENDED_REQUEST:
          protocolOp = new ExtendedRequestProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_EXTENDED_RESPONSE:
          protocolOp = new ExtendedResponseProtocolOp(reader);
          break;
        case PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE:
          protocolOp = new IntermediateResponseProtocolOp(reader);
          break;
        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_MESSAGE_INVALID_PROTOCOL_OP_TYPE.get(toHex(protocolOpType)));
      }

      final ArrayList<Control> controls = new ArrayList<Control>(5);
      if (messageSequence.hasMoreElements())
      {
        final ASN1StreamReaderSequence controlSequence = reader.beginSequence();
        while (controlSequence.hasMoreElements())
        {
          controls.add(Control.readFrom(reader));
        }
      }

      return new LDAPMessage(messageID, protocolOp, controls);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (IOException ioe)
    {
      debugException(ioe);

      if ((ioe instanceof SocketTimeoutException) ||
          (ioe instanceof InterruptedIOException))
      {


        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MESSAGE_CANNOT_DECODE.get(getExceptionMessage(ioe)));
      }
      else
      {
        throw new LDAPException(ResultCode.SERVER_DOWN,
             ERR_MESSAGE_IO_ERROR.get(getExceptionMessage(ioe)), ioe);
      }
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MESSAGE_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }




  public static LDAPResponse readLDAPResponseFrom(final ASN1StreamReader reader,
                                  final boolean ignoreSocketTimeout)
         throws LDAPException
  {
    return readLDAPResponseFrom(reader, ignoreSocketTimeout, null);
  }




  public static LDAPResponse readLDAPResponseFrom(final ASN1StreamReader reader,
                                  final boolean ignoreSocketTimeout,
                                  final Schema schema)
         throws LDAPException
  {
    final ASN1StreamReaderSequence messageSequence;
    try
    {
      reader.setIgnoreSocketTimeout(false, ignoreSocketTimeout);
      messageSequence = reader.beginSequence();
      if (messageSequence == null)
      {
        return null;
      }
    }
    catch (IOException ioe)
    {
      if (! ((ioe instanceof SocketTimeoutException) ||
             (ioe instanceof InterruptedIOException)))
      {
        debugException(ioe);
      }

      throw new LDAPException(ResultCode.SERVER_DOWN,
           ERR_MESSAGE_IO_ERROR.get(getExceptionMessage(ioe)), ioe);
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MESSAGE_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }

    try
    {
      reader.setIgnoreSocketTimeout(ignoreSocketTimeout, ignoreSocketTimeout);
      final int messageID = reader.readInteger();

      final byte protocolOpType = (byte) reader.peek();
      switch (protocolOpType)
      {
        case PROTOCOL_OP_TYPE_ADD_RESPONSE:
        case PROTOCOL_OP_TYPE_DELETE_RESPONSE:
        case PROTOCOL_OP_TYPE_MODIFY_RESPONSE:
        case PROTOCOL_OP_TYPE_MODIFY_DN_RESPONSE:
          return InternalSDKHelper.readLDAPResultFrom(messageID,
                      messageSequence, reader);

        case PROTOCOL_OP_TYPE_BIND_RESPONSE:
          return InternalSDKHelper.readBindResultFrom(messageID,
                      messageSequence, reader);

        case PROTOCOL_OP_TYPE_COMPARE_RESPONSE:
          return InternalSDKHelper.readCompareResultFrom(messageID,
                      messageSequence, reader);

        case PROTOCOL_OP_TYPE_EXTENDED_RESPONSE:
          return InternalSDKHelper.readExtendedResultFrom(messageID,
                      messageSequence, reader);

        case PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY:
          return InternalSDKHelper.readSearchResultEntryFrom(messageID,
                      messageSequence, reader, schema);

        case PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE:
          return InternalSDKHelper.readSearchResultReferenceFrom(messageID,
                      messageSequence, reader);

        case PROTOCOL_OP_TYPE_SEARCH_RESULT_DONE:
          return InternalSDKHelper.readSearchResultFrom(messageID,
                      messageSequence, reader);

        case PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE:
          return InternalSDKHelper.readIntermediateResponseFrom(messageID,
                      messageSequence, reader);

        case PROTOCOL_OP_TYPE_ABANDON_REQUEST:
        case PROTOCOL_OP_TYPE_ADD_REQUEST:
        case PROTOCOL_OP_TYPE_BIND_REQUEST:
        case PROTOCOL_OP_TYPE_COMPARE_REQUEST:
        case PROTOCOL_OP_TYPE_DELETE_REQUEST:
        case PROTOCOL_OP_TYPE_EXTENDED_REQUEST:
        case PROTOCOL_OP_TYPE_MODIFY_REQUEST:
        case PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST:
        case PROTOCOL_OP_TYPE_SEARCH_REQUEST:
        case PROTOCOL_OP_TYPE_UNBIND_REQUEST:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_MESSAGE_PROTOCOL_OP_TYPE_NOT_RESPONSE.get(
                    toHex(protocolOpType)));

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_MESSAGE_INVALID_PROTOCOL_OP_TYPE.get(toHex(protocolOpType)));
      }
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (IOException ioe)
    {
      debugException(ioe);

      if ((ioe instanceof SocketTimeoutException) ||
          (ioe instanceof InterruptedIOException))
      {

        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MESSAGE_CANNOT_DECODE.get(getExceptionMessage(ioe)));
      }
      else
      {
        throw new LDAPException(ResultCode.SERVER_DOWN,
             ERR_MESSAGE_IO_ERROR.get(getExceptionMessage(ioe)), ioe);
      }
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MESSAGE_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
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
    buffer.append("LDAPMessage(msgID=");
    buffer.append(messageID);
    buffer.append(", protocolOp=");
    protocolOp.toString(buffer);

    if (! controls.isEmpty())
    {
      buffer.append(", controls={");
      final Iterator<Control> iterator = controls.iterator();
      while (iterator.hasNext())
      {
        iterator.next().toString(buffer);
        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}

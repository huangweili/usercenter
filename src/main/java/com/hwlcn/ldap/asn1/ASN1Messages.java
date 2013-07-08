/*
 * Copyright 2013 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2013 UnboundID Corp.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
package com.hwlcn.ldap.asn1;



import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;



/**
 * This enum defines a set of message keys for messages in the
 * com.hwlcn.ldap.asn1 package, which correspond to messages in the
 * ldap-ldapsdk-asn1.properties properties file.
 * <BR><BR>
 * This source file was generated from the properties file.
 * Do not edit it directly.
 */
enum ASN1Messages
{
  /**
   * ASN.1 Boolean elements must have a value whose length is exactly one byte.
   */
  ERR_BOOLEAN_INVALID_LENGTH("ASN.1 Boolean elements must have a value whose length is exactly one byte."),



  /**
   * Unable to decode the provided byte array as an ASN.1 BER element:  {0}
   */
  ERR_ELEMENT_DECODE_EXCEPTION("Unable to decode the provided byte array as an ASN.1 BER element:  {0}"),



  /**
   * The decoded length of {0,number,0} does not match the number of bytes remaining in the provided array ({1,number,0}).
   */
  ERR_ELEMENT_LENGTH_MISMATCH("The decoded length of {0,number,0} does not match the number of bytes remaining in the provided array ({1,number,0})."),



  /**
   * Invalid value length of {0,number,0} for an ASN.1 enumerated element.  Enumerated element values must have a length between 1 and 4 bytes.
   */
  ERR_ENUMERATED_INVALID_LENGTH("Invalid value length of {0,number,0} for an ASN.1 enumerated element.  Enumerated element values must have a length between 1 and 4 bytes."),



  /**
   * Invalid value length of {0,number,0} for an ASN.1 integer element.  Integer element values must have a length between 1 and 4 bytes.
   */
  ERR_INTEGER_INVALID_LENGTH("Invalid value length of {0,number,0} for an ASN.1 integer element.  Integer element values must have a length between 1 and 4 bytes."),



  /**
   * Invalid value length of {0,number,0} for an ASN.1 long element.  Long element values must have a length between 1 and 8 bytes.
   */
  ERR_LONG_INVALID_LENGTH("Invalid value length of {0,number,0} for an ASN.1 long element.  Long element values must have a length between 1 and 8 bytes."),



  /**
   * ASN.1 null elements must not have a value.
   */
  ERR_NULL_HAS_VALUE("ASN.1 null elements must not have a value."),



  /**
   * The end of the input stream was reached before the first length byte could be read.
   */
  ERR_READ_END_BEFORE_FIRST_LENGTH("The end of the input stream was reached before the first length byte could be read."),



  /**
   * The end of the input stream was reached before the full length could be read.
   */
  ERR_READ_END_BEFORE_LENGTH_END("The end of the input stream was reached before the full length could be read."),



  /**
   * The end of the input stream was reached before the full value could be read.
   */
  ERR_READ_END_BEFORE_VALUE_END("The end of the input stream was reached before the full value could be read."),



  /**
   * The element indicated that it required {0,number,0} bytes to hold the value, but this is larger than the maximum of {1,number,0} bytes that the client has been configured to accept.
   */
  ERR_READ_LENGTH_EXCEEDS_MAX("The element indicated that it required {0,number,0} bytes to hold the value, but this is larger than the maximum of {1,number,0} bytes that the client has been configured to accept."),



  /**
   * The element indicated that it required {0,number,0} bytes to encode the multi-byte length, but multi-byte lengths must be encoded in 1 to 4 bytes.
   */
  ERR_READ_LENGTH_TOO_LONG("The element indicated that it required {0,number,0} bytes to encode the multi-byte length, but multi-byte lengths must be encoded in 1 to 4 bytes."),



  /**
   * Unable to decode the provided byte array as a sequence:  {0}
   */
  ERR_SEQUENCE_BYTES_DECODE_EXCEPTION("Unable to decode the provided byte array as a sequence:  {0}"),



  /**
   * Unable to decode the provided byte array as a sequence because the decoded length of an embedded element exceeds the number of bytes remaining.
   */
  ERR_SEQUENCE_BYTES_DECODE_LENGTH_EXCEEDS_AVAILABLE("Unable to decode the provided byte array as a sequence because the decoded length of an embedded element exceeds the number of bytes remaining."),



  /**
   * Unable to decode the provided ASN.1 element {0} as a sequence:  {1}
   */
  ERR_SEQUENCE_DECODE_EXCEPTION("Unable to decode the provided ASN.1 element {0} as a sequence:  {1}"),



  /**
   * Unable to decode the provided ASN.1 element {0} as a sequence because the decoded length of an embedded element exceeds the number of bytes remaining.
   */
  ERR_SEQUENCE_DECODE_LENGTH_EXCEEDS_AVAILABLE("Unable to decode the provided ASN.1 element {0} as a sequence because the decoded length of an embedded element exceeds the number of bytes remaining."),



  /**
   * Unable to decode the provided byte array as a set:  {0}
   */
  ERR_SET_BYTES_DECODE_EXCEPTION("Unable to decode the provided byte array as a set:  {0}"),



  /**
   * Unable to decode the provided byte array as a set because the decoded length of an embedded element exceeds the number of bytes remaining.
   */
  ERR_SET_BYTES_DECODE_LENGTH_EXCEEDS_AVAILABLE("Unable to decode the provided byte array as a set because the decoded length of an embedded element exceeds the number of bytes remaining."),



  /**
   * Unable to decode the provided ASN.1 element {0} as a set:  {1}
   */
  ERR_SET_DECODE_EXCEPTION("Unable to decode the provided ASN.1 element {0} as a set:  {1}"),



  /**
   * Unable to decode the provided ASN.1 element {0} as a set because the decoded length of an embedded element exceeds the number of bytes remaining.
   */
  ERR_SET_DECODE_LENGTH_EXCEEDS_AVAILABLE("Unable to decode the provided ASN.1 element {0} as a set because the decoded length of an embedded element exceeds the number of bytes remaining."),



  /**
   * The ASN.1 stream reader has already read beyond the end of this sequence (expected sequence of length {0} to end at {1} bytes into the stream, but {2} bytes have already been read from the stream).
   */
  ERR_STREAM_READER_SEQUENCE_READ_PAST_END("The ASN.1 stream reader has already read beyond the end of this sequence (expected sequence of length {0} to end at {1} bytes into the stream, but {2} bytes have already been read from the stream)."),



  /**
   * The ASN.1 stream reader has already read beyond the end of this set (expected set of length {0} to end at {1} bytes into the stream, but {2} bytes have already been read from the stream).
   */
  ERR_STREAM_READER_SET_READ_PAST_END("The ASN.1 stream reader has already read beyond the end of this set (expected set of length {0} to end at {1} bytes into the stream, but {2} bytes have already been read from the stream).");



  /**
   * The resource bundle that will be used to load the properties file.
   */
  private static final ResourceBundle RESOURCE_BUNDLE;
  static
  {
    ResourceBundle rb = null;
    try
    {
      rb = ResourceBundle.getBundle("ldap-ldapsdk-asn1");
    } catch (Exception e) {}
    RESOURCE_BUNDLE = rb;
  }



  /**
   * The map that will be used to hold the unformatted message strings, indexed by property name.
   */
  private static final ConcurrentHashMap<ASN1Messages,String> MESSAGE_STRINGS = new ConcurrentHashMap<ASN1Messages,String>();



  /**
   * The map that will be used to hold the message format objects, indexed by property name.
   */
  private static final ConcurrentHashMap<ASN1Messages,MessageFormat> MESSAGES = new ConcurrentHashMap<ASN1Messages,MessageFormat>();

  private final String defaultText;



  /**
   * Creates a new message key.
   */
  private ASN1Messages(final String defaultText)
  {
    this.defaultText = defaultText;
  }



  /**
   * Retrieves a localized version of the message.
   * This method should only be used for messages which do not take any arguments.
   *
   * @return  A localized version of the message.
   */
  public String get()
  {
    String s = MESSAGE_STRINGS.get(this);
    if (s == null)
    {
      if (RESOURCE_BUNDLE == null)
      {
        return defaultText;
      }
      else
      {
        try
        {
          s = RESOURCE_BUNDLE.getString(name());
        }
        catch (final Exception e)
        {
          s = defaultText;
        }
        MESSAGE_STRINGS.putIfAbsent(this, s);
      }
    }
    return s;
  }



  /**
   * Retrieves a localized version of the message.
   *
   * @param  args  The arguments to use to format the message.
   *
   * @return  A localized version of the message.
   */
  public String get(final Object... args)
  {
    MessageFormat f = MESSAGES.get(this);
    if (f == null)
    {
      if (RESOURCE_BUNDLE == null)
      {
        f = new MessageFormat(defaultText);
      }
      else
      {
        try
        {
          f = new MessageFormat(RESOURCE_BUNDLE.getString(name()));
        }
        catch (final Exception e)
        {
          f = new MessageFormat(defaultText);
        }
      }
      MESSAGES.putIfAbsent(this, f);
    }
    synchronized (f)
    {
      return f.format(args);
    }
  }



  /**
   * Retrieves a string representation of this message key.
   *
   * @return  A string representation of this message key.
   */
  @Override()
  public String toString()
  {
    return get();
  }
}


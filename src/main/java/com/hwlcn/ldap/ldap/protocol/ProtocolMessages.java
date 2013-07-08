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
package com.hwlcn.ldap.ldap.protocol;



import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;



/**
 * This enum defines a set of message keys for messages in the
 * com.hwlcn.ldap.ldap.protocol package, which correspond to messages in the
 * ldap-ldapsdk-protocol.properties properties file.
 * <BR><BR>
 * This source file was generated from the properties file.
 * Do not edit it directly.
 */
enum ProtocolMessages
{
  /**
   * Unable to read or decode an abandon request protocol op:  {0}
   */
  ERR_ABANDON_REQUEST_CANNOT_DECODE("Unable to read or decode an abandon request protocol op:  {0}"),



  /**
   * Unable to read or decode an add request protocol op:  {0}
   */
  ERR_ADD_REQUEST_CANNOT_DECODE("Unable to read or decode an add request protocol op:  {0}"),



  /**
   * Unable to read or decode an add response protocol op:  {0}
   */
  ERR_ADD_RESPONSE_CANNOT_DECODE("Unable to read or decode an add response protocol op:  {0}"),



  /**
   * Unable to create a bind request protocol op from a simple bind request object that uses a password provider rather than a statically-defined password.
   */
  ERR_BIND_REQUEST_CANNOT_CREATE_WITH_PASSWORD_PROVIDER("Unable to create a bind request protocol op from a simple bind request object that uses a password provider rather than a statically-defined password."),



  /**
   * Unable to read or decode a bind request protocol op:  {0}
   */
  ERR_BIND_REQUEST_CANNOT_DECODE("Unable to read or decode a bind request protocol op:  {0}"),



  /**
   * Invalid credentials type {0} in a bind request protocol op.
   */
  ERR_BIND_REQUEST_INVALID_CRED_TYPE("Invalid credentials type {0} in a bind request protocol op."),



  /**
   * Unable to read or decode a bind response protocol op:  {0}
   */
  ERR_BIND_RESPONSE_CANNOT_DECODE("Unable to read or decode a bind response protocol op:  {0}"),



  /**
   * Invalid element type {0} in a bind response protocol op.
   */
  ERR_BIND_RESPONSE_INVALID_ELEMENT("Invalid element type {0} in a bind response protocol op."),



  /**
   * Unable to read or decode a compare request protocol op:  {0}
   */
  ERR_COMPARE_REQUEST_CANNOT_DECODE("Unable to read or decode a compare request protocol op:  {0}"),



  /**
   * Unable to read or decode a compare response protocol op:  {0}
   */
  ERR_COMPARE_RESPONSE_CANNOT_DECODE("Unable to read or decode a compare response protocol op:  {0}"),



  /**
   * Unable to read or decode a delete request protocol op:  {0}
   */
  ERR_DELETE_REQUEST_CANNOT_DECODE("Unable to read or decode a delete request protocol op:  {0}"),



  /**
   * Unable to read or decode a delete response protocol op:  {0}
   */
  ERR_DELETE_RESPONSE_CANNOT_DECODE("Unable to read or decode a delete response protocol op:  {0}"),



  /**
   * Unable to read or decode an extended request protocol op:  {0}
   */
  ERR_EXTENDED_REQUEST_CANNOT_DECODE("Unable to read or decode an extended request protocol op:  {0}"),



  /**
   * Unable to read or decode an extended response:  {0}
   */
  ERR_EXTENDED_RESPONSE_CANNOT_DECODE("Unable to read or decode an extended response:  {0}"),



  /**
   * Invalid element type {0} in an extended response protocol op.
   */
  ERR_EXTENDED_RESPONSE_INVALID_ELEMENT("Invalid element type {0} in an extended response protocol op."),



  /**
   * Unable to read or decode an intermediate response:  {0}
   */
  ERR_INTERMEDIATE_RESPONSE_CANNOT_DECODE("Unable to read or decode an intermediate response:  {0}"),



  /**
   * Invalid element type {0} in an extended response protocol op.
   */
  ERR_INTERMEDIATE_RESPONSE_INVALID_ELEMENT("Invalid element type {0} in an extended response protocol op."),



  /**
   * Unable to read or decode an LDAP message:  {0}
   */
  ERR_MESSAGE_CANNOT_DECODE("Unable to read or decode an LDAP message:  {0}"),



  /**
   * An error occurred while attempting to decode the provided ASN.1 element as an LDAP message:  {0}
   */
  ERR_MESSAGE_DECODE_ERROR("An error occurred while attempting to decode the provided ASN.1 element as an LDAP message:  {0}"),



  /**
   * Unable to decode the provided ASN.1 element as an LDAP message because it has an invalid protocol op type of {0}.
   */
  ERR_MESSAGE_DECODE_INVALID_PROTOCOL_OP_TYPE("Unable to decode the provided ASN.1 element as an LDAP message because it has an invalid protocol op type of {0}."),



  /**
   * Unable to decode the provided ASN.1 element as an LDAP message because the sequence had an invalid element count of {0,number,0}.
   */
  ERR_MESSAGE_DECODE_VALUE_SEQUENCE_INVALID_ELEMENT_COUNT("Unable to decode the provided ASN.1 element as an LDAP message because the sequence had an invalid element count of {0,number,0}."),



  /**
   * Invalid protocol op type {0} encountered in an LDAP message.
   */
  ERR_MESSAGE_INVALID_PROTOCOL_OP_TYPE("Invalid protocol op type {0} encountered in an LDAP message."),



  /**
   * An I/O error occurred while trying to read the response from the server:  {0}
   */
  ERR_MESSAGE_IO_ERROR("An I/O error occurred while trying to read the response from the server:  {0}"),



  /**
   * Request protocol op type {0} encountered in an LDAP message when a response type was expected.
   */
  ERR_MESSAGE_PROTOCOL_OP_TYPE_NOT_RESPONSE("Request protocol op type {0} encountered in an LDAP message when a response type was expected."),



  /**
   * Unable to read or decode a modify DN request protocol op:  {0}
   */
  ERR_MODIFY_DN_REQUEST_CANNOT_DECODE("Unable to read or decode a modify DN request protocol op:  {0}"),



  /**
   * Unable to read or decode a modify DN response protocol op:  {0}
   */
  ERR_MODIFY_DN_RESPONSE_CANNOT_DECODE("Unable to read or decode a modify DN response protocol op:  {0}"),



  /**
   * Unable to read or decode a modify request protocol op:  {0}
   */
  ERR_MODIFY_REQUEST_CANNOT_DECODE("Unable to read or decode a modify request protocol op:  {0}"),



  /**
   * Unable to read or decode a modify response protocol op:  {0}
   */
  ERR_MODIFY_RESPONSE_CANNOT_DECODE("Unable to read or decode a modify response protocol op:  {0}"),



  /**
   * Unable to read or decode an LDAP response:  {0}
   */
  ERR_RESPONSE_CANNOT_DECODE("Unable to read or decode an LDAP response:  {0}"),



  /**
   * Unable to read or decode a search result done protocol op:  {0}
   */
  ERR_SEARCH_DONE_CANNOT_DECODE("Unable to read or decode a search result done protocol op:  {0}"),



  /**
   * Unable to read or decode a search result entry protocol op:  {0}
   */
  ERR_SEARCH_ENTRY_CANNOT_DECODE("Unable to read or decode a search result entry protocol op:  {0}"),



  /**
   * Unable to read or decode a search result reference protocol op:  {0}
   */
  ERR_SEARCH_REFERENCE_CANNOT_DECODE("Unable to read or decode a search result reference protocol op:  {0}"),



  /**
   * Unable to read or decode a search request protocol op:  {0}
   */
  ERR_SEARCH_REQUEST_CANNOT_DECODE("Unable to read or decode a search request protocol op:  {0}"),



  /**
   * Unable to read or decode an unbind request protocol op:  {0}
   */
  ERR_UNBIND_REQUEST_CANNOT_DECODE("Unable to read or decode an unbind request protocol op:  {0}");



  /**
   * The resource bundle that will be used to load the properties file.
   */
  private static final ResourceBundle RESOURCE_BUNDLE;
  static
  {
    ResourceBundle rb = null;
    try
    {
      rb = ResourceBundle.getBundle("ldap-ldapsdk-protocol");
    } catch (Exception e) {}
    RESOURCE_BUNDLE = rb;
  }



  /**
   * The map that will be used to hold the unformatted message strings, indexed by property name.
   */
  private static final ConcurrentHashMap<ProtocolMessages,String> MESSAGE_STRINGS = new ConcurrentHashMap<ProtocolMessages,String>();



  /**
   * The map that will be used to hold the message format objects, indexed by property name.
   */
  private static final ConcurrentHashMap<ProtocolMessages,MessageFormat> MESSAGES = new ConcurrentHashMap<ProtocolMessages,MessageFormat>();



  // The default text for this message
  private final String defaultText;



  /**
   * Creates a new message key.
   */
  private ProtocolMessages(final String defaultText)
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


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
package com.hwlcn.ldap.ldap.matchingrules;



import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;



/**
 * This enum defines a set of message keys for messages in the
 * com.hwlcn.ldap.ldap.matchingrules package, which correspond to messages in the
 * ldap-ldapsdk-matchingrules.properties properties file.
 * <BR><BR>
 * This source file was generated from the properties file.
 * Do not edit it directly.
 */
enum MatchingRuleMessages
{
  /**
   * The provided value is invalid.  Boolean values may only be 'TRUE' or 'FALSE'.
   */
  ERR_BOOLEAN_INVALID_VALUE("The provided value is invalid.  Boolean values may only be 'TRUE' or 'FALSE'."),



  /**
   * Ordering matching is not supported for Boolean values.
   */
  ERR_BOOLEAN_ORDERING_MATCHING_NOT_SUPPORTED("Ordering matching is not supported for Boolean values."),



  /**
   * Substring matching is not supported for Boolean values.
   */
  ERR_BOOLEAN_SUBSTRING_MATCHING_NOT_SUPPORTED("Substring matching is not supported for Boolean values."),



  /**
   * The provided value ''{0}'' is not valid according to the case-ignore list syntax because it contains a zero-length item.
   */
  ERR_CASE_IGNORE_LIST_EMPTY_ITEM("The provided value ''{0}'' is not valid according to the case-ignore list syntax because it contains a zero-length item."),



  /**
   * The provided value ''{0}'' is not valid according to the case-ignore list syntax because it does not contain any items.
   */
  ERR_CASE_IGNORE_LIST_EMPTY_LIST("The provided value ''{0}'' is not valid according to the case-ignore list syntax because it does not contain any items."),



  /**
   * The provided value ''{0}'' is not valid according to the case-ignore list syntax because it contains a backslash which is not followed by two hexadecimal digits.
   */
  ERR_CASE_IGNORE_LIST_MALFORMED_HEX_CHAR("The provided value ''{0}'' is not valid according to the case-ignore list syntax because it contains a backslash which is not followed by two hexadecimal digits."),



  /**
   * Character ''{0}'' is not a valid hexadecimal digit.
   */
  ERR_CASE_IGNORE_LIST_NOT_HEX_DIGIT("Character ''{0}'' is not a valid hexadecimal digit."),



  /**
   * Ordering matching is not supported for case-ignore list values.
   */
  ERR_CASE_IGNORE_LIST_ORDERING_MATCHING_NOT_SUPPORTED("Ordering matching is not supported for case-ignore list values."),



  /**
   * Substring component ''{0}'' is invalid because it contains an unescaped dollar sign.
   */
  ERR_CASE_IGNORE_LIST_SUBSTRING_COMPONENT_CONTAINS_DOLLAR("Substring component ''{0}'' is invalid because it contains an unescaped dollar sign."),



  /**
   * Ordering matching is not supported for distinguished name values.
   */
  ERR_DN_ORDERING_MATCHING_NOT_SUPPORTED("Ordering matching is not supported for distinguished name values."),



  /**
   * Substring matching is not supported for distinguished name values.
   */
  ERR_DN_SUBSTRING_MATCHING_NOT_SUPPORTED("Substring matching is not supported for distinguished name values."),



  /**
   * The provided value cannot be parsed according to the generalized time syntax:  {0}
   */
  ERR_GENERALIZED_TIME_INVALID_VALUE("The provided value cannot be parsed according to the generalized time syntax:  {0}"),



  /**
   * Substring matching is not supported for generalized time values.
   */
  ERR_GENERALIZED_TIME_SUBSTRING_MATCHING_NOT_SUPPORTED("Substring matching is not supported for generalized time values."),



  /**
   * The provided value is not a valid integer because it contains an invalid character at position {0,number,0}.
   */
  ERR_INTEGER_INVALID_CHARACTER("The provided value is not a valid integer because it contains an invalid character at position {0,number,0}."),



  /**
   * Integer values are not allowed to have  leading zeroes.
   */
  ERR_INTEGER_INVALID_LEADING_ZERO("Integer values are not allowed to have  leading zeroes."),



  /**
   * Substring matching is not supported for integer values.
   */
  ERR_INTEGER_SUBSTRING_MATCHING_NOT_SUPPORTED("Substring matching is not supported for integer values."),



  /**
   * Integer values are not allowed to be zero-length strings.
   */
  ERR_INTEGER_ZERO_LENGTH_NOT_ALLOWED("Integer values are not allowed to be zero-length strings."),



  /**
   * The provided value is not a valid numeric string because it contains a character other than a space or numeric digit at position {0,number,0}.
   */
  ERR_NUMERIC_STRING_INVALID_CHARACTER("The provided value is not a valid numeric string because it contains a character other than a space or numeric digit at position {0,number,0}."),



  /**
   * The provided value cannot be parsed as a telephone number because it contains an invalid character at position {0,number,0}.
   */
  ERR_TELEPHONE_NUMBER_INVALID_CHARACTER("The provided value cannot be parsed as a telephone number because it contains an invalid character at position {0,number,0}."),



  /**
   * Ordering matching is not supported for telephone number values.
   */
  ERR_TELEPHONE_NUMBER_ORDERING_MATCHING_NOT_SUPPORTED("Ordering matching is not supported for telephone number values.");



  /**
   * The resource bundle that will be used to load the properties file.
   */
  private static final ResourceBundle RESOURCE_BUNDLE;
  static
  {
    ResourceBundle rb = null;
    try
    {
      rb = ResourceBundle.getBundle("ldap-ldapsdk-matchingrules");
    } catch (Exception e) {}
    RESOURCE_BUNDLE = rb;
  }



  /**
   * The map that will be used to hold the unformatted message strings, indexed by property name.
   */
  private static final ConcurrentHashMap<MatchingRuleMessages,String> MESSAGE_STRINGS = new ConcurrentHashMap<MatchingRuleMessages,String>();



  /**
   * The map that will be used to hold the message format objects, indexed by property name.
   */
  private static final ConcurrentHashMap<MatchingRuleMessages,MessageFormat> MESSAGES = new ConcurrentHashMap<MatchingRuleMessages,MessageFormat>();



  // The default text for this message
  private final String defaultText;



  /**
   * Creates a new message key.
   */
  private MatchingRuleMessages(final String defaultText)
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


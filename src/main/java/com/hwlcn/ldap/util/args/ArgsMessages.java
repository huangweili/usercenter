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
package com.hwlcn.ldap.util.args;



import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;



/**
 * This enum defines a set of message keys for messages in the
 * com.hwlcn.ldap.util.args package, which correspond to messages in the
 * ldap-ldapsdk-args.properties properties file.
 * <BR><BR>
 * This source file was generated from the properties file.
 * Do not edit it directly.
 */
enum ArgsMessages
{
  /**
   * Argument ''{0}'' is already registered with an argument parser and cannot be registered a second time or with a different parser.
   */
  ERR_ARG_ALREADY_REGISTERED("Argument ''{0}'' is already registered with an argument parser and cannot be registered a second time or with a different parser."),



  /**
   * The provided description was null.
   */
  ERR_ARG_DESCRIPTION_NULL("The provided description was null."),



  /**
   * The set of identifiers for argument ''{0}'' cannot be altered because the argument has already been registered with an argument parser.
   */
  ERR_ARG_ID_CHANGE_AFTER_REGISTERED("The set of identifiers for argument ''{0}'' cannot be altered because the argument has already been registered with an argument parser."),



  /**
   * The value ''{0}'' provided for argument ''{1}'' is not acceptable because it was rejected by the associated argument parser:  {2}
   */
  ERR_ARG_LIST_INVALID_VALUE("The value ''{0}'' provided for argument ''{1}'' is not acceptable because it was rejected by the associated argument parser:  {2}"),



  /**
   * The value ''{0}'' provided for argument ''{1}'' is not a properly-formed argument list:  {2}
   */
  ERR_ARG_LIST_MALFORMED_VALUE("The value ''{0}'' provided for argument ''{1}'' is not a properly-formed argument list:  {2}"),



  /**
   * The ''{0}'' argument was provided more than the maximum allowed number of times for that argument.
   */
  ERR_ARG_MAX_OCCURRENCES_EXCEEDED("The ''{0}'' argument was provided more than the maximum allowed number of times for that argument."),



  /**
   * A value placeholder must be provided for the ''{0}'' argument.
   */
  ERR_ARG_MUST_TAKE_VALUE("A value placeholder must be provided for the ''{0}'' argument."),



  /**
   * At least one of the short and long identifiers must be non-null.
   */
  ERR_ARG_NO_IDENTIFIERS("At least one of the short and long identifiers must be non-null."),



  /**
   * The provided value ''{0}'' is not allowed for argument ''{1}'' because it does not match regular expression ''{2}''.
   */
  ERR_ARG_VALUE_DOES_NOT_MATCH_PATTERN_WITHOUT_EXPLANATION("The provided value ''{0}'' is not allowed for argument ''{1}'' because it does not match regular expression ''{2}''."),



  /**
   * The provided value ''{0}'' is not allowed for argument ''{1}'' because it does not match regular expression ''{2}''.  {3}
   */
  ERR_ARG_VALUE_DOES_NOT_MATCH_PATTERN_WITH_EXPLANATION("The provided value ''{0}'' is not allowed for argument ''{1}'' because it does not match regular expression ''{2}''.  {3}"),



  /**
   * The provided value ''{0}'' is not allowed for argument ''{1}''.
   */
  ERR_ARG_VALUE_NOT_ALLOWED("The provided value ''{0}'' is not allowed for argument ''{1}''."),



  /**
   * The ''{0}'' argument does not take a value.
   */
  ERR_BOOLEAN_VALUES_NOT_ALLOWED("The ''{0}'' argument does not take a value."),



  /**
   * The provided value ''{0}'' for argument ''{1}'' could not be parsed as a distinguished name:  {2}
   */
  ERR_DN_VALUE_NOT_DN("The provided value ''{0}'' for argument ''{1}'' could not be parsed as a distinguished name:  {2}"),



  /**
   * The value for argument ''{0}'' is not acceptable because it represents a duration above the upper bound of {1}.
   */
  ERR_DURATION_ABOVE_UPPER_BOUND("The value for argument ''{0}'' is not acceptable because it represents a duration above the upper bound of {1}."),



  /**
   * The value for argument ''{0}'' is not acceptable because it represents a duration below the lower bound of {1}.
   */
  ERR_DURATION_BELOW_LOWER_BOUND("The value for argument ''{0}'' is not acceptable because it represents a duration below the lower bound of {1}."),



  /**
   * If a default value is defined for duration argument ''{0}'', then a default value unit must also be specified.
   */
  ERR_DURATION_DEFAULT_REQUIRES_UNIT("If a default value is defined for duration argument ''{0}'', then a default value unit must also be specified."),



  /**
   * The value is an empty string.
   */
  ERR_DURATION_EMPTY_VALUE("The value is an empty string."),



  /**
   * Argument ''{0}'' is invalid because the defined lower bound of {1} is greater than the defined upper bound of {2}.
   */
  ERR_DURATION_LOWER_GT_UPPER("Argument ''{0}'' is invalid because the defined lower bound of {1} is greater than the defined upper bound of {2}."),



  /**
   * If a lower bound value is defined for duration argument ''{0}'', then a lower bound unit must also be specified.
   */
  ERR_DURATION_LOWER_REQUIRES_UNIT("If a lower bound value is defined for duration argument ''{0}'', then a lower bound unit must also be specified."),



  /**
   * Value ''{0}'' is not valid for argument ''{1}'':  {2}
   */
  ERR_DURATION_MALFORMED_VALUE("Value ''{0}'' is not valid for argument ''{1}'':  {2}"),



  /**
   * The provided string did not include a numeric portion.
   */
  ERR_DURATION_NO_DIGIT("The provided string did not include a numeric portion."),



  /**
   * The provided string did not include a time unit.
   */
  ERR_DURATION_NO_UNIT("The provided string did not include a time unit."),



  /**
   * ''{0}'' is not a recognized time unit.
   */
  ERR_DURATION_UNRECOGNIZED_UNIT("''{0}'' is not a recognized time unit."),



  /**
   * Lower bound time unit ''{0}'' is not supported.
   */
  ERR_DURATION_UNSUPPORTED_LOWER_BOUND_UNIT("Lower bound time unit ''{0}'' is not supported."),



  /**
   * Upper bound time unit ''{0}'' is not supported.
   */
  ERR_DURATION_UNSUPPORTED_UPPER_BOUND_UNIT("Upper bound time unit ''{0}'' is not supported."),



  /**
   * If an upper bound value is defined for duration argument ''{0}'', then an upper bound unit must also be specified.
   */
  ERR_DURATION_UPPER_REQUIRES_UNIT("If an upper bound value is defined for duration argument ''{0}'', then an upper bound unit must also be specified."),



  /**
   * File argument ''{0}'' is configured to require values to be both files and directories.  This is not allowed.
   */
  ERR_FILE_CANNOT_BE_FILE_AND_DIRECTORY("File argument ''{0}'' is configured to require values to be both files and directories.  This is not allowed."),



  /**
   * Unable to fully read the contents of file ''{0}'' specified as the value for argument ''{1}''.
   */
  ERR_FILE_CANNOT_READ_FULLY("Unable to fully read the contents of file ''{0}'' specified as the value for argument ''{1}''."),



  /**
   * The file ''{0}'' specified as the value for argument ''{1}'' does not exist.
   */
  ERR_FILE_DOESNT_EXIST("The file ''{0}'' specified as the value for argument ''{1}'' does not exist."),



  /**
   * The file ''{0}'' specified as the value for argument ''{1}'' does not exist, and its parent also does not exist or is not a directory.
   */
  ERR_FILE_PARENT_DOESNT_EXIST("The file ''{0}'' specified as the value for argument ''{1}'' does not exist, and its parent also does not exist or is not a directory."),



  /**
   * The value for file argument ''{0}'' resolves to path ''{1}'' which exists but is not a directory.
   */
  ERR_FILE_VALUE_NOT_DIRECTORY("The value for file argument ''{0}'' resolves to path ''{1}'' which exists but is not a directory."),



  /**
   * The value for file argument ''{0}'' resolves to path ''{1}'' which exists but is not a file.
   */
  ERR_FILE_VALUE_NOT_FILE("The value for file argument ''{0}'' resolves to path ''{1}'' which exists but is not a file."),



  /**
   * The provided value ''{0}'' for argument ''{1}'' could not be parsed as a search filter:  {2}
   */
  ERR_FILTER_VALUE_NOT_FILTER("The provided value ''{0}'' for argument ''{1}'' could not be parsed as a search filter:  {2}"),



  /**
   * The provided value {0,number,0} for argument ''{1}'' was larger than the upper bound of {2,number,0}.
   */
  ERR_INTEGER_VALUE_ABOVE_UPPER_BOUND("The provided value {0,number,0} for argument ''{1}'' was larger than the upper bound of {2,number,0}."),



  /**
   * The provided value {0,number,0} for argument ''{1}'' was smaller than the lower bound of {2,number,0}.
   */
  ERR_INTEGER_VALUE_BELOW_LOWER_BOUND("The provided value {0,number,0} for argument ''{1}'' was smaller than the lower bound of {2,number,0}."),



  /**
   * The provided value ''{0}'' for argument ''{1}'' could not be parsed as an integer.
   */
  ERR_INTEGER_VALUE_NOT_INT("The provided value ''{0}'' for argument ''{1}'' could not be parsed as an integer."),



  /**
   * The provided command description was null.
   */
  ERR_PARSER_COMMAND_DESCRIPTION_NULL("The provided command description was null."),



  /**
   * The provided command name was null.
   */
  ERR_PARSER_COMMAND_NAME_NULL("The provided command name was null."),



  /**
   * If argument ''{0}'' is provided, then at least one of the following arguments must also be given:  {1}.
   */
  ERR_PARSER_DEPENDENT_CONFLICT_MULTIPLE("If argument ''{0}'' is provided, then at least one of the following arguments must also be given:  {1}."),



  /**
   * If argument ''{0}'' is provided, then argument ''{1}'' must also be given.
   */
  ERR_PARSER_DEPENDENT_CONFLICT_SINGLE("If argument ''{0}'' is provided, then argument ''{1}'' must also be given."),



  /**
   * Arguments ''{0}'' and ''{1}'' are not allowed to be used together.
   */
  ERR_PARSER_EXCLUSIVE_CONFLICT("Arguments ''{0}'' and ''{1}'' are not allowed to be used together."),



  /**
   * Argument ''--{0}'' does not take a value.
   */
  ERR_PARSER_LONG_ARG_DOESNT_TAKE_VALUE("Argument ''--{0}'' does not take a value."),



  /**
   * Argument ''--{0}'' requires a value.
   */
  ERR_PARSER_LONG_ARG_MISSING_VALUE("Argument ''--{0}'' requires a value."),



  /**
   * Another argument is already registered with a long identifier of ''{0}''.
   */
  ERR_PARSER_LONG_ID_CONFLICT("Another argument is already registered with a long identifier of ''{0}''."),



  /**
   * Argument ''{0}'' is required to be present but was not provided and does not have a default value.
   */
  ERR_PARSER_MISSING_REQUIRED_ARG("Argument ''{0}'' is required to be present but was not provided and does not have a default value."),



  /**
   * Unknown argument ''-{0}'' referenced in string ''{1}''.
   */
  ERR_PARSER_NO_SUBSEQUENT_SHORT_ARG("Unknown argument ''-{0}'' referenced in string ''{1}''."),



  /**
   * Unknown argument ''--{0}''
   */
  ERR_PARSER_NO_SUCH_LONG_ID("Unknown argument ''--{0}''"),



  /**
   * Unknown argument ''-{0}''
   */
  ERR_PARSER_NO_SUCH_SHORT_ID("Unknown argument ''-{0}''"),



  /**
   * At least one of the following arguments is required to be present:  {0}.
   */
  ERR_PARSER_REQUIRED_CONFLICT("At least one of the following arguments is required to be present:  {0}."),



  /**
   * Argument ''-{0}'' requires a value.
   */
  ERR_PARSER_SHORT_ARG_MISSING_VALUE("Argument ''-{0}'' requires a value."),



  /**
   * Another argument is already registered with a short identifier of ''{0}''.
   */
  ERR_PARSER_SHORT_ID_CONFLICT("Another argument is already registered with a short identifier of ''{0}''."),



  /**
   * Argument ''-{0}'' referenced in string ''{1}'' requires a value, but arguments which take values cannot be referenced by their short identifier in a single string containing other arguments referenced by their short identifiers.
   */
  ERR_PARSER_SUBSEQUENT_SHORT_ARG_TAKES_VALUE("Argument ''-{0}'' referenced in string ''{1}'' requires a value, but arguments which take values cannot be referenced by their short identifier in a single string containing other arguments referenced by their short identifiers."),



  /**
   * Argument ''{0}'' is not acceptable because command ''{1}'' does not allow more than {2} unnamed trailing argument(s).
   */
  ERR_PARSER_TOO_MANY_TRAILING_ARGS("Argument ''{0}'' is not acceptable because command ''{1}'' does not allow more than {2} unnamed trailing argument(s)."),



  /**
   * Argument ''{0}'' is not acceptable because command ''{1}'' does not allow unnamed trailing arguments.
   */
  ERR_PARSER_TRAILING_ARGS_NOT_ALLOWED("Argument ''{0}'' is not acceptable because command ''{1}'' does not allow unnamed trailing arguments."),



  /**
   * The argument parser was configured to allow unnamed trailing arguments, but the trailing args placeholder was null.
   */
  ERR_PARSER_TRAILING_ARGS_PLACEHOLDER_NULL("The argument parser was configured to allow unnamed trailing arguments, but the trailing args placeholder was null."),



  /**
   * Unexpected lone ''-'' character in argument list.
   */
  ERR_PARSER_UNEXPECTED_DASH("Unexpected lone ''-'' character in argument list."),



  /**
   * The value ''{0}'' provided for argument ''{1}'' is not acceptable because it does not represent a recognized search scope.  Search scope values should be one of 'base', 'one', 'sub', or 'subordinate'.
   */
  ERR_SCOPE_VALUE_NOT_VALID("The value ''{0}'' provided for argument ''{1}'' is not acceptable because it does not represent a recognized search scope.  Search scope values should be one of 'base', 'one', 'sub', or 'subordinate'."),



  /**
   * A provided value must be a string representation of a valid argument list that meets the constraints of the associated argument parser.
   */
  INFO_ARG_LIST_CONSTRAINTS("A provided value must be a string representation of a valid argument list that meets the constraints of the associated argument parser."),



  /**
   * Argument List
   */
  INFO_ARG_LIST_TYPE_NAME("Argument List"),



  /**
   * This argument is not allowed to have a value.  If this argument is included in a set of arguments, then it will be assumed to have a value of 'true'.  If it is absent from a set of arguments, then it will be assumed to have a value of 'false'.
   */
  INFO_BOOLEAN_CONSTRAINTS("This argument is not allowed to have a value.  If this argument is included in a set of arguments, then it will be assumed to have a value of 'true'.  If it is absent from a set of arguments, then it will be assumed to have a value of 'false'."),



  /**
   * Boolean
   */
  INFO_BOOLEAN_TYPE_NAME("Boolean"),



  /**
   * A provided value should be either 'true' or 'false'.
   */
  INFO_BOOLEAN_VALUE_CONSTRAINTS("A provided value should be either 'true' or 'false'."),



  /**
   * Boolean
   */
  INFO_BOOLEAN_VALUE_TYPE_NAME("Boolean"),



  /**
   * A provided value must be able to be parsed as an LDAP distinguished name as described in RFC 4514.
   */
  INFO_DN_CONSTRAINTS("A provided value must be able to be parsed as an LDAP distinguished name as described in RFC 4514."),



  /**
   * LDAP Distinguished Name
   */
  INFO_DN_TYPE_NAME("LDAP Distinguished Name"),



  /**
   * The provided value must contain an integer followed by a unit of 'ns' (for nanoseconds), 'us' (for microseconds), 'ms' (for milliseconds), 's' (for seconds), 'm' (for minutes), 'h' (for hours), or 'd' (for days).
   */
  INFO_DURATION_CONSTRAINTS_FORMAT("The provided value must contain an integer followed by a unit of 'ns' (for nanoseconds), 'us' (for microseconds), 'ms' (for milliseconds), 's' (for seconds), 'm' (for minutes), 'h' (for hours), or 'd' (for days)."),



  /**
   * The specified duration must not be less than {0} or greater than {1}.
   */
  INFO_DURATION_CONSTRAINTS_LOWER_AND_UPPER_BOUND("The specified duration must not be less than {0} or greater than {1}."),



  /**
   * The specified duration must not be less than {0}.
   */
  INFO_DURATION_CONSTRAINTS_LOWER_BOUND("The specified duration must not be less than {0}."),



  /**
   * The specified duration must not be greater than {0}.
   */
  INFO_DURATION_CONSTRAINTS_UPPER_BOUND("The specified duration must not be greater than {0}."),



  /**
   * Duration
   */
  INFO_DURATION_TYPE_NAME("Duration"),



  /**
   * The specified path must refer to a directory that may or may not exist.
   */
  INFO_FILE_CONSTRAINTS_DIR_MAY_EXIST("The specified path must refer to a directory that may or may not exist."),



  /**
   * The specified path must refer to a directory that exists.
   */
  INFO_FILE_CONSTRAINTS_DIR_MUST_EXIST("The specified path must refer to a directory that exists."),



  /**
   * The specified path must refer to a directory which may or may not exist, but whose parent directory must exist.
   */
  INFO_FILE_CONSTRAINTS_DIR_PARENT_MUST_EXIST("The specified path must refer to a directory which may or may not exist, but whose parent directory must exist."),



  /**
   * The specified path must refer to a file that may or may not exist.
   */
  INFO_FILE_CONSTRAINTS_FILE_MAY_EXIST("The specified path must refer to a file that may or may not exist."),



  /**
   * The specified path must refer to a file that exists.
   */
  INFO_FILE_CONSTRAINTS_FILE_MUST_EXIST("The specified path must refer to a file that exists."),



  /**
   * The specified path must refer to a file which may or may not exist, but whose parent directory must exist.
   */
  INFO_FILE_CONSTRAINTS_FILE_PARENT_MUST_EXIST("The specified path must refer to a file which may or may not exist, but whose parent directory must exist."),



  /**
   * Non-absolute paths will be relative to directory ''{0}''.
   */
  INFO_FILE_CONSTRAINTS_RELATIVE_PATH_SPECIFIED_ROOT("Non-absolute paths will be relative to directory ''{0}''."),



  /**
   * Directory Path
   */
  INFO_FILE_TYPE_PATH_DIRECTORY("Directory Path"),



  /**
   * File Path
   */
  INFO_FILE_TYPE_PATH_FILE("File Path"),



  /**
   * A provided value must be able to be parsed as an LDAP search filter as described in RFC 4515.
   */
  INFO_FILTER_CONSTRAINTS("A provided value must be able to be parsed as an LDAP search filter as described in RFC 4515."),



  /**
   * LDAP Search Filter
   */
  INFO_FILTER_TYPE_NAME("LDAP Search Filter"),



  /**
   * The specified value must not be less than {0} or greater than {1}.
   */
  INFO_INTEGER_CONSTRAINTS_LOWER_AND_UPPER_BOUND("The specified value must not be less than {0} or greater than {1}."),



  /**
   * Integer
   */
  INFO_INTEGER_TYPE_NAME("Integer"),



  /**
   * The provided value should be one of 'base', 'one', 'sub', or 'subordinate'.
   */
  INFO_SCOPE_CONSTRAINTS("The provided value should be one of 'base', 'one', 'sub', or 'subordinate'."),



  /**
   * LDAP Search Scope
   */
  INFO_SCOPE_TYPE_NAME("LDAP Search Scope"),



  /**
   * A provided value should be one of the following:
   */
  INFO_STRING_CONSTRAINTS_ALLOWED_VALUE("A provided value should be one of the following:"),



  /**
   * A provided value must match regular expression ''{0}''.
   */
  INFO_STRING_CONSTRAINTS_REGEX_WITHOUT_EXPLANATION("A provided value must match regular expression ''{0}''."),



  /**
   * A provided value must match regular expression ''{0}'' ({1}).
   */
  INFO_STRING_CONSTRAINTS_REGEX_WITH_EXPLANATION("A provided value must match regular expression ''{0}'' ({1})."),



  /**
   * String
   */
  INFO_STRING_TYPE_NAME("String"),



  /**
   * Usage:  {0}
   */
  INFO_USAGE_NOOPTIONS_NOTRAILING("Usage:  {0}"),



  /**
   * Usage:  {0} {1}
   */
  INFO_USAGE_NOOPTIONS_TRAILING("Usage:  {0} {1}"),



  /**
   * Available options include:
   */
  INFO_USAGE_OPTIONS_INCLUDE("Available options include:"),



  /**
   * Usage:  {0} '{'options'}'
   */
  INFO_USAGE_OPTIONS_NOTRAILING("Usage:  {0} '{'options'}'"),



  /**
   * Usage:  {0} '{'options'}' {1}
   */
  INFO_USAGE_OPTIONS_TRAILING("Usage:  {0} '{'options'}' {1}");



  /**
   * The resource bundle that will be used to load the properties file.
   */
  private static final ResourceBundle RESOURCE_BUNDLE;
  static
  {
    ResourceBundle rb = null;
    try
    {
      rb = ResourceBundle.getBundle("ldap-ldapsdk-args");
    } catch (Exception e) {}
    RESOURCE_BUNDLE = rb;
  }



  /**
   * The map that will be used to hold the unformatted message strings, indexed by property name.
   */
  private static final ConcurrentHashMap<ArgsMessages,String> MESSAGE_STRINGS = new ConcurrentHashMap<ArgsMessages,String>();



  /**
   * The map that will be used to hold the message format objects, indexed by property name.
   */
  private static final ConcurrentHashMap<ArgsMessages,MessageFormat> MESSAGES = new ConcurrentHashMap<ArgsMessages,MessageFormat>();



  // The default text for this message
  private final String defaultText;



  /**
   * Creates a new message key.
   */
  private ArgsMessages(final String defaultText)
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


  @Override()
  public String toString()
  {
    return get();
  }
}


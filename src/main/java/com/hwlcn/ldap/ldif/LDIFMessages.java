package com.hwlcn.ldap.ldif;



import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;


enum LDIFMessages
{
  /**
   * Unable to base64-decode a value for attribute {0} in the record starting at or near line number {1,number,0}:  {2}
   */
  ERR_READ_CANNOT_BASE64_DECODE_ATTR("Unable to base64-decode a value for attribute {0} in the record starting at or near line number {1,number,0}:  {2}"),



  /**
   * Unable to base64-decode the changetype value of the change record starting at or near line number {0,number,0}:  {1}
   */
  ERR_READ_CANNOT_BASE64_DECODE_CT("Unable to base64-decode the changetype value of the change record starting at or near line number {0,number,0}:  {1}"),



  /**
   * Unable to base64-decode the DN of the entry starting at or near line number {0,number,0}:  {1}
   */
  ERR_READ_CANNOT_BASE64_DECODE_DN("Unable to base64-decode the DN of the entry starting at or near line number {0,number,0}:  {1}"),



  /**
   * Unable to base64-decode the DN of the change record starting at or near line number {0,number,0}:  {1}
   */
  ERR_READ_CR_CANNOT_BASE64_DECODE_DN("Unable to base64-decode the DN of the change record starting at or near line number {0,number,0}:  {1}"),



  /**
   * The second line of the change record starting at or near line number {0,number,0} did not begin with ''changetype:''.
   */
  ERR_READ_CR_CT_LINE_DOESNT_START_WITH_CT("The second line of the change record starting at or near line number {0,number,0} did not begin with ''changetype:''."),



  /**
   * The first line of the change record starting at or near line number {0,number,0} did not begin with ''dn:''.
   */
  ERR_READ_CR_DN_LINE_DOESNT_START_WITH_DN("The first line of the change record starting at or near line number {0,number,0} did not begin with ''dn:''."),



  /**
   * Unexpected additional data after the changetype line for the delete change record starting at or near line number {0,number,0}.
   */
  ERR_READ_CR_EXTRA_DELETE_DATA("Unexpected additional data after the changetype line for the delete change record starting at or near line number {0,number,0}."),



  /**
   * Unexpected additional information at the end of the modify DN change record starting at or near line number {0,number,0}.
   */
  ERR_READ_CR_EXTRA_MODDN_DATA("Unexpected additional information at the end of the modify DN change record starting at or near line number {0,number,0}."),



  /**
   * Invalid changetype value ''{0}'' for the change record starting at or near line number {1,number,0}.
   */
  ERR_READ_CR_INVALID_CT("Invalid changetype value ''{0}'' for the change record starting at or near line number {1,number,0}."),



  /**
   * No attributes found for the change record starting at or near line number {0,number,0}.
   */
  ERR_READ_CR_NO_ATTRIBUTES("No attributes found for the change record starting at or near line number {0,number,0}."),



  /**
   * No modifications were contained in the modify change record starting at or near line number {0,number,0}.
   */
  ERR_READ_CR_NO_MODS("No modifications were contained in the modify change record starting at or near line number {0,number,0}."),



  /**
   * No newRDN found for the modify DN change record starting at or near line number {0,number,0}.
   */
  ERR_READ_CR_NO_NEWRDN("No newRDN found for the modify DN change record starting at or near line number {0,number,0}."),



  /**
   * The change record starting at or near line {0,number,0} is too short to represent a valid change record.
   */
  ERR_READ_CR_TOO_SHORT("The change record starting at or near line {0,number,0} is too short to represent a valid change record."),



  /**
   * The changetype line of the change record starting at or near line number {0,number,0} does not have a value.
   */
  ERR_READ_CT_LINE_NO_CT_VALUE("The changetype line of the change record starting at or near line number {0,number,0} does not have a value."),



  /**
   * The first line of the entry starting at or near line number {0,number,0} did not begin with ''dn:''.
   */
  ERR_READ_DN_LINE_DOESNT_START_WITH_DN("The first line of the entry starting at or near line number {0,number,0} did not begin with ''dn:''."),



  /**
   * The record for entry ''{0}'' starting near line {1,number,0} contains a duplicate value for attribute ''{2}''.
   */
  ERR_READ_DUPLICATE_VALUE("The record for entry ''{0}'' starting near line {1,number,0} contains a duplicate value for attribute ''{2}''."),



  /**
   * The LDIF record starting at or near line number {0,number,0} contains line ''{1}'' which ends with an illegal trailing space.
   */
  ERR_READ_ILLEGAL_TRAILING_SPACE_WITHOUT_DN("The LDIF record starting at or near line number {0,number,0} contains line ''{1}'' which ends with an illegal trailing space."),



  /**
   * The LDIF record for entry ''{0}'' starting at or near line number {1,number,0} contains line ''{2}'' which ends with an illegal trailing space.
   */
  ERR_READ_ILLEGAL_TRAILING_SPACE_WITH_DN("The LDIF record for entry ''{0}'' starting at or near line number {1,number,0} contains line ''{2}'' which ends with an illegal trailing space."),



  /**
   * Unable to base64-decode the deleteOldRDN value in the modify DN change record starting at or near line number {0,number,0}:  {1}
   */
  ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_DELOLDRDN("Unable to base64-decode the deleteOldRDN value in the modify DN change record starting at or near line number {0,number,0}:  {1}"),



  /**
   * Unable to base64-decode the newRDN value in the modify DN change record starting at or near line number {0,number,0}:  {1}
   */
  ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_NEWRDN("Unable to base64-decode the newRDN value in the modify DN change record starting at or near line number {0,number,0}:  {1}"),



  /**
   * Unable to base64-decode the newSuperior value in the modify DN change record starting at or near line number {0,number,0}:  {1}
   */
  ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_NEWSUPERIOR("Unable to base64-decode the newSuperior value in the modify DN change record starting at or near line number {0,number,0}:  {1}"),



  /**
   * Invalid deleteOldRDN value ''{0}'' found in the modify DN change record starting at or near line {1,number,0}.  The value must be either 0 or 1.
   */
  ERR_READ_MODDN_CR_INVALID_DELOLDRDN("Invalid deleteOldRDN value ''{0}'' found in the modify DN change record starting at or near line {1,number,0}.  The value must be either 0 or 1."),



  /**
   * The fourth line of the modify DN change record starting at or near line number {0,number,0} does not begin with ''deleteOldRDN:''.
   */
  ERR_READ_MODDN_CR_NO_DELOLDRDN_COLON("The fourth line of the modify DN change record starting at or near line number {0,number,0} does not begin with ''deleteOldRDN:''."),



  /**
   * The deleteOldRDN line of the modify DN change record starting at or near line number {0,number,0} does not have a value.
   */
  ERR_READ_MODDN_CR_NO_DELOLDRDN_VALUE("The deleteOldRDN line of the modify DN change record starting at or near line number {0,number,0} does not have a value."),



  /**
   * The third line of the modify DN change record starting at or near line number {0,number,0} does not begin with ''newRDN:''.
   */
  ERR_READ_MODDN_CR_NO_NEWRDN_COLON("The third line of the modify DN change record starting at or near line number {0,number,0} does not begin with ''newRDN:''."),



  /**
   * The newRDN line of the modify DN change record starting at or near line number {0,number,0} does not have a value.
   */
  ERR_READ_MODDN_CR_NO_NEWRDN_VALUE("The newRDN line of the modify DN change record starting at or near line number {0,number,0} does not have a value."),



  /**
   * The fifth line of the modify DN change record starting at or near line number {0,number,0} does not begin with ''newSuperior:''.
   */
  ERR_READ_MODDN_CR_NO_NEWSUPERIOR_COLON("The fifth line of the modify DN change record starting at or near line number {0,number,0} does not begin with ''newSuperior:''."),



  /**
   * The modify change record starting at or near line {0,number,0} has attribute name {1} where {2} was expected.
   */
  ERR_READ_MOD_CR_ATTR_MISMATCH("The modify change record starting at or near line {0,number,0} has attribute name {1} where {2} was expected."),



  /**
   * The modify change record starting at or near line {0,number,0} includes an increment for attribute {1} with an invalid number of values.  Increment changes must have exactly one value.
   */
  ERR_READ_MOD_CR_INVALID_INCR_VALUE_COUNT("The modify change record starting at or near line {0,number,0} includes an increment for attribute {1} with an invalid number of values.  Increment changes must have exactly one value."),



  /**
   * Invalid modification type {0} found in the modify change record starting at or near line number {1,number,0}.
   */
  ERR_READ_MOD_CR_INVALID_MODTYPE("Invalid modification type {0} found in the modify change record starting at or near line number {1,number,0}."),



  /**
   * Unable to base64-decode the attribute name in a modification type line for the modify change record starting at or near line number {0,number,0}:  {1}
   */
  ERR_READ_MOD_CR_MODTYPE_CANNOT_BASE64_DECODE_ATTR("Unable to base64-decode the attribute name in a modification type line for the modify change record starting at or near line number {0,number,0}:  {1}"),



  /**
   * The modification type line of the modify change record starting at or near line number {0,number,0} does not include an attribute name.
   */
  ERR_READ_MOD_CR_MODTYPE_NO_ATTR("The modification type line of the modify change record starting at or near line number {0,number,0} does not include an attribute name."),



  /**
   * No values to add for attribute {0} in the modify change record starting at or near line number {1,number,0}.
   */
  ERR_READ_MOD_CR_NO_ADD_VALUES("No values to add for attribute {0} in the modify change record starting at or near line number {1,number,0}."),



  /**
   * The modify change record starting at or near line {0,number,0} includes a line that does not contain a colon to separate the modification type from the attribute name.
   */
  ERR_READ_MOD_CR_NO_MODTYPE("The modify change record starting at or near line {0,number,0} includes a line that does not contain a colon to separate the modification type from the attribute name."),



  /**
   * The LDIF record starting at or near line {0,number,0} is an entry, which cannot be converted to an LDIF change record when defaultAdd=false.
   */
  ERR_READ_NOT_CHANGE_RECORD("The LDIF record starting at or near line {0,number,0} is an entry, which cannot be converted to an LDIF change record when defaultAdd=false."),



  /**
   * The record starting at or near line number {0,number,0} contains a line that does not begin with an attribute name followed by a colon.
   */
  ERR_READ_NO_ATTR_COLON("The record starting at or near line number {0,number,0} contains a line that does not begin with an attribute name followed by a colon."),



  /**
   * The provided LDIF entry did not contain any non-blank lines.
   */
  ERR_READ_NO_DATA("The provided LDIF entry did not contain any non-blank lines."),



  /**
   * An LDIF reader cannot be created with an empty set of LDIF files.
   */
  ERR_READ_NO_LDIF_FILES("An LDIF reader cannot be created with an empty set of LDIF files."),



  /**
   * The provided LDIF content contained only blank lines.
   */
  ERR_READ_ONLY_BLANKS("The provided LDIF content contained only blank lines."),



  /**
   * Unexpected blank line found at or near line number {0,number,0}.
   */
  ERR_READ_UNEXPECTED_BLANK("Unexpected blank line found at or near line number {0,number,0}."),



  /**
   * Unexpected space found at the beginning of the first line for an LDIF entry on or near line number {0,number,0}.
   */
  ERR_READ_UNEXPECTED_FIRST_SPACE("Unexpected space found at the beginning of the first line for an LDIF entry on or near line number {0,number,0}."),



  /**
   * Unexpected space found at the beginning of the first line of the LDIF entry.
   */
  ERR_READ_UNEXPECTED_FIRST_SPACE_NO_NUMBER("Unexpected space found at the beginning of the first line of the LDIF entry."),



  /**
   * Unable to access the value for attribute {0} using URL {1} in the record starting at or near line number {2,number,0}:  {3}
   */
  ERR_READ_URL_EXCEPTION("Unable to access the value for attribute {0} using URL {1} in the record starting at or near line number {2,number,0}:  {3}"),



  /**
   * Unable to access the value for attribute {0} using URL {1} in the record starting at or near line number {2,number,0} because the size of file {3} changed while it was being read.
   */
  ERR_READ_URL_FILE_SIZE_CHANGED("Unable to access the value for attribute {0} using URL {1} in the record starting at or near line number {2,number,0} because the size of file {3} changed while it was being read."),



  /**
   * Unable to access the value for attribute {0} using URL {1} in the record starting at or near line number {2,number,0} because file {3} is larger than the maximum supported size of {4,number,0} bytes.
   */
  ERR_READ_URL_FILE_TOO_LARGE("Unable to access the value for attribute {0} using URL {1} in the record starting at or near line number {2,number,0} because file {3} is larger than the maximum supported size of {4,number,0} bytes."),



  /**
   * Unable to access the value for attribute {0} using URL {1} in the record starting at or near line number {2,number,0} because this implementation only supports the file:// URL format.
   */
  ERR_READ_URL_INVALID_SCHEME("Unable to access the value for attribute {0} using URL {1} in the record starting at or near line number {2,number,0} because this implementation only supports the file:// URL format."),



  /**
   * Unable to access the value for attribute {0} using URL {1} in the record starting at or near line {2,number,0} because the file {3} does not exist.
   */
  ERR_READ_URL_NO_SUCH_FILE("Unable to access the value for attribute {0} using URL {1} in the record starting at or near line {2,number,0} because the file {3} does not exist."),



  /**
   * The record for entry ''{0}'' starting near line {1,number,0} contains a value for attribute ''{2}'' which violates the associated attribute syntax:  {3}
   */
  ERR_READ_VALUE_SYNTAX_VIOLATION("The record for entry ''{0}'' starting near line {1,number,0} contains a value for attribute ''{2}'' which violates the associated attribute syntax:  {3}");



  /**
   * The resource bundle that will be used to load the properties file.
   */
  private static final ResourceBundle RESOURCE_BUNDLE;
  static
  {
    ResourceBundle rb = null;
    try
    {
      rb = ResourceBundle.getBundle("ldap-ldapsdk-ldif");
    } catch (Exception e) {}
    RESOURCE_BUNDLE = rb;
  }



  /**
   * The map that will be used to hold the unformatted message strings, indexed by property name.
   */
  private static final ConcurrentHashMap<LDIFMessages,String> MESSAGE_STRINGS = new ConcurrentHashMap<LDIFMessages,String>();



  /**
   * The map that will be used to hold the message format objects, indexed by property name.
   */
  private static final ConcurrentHashMap<LDIFMessages,MessageFormat> MESSAGES = new ConcurrentHashMap<LDIFMessages,MessageFormat>();



  // The default text for this message
  private final String defaultText;



  /**
   * Creates a new message key.
   */
  private LDIFMessages(final String defaultText)
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


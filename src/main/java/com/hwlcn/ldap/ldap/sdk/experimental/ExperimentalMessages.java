package com.hwlcn.ldap.ldap.sdk.experimental;



import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;

enum ExperimentalMessages
{
  /**
   * The provided control cannot be decoded as a DirSync control because an error was encountered while attempting to parse the control value:  {0}
   */
  ERR_DIRSYNC_CONTROL_DECODE_ERROR("The provided control cannot be decoded as a DirSync control because an error was encountered while attempting to parse the control value:  {0}"),



  /**
   * The provided control cannot be decoded as a DirSync control because it does not have a value.
   */
  ERR_DIRSYNC_CONTROL_NO_VALUE("The provided control cannot be decoded as a DirSync control because it does not have a value."),



  /**
   * The provided control cannot be decoded as a no-op request control because it has a value.
   */
  ERR_NOOP_REQUEST_HAS_VALUE("The provided control cannot be decoded as a no-op request control because it has a value."),



  /**
   * The provided control cannot be decoded as a password policy request control because it has a value.
   */
  ERR_PWP_REQUEST_HAS_VALUE("The provided control cannot be decoded as a password policy request control because it has a value."),



  /**
   * The provided control cannot be decoded as a password policy response control because the error type element could not be decoded:  {0}
   */
  ERR_PWP_RESPONSE_CANNOT_DECODE_ERROR("The provided control cannot be decoded as a password policy response control because the error type element could not be decoded:  {0}"),



  /**
   * The provided control cannot be decoded as a password policy response control because the warning type element could not be decoded:  {0}
   */
  ERR_PWP_RESPONSE_CANNOT_DECODE_WARNING("The provided control cannot be decoded as a password policy response control because the warning type element could not be decoded:  {0}"),



  /**
   * The provided control cannot be decoded as a password policy response control because there were too many elements in the value sequence (expected between 0 and 2, got {0,number,0}).
   */
  ERR_PWP_RESPONSE_INVALID_ELEMENT_COUNT("The provided control cannot be decoded as a password policy response control because there were too many elements in the value sequence (expected between 0 and 2, got {0,number,0})."),



  /**
   * The provided control cannot be decoded as a password policy response control because it had an invalid error type ({0}).
   */
  ERR_PWP_RESPONSE_INVALID_ERROR_TYPE("The provided control cannot be decoded as a password policy response control because it had an invalid error type ({0})."),



  /**
   * The provided control cannot be decoded as a password policy response control because the value sequence contained an element with an invalid type ({0}).
   */
  ERR_PWP_RESPONSE_INVALID_TYPE("The provided control cannot be decoded as a password policy response control because the value sequence contained an element with an invalid type ({0})."),



  /**
   * The provided control cannot be decoded as a password policy response control because the warning type element had an invalid type ({0}).
   */
  ERR_PWP_RESPONSE_INVALID_WARNING_TYPE("The provided control cannot be decoded as a password policy response control because the warning type element had an invalid type ({0})."),



  /**
   * The provided control cannot be decoded as a password policy response control because the value sequence contained multiple error elements.
   */
  ERR_PWP_RESPONSE_MULTIPLE_ERROR("The provided control cannot be decoded as a password policy response control because the value sequence contained multiple error elements."),



  /**
   * The provided control cannot be decoded as a password policy response control because the value sequence contained multiple warning elements.
   */
  ERR_PWP_RESPONSE_MULTIPLE_WARNING("The provided control cannot be decoded as a password policy response control because the value sequence contained multiple warning elements."),



  /**
   * The provided control cannot be decoded as a password policy response control because it does not have a value.
   */
  ERR_PWP_RESPONSE_NO_VALUE("The provided control cannot be decoded as a password policy response control because it does not have a value."),



  /**
   * The provided control cannot be decoded as a password policy response control because the control value could not be decoded as a sequence:  {0}
   */
  ERR_PWP_RESPONSE_VALUE_NOT_SEQUENCE("The provided control cannot be decoded as a password policy response control because the control value could not be decoded as a sequence:  {0}"),



  /**
   * Active Directory DirSync Control
   */
  INFO_CONTROL_NAME_DIRSYNC("Active Directory DirSync Control"),



  /**
   * No-Op Request Control
   */
  INFO_CONTROL_NAME_NOOP_REQUEST("No-Op Request Control"),



  /**
   * Password Policy Request Control
   */
  INFO_CONTROL_NAME_PW_POLICY_REQUEST("Password Policy Request Control"),



  /**
   * Password Policy Response Control
   */
  INFO_CONTROL_NAME_PW_POLICY_RESPONSE("Password Policy Response Control");



  /**
   * The resource bundle that will be used to load the properties file.
   */
  private static final ResourceBundle RESOURCE_BUNDLE;
  static
  {
    ResourceBundle rb = null;
    try
    {
      rb = ResourceBundle.getBundle("ldap-ldapsdk-experimental");
    } catch (Exception e) {}
    RESOURCE_BUNDLE = rb;
  }



  /**
   * The map that will be used to hold the unformatted message strings, indexed by property name.
   */
  private static final ConcurrentHashMap<ExperimentalMessages,String> MESSAGE_STRINGS = new ConcurrentHashMap<ExperimentalMessages,String>();



  /**
   * The map that will be used to hold the message format objects, indexed by property name.
   */
  private static final ConcurrentHashMap<ExperimentalMessages,MessageFormat> MESSAGES = new ConcurrentHashMap<ExperimentalMessages,MessageFormat>();



  // The default text for this message
  private final String defaultText;



  /**
   * Creates a new message key.
   */
  private ExperimentalMessages(final String defaultText)
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


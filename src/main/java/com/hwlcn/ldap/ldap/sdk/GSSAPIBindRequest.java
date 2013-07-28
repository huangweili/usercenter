
package com.hwlcn.ldap.ldap.sdk;



import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginContext;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.util.DebugType;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides a SASL GSSAPI bind request implementation as described in
 * <A HREF="http://www.ietf.org/rfc/rfc4752.txt">RFC 4752</A>.  It provides the
 * ability to authenticate to a directory server using Kerberos V, which can
 * serve as a kind of single sign-on mechanism that may be shared across
 * client applications that support Kerberos.  At present, this implementation
 * may only be used for authentication, as it does not yet offer support for
 * integrity or confidentiality.
 * <BR><BR>
 * This class uses the Java Authentication and Authorization Service (JAAS)
 * behind the scenes to perform all Kerberos processing.  This framework
 * requires a configuration file to indicate the underlying mechanism to be
 * used.  It is possible for clients to explicitly specify the path to the
 * configuration file that should be used, but if none is given then a default
 * file will be created and used.  This default file should be sufficient for
 * Sun-provided JVMs, but a custom file may be required for JVMs provided by
 * other vendors.
 * <BR><BR>
 * Elements included in a GSSAPI bind request include:
 * <UL>
 *   <LI>Authentication ID -- A string which identifies the user that is
 *       attempting to authenticate.  It should be the user's Kerberos
 *       principal.</LI>
 *   <LI>Authorization ID -- An optional string which specifies an alternate
 *       authorization identity that should be used for subsequent operations
 *       requested on the connection.  Like the authentication ID, the
 *       authorization ID should be a Kerberos principal.</LI>
 *   <LI>KDC Address -- An optional string which specifies the IP address or
 *       resolvable name for the Kerberos key distribution center.  If this is
 *       not provided, an attempt will be made to determine the appropriate
 *       value from the system configuration.</LI>
 *   <LI>Realm -- An optional string which specifies the realm into which the
 *       user should authenticate.  If this is not provided, an attempt will be
 *       made to determine the appropriate value from the system
 *       configuration</LI>
 *   <LI>Password -- The clear-text password for the target user in the Kerberos
 *       realm.</LI>
 * </UL>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing a GSSAPI bind
 * against a directory server with a username of "john.doe" and a password
 * of "password":
 * <PRE>
 *   GSSAPIBindRequest bindRequest =
 *        new GSSAPIBindRequest("john.doe@EXAMPLE.COM", "password");
 *   try
 *   {
 *     BindResult bindResult = connection.bind(bindRequest);
 *     // If we get here, then the bind was successful.
 *   }
 *   catch (LDAPException le)
 *   {
 *     // The bind failed for some reason.
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class GSSAPIBindRequest
       extends SASLBindRequest
       implements CallbackHandler, PrivilegedExceptionAction<Object>
{
  public static final String GSSAPI_MECHANISM_NAME = "GSSAPI";




  private static final String PROPERTY_KDC_ADDRESS = "java.security.krb5.kdc";



  private static final String PROPERTY_REALM = "java.security.krb5.realm";




  private static final String PROPERTY_CONFIG_FILE =
       "java.security.auth.login.config";




  private static final String PROPERTY_SUBJECT_CREDS_ONLY =
       "javax.security.auth.useSubjectCredsOnly";



  private static final String DEFAULT_CONFIG_FILE =
       System.getProperty(PROPERTY_CONFIG_FILE);



  private static final String DEFAULT_KDC_ADDRESS =
       System.getProperty(PROPERTY_KDC_ADDRESS);


  private static final String DEFAULT_REALM =
       System.getProperty(PROPERTY_REALM);



  private static final String JAAS_CLIENT_NAME = "GSSAPIBindRequest";



  private static final long serialVersionUID = 2511890818146955112L;



  private final ASN1OctetString password;

  private final AtomicReference<LDAPConnection> conn;

  private final boolean enableGSSAPIDebugging;


  private boolean renewTGT;


  private boolean requireCachedCredentials;

  private boolean useTicketCache;

  private int messageID;

  private final String authenticationID;

  private final String authorizationID;

  private final String configFilePath;

  private final String kdcAddress;

  private final String realm;


  private final String servicePrincipalProtocol;

  private String ticketCachePath;



  public GSSAPIBindRequest(final String authenticationID, final String password)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, password));
  }




  public GSSAPIBindRequest(final String authenticationID, final byte[] password)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, password));
  }



  public GSSAPIBindRequest(final String authenticationID, final String password,
                           final Control[] controls)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, password), controls);
  }




  public GSSAPIBindRequest(final String authenticationID, final byte[] password,
                           final Control[] controls)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, password), controls);
  }



  public GSSAPIBindRequest(final String authenticationID,
                           final String authorizationID, final String password,
                           final String realm, final String kdcAddress,
                           final String configFilePath)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, authorizationID,
         new ASN1OctetString(password), realm, kdcAddress, configFilePath));
  }



  public GSSAPIBindRequest(final String authenticationID,
                           final String authorizationID, final byte[] password,
                           final String realm, final String kdcAddress,
                           final String configFilePath)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, authorizationID,
         new ASN1OctetString(password), realm, kdcAddress, configFilePath));
  }



  public GSSAPIBindRequest(final String authenticationID,
                           final String authorizationID, final String password,
                           final String realm, final String kdcAddress,
                           final String configFilePath,
                           final Control[] controls)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, authorizationID,
         new ASN1OctetString(password), realm, kdcAddress, configFilePath),
         controls);
  }



  public GSSAPIBindRequest(final String authenticationID,
                           final String authorizationID, final byte[] password,
                           final String realm, final String kdcAddress,
                           final String configFilePath,
                           final Control[] controls)
         throws LDAPException
  {
    this(new GSSAPIBindRequestProperties(authenticationID, authorizationID,
         new ASN1OctetString(password), realm, kdcAddress, configFilePath),
         controls);
  }



  public GSSAPIBindRequest(final GSSAPIBindRequestProperties gssapiProperties,
                           final Control... controls)
          throws LDAPException
  {
    super(controls);

    ensureNotNull(gssapiProperties);

    authenticationID         = gssapiProperties.getAuthenticationID();
    password                 = gssapiProperties.getPassword();
    realm                    = gssapiProperties.getRealm();
    kdcAddress               = gssapiProperties.getKDCAddress();
    servicePrincipalProtocol = gssapiProperties.getServicePrincipalProtocol();
    enableGSSAPIDebugging    = gssapiProperties.enableGSSAPIDebugging();
    useTicketCache           = gssapiProperties.useTicketCache();
    requireCachedCredentials = gssapiProperties.requireCachedCredentials();
    renewTGT                 = gssapiProperties.renewTGT();
    ticketCachePath          = gssapiProperties.getTicketCachePath();

    conn      = new AtomicReference<LDAPConnection>();
    messageID = -1;

    final String authzID = gssapiProperties.getAuthorizationID();
    if (authzID == null)
    {
      authorizationID = null;
    }
    else
    {
      authorizationID = authzID;
    }

    final String cfgPath = gssapiProperties.getConfigFilePath();
    if (cfgPath == null)
    {
      if (DEFAULT_CONFIG_FILE == null)
      {
        configFilePath = getConfigFilePath(gssapiProperties);
      }
      else
      {
        configFilePath = DEFAULT_CONFIG_FILE;
      }
    }
    else
    {
      configFilePath = cfgPath;
    }
  }




  @Override()
  public String getSASLMechanismName()
  {
    return GSSAPI_MECHANISM_NAME;
  }




  public String getAuthenticationID()
  {
    return authenticationID;
  }



  public String getAuthorizationID()
  {
    return authorizationID;
  }




  public String getPasswordString()
  {
    if (password == null)
    {
      return null;
    }
    else
    {
      return password.stringValue();
    }
  }



  public byte[] getPasswordBytes()
  {
    if (password == null)
    {
      return null;
    }
    else
    {
      return password.getValue();
    }
  }



  public String getRealm()
  {
    return realm;
  }


  public String getKDCAddress()
  {
    return kdcAddress;
  }


  public String getConfigFilePath()
  {
    return configFilePath;
  }



  public String getServicePrincipalProtocol()
  {
    return servicePrincipalProtocol;
  }


  public boolean useTicketCache()
  {
    return useTicketCache;
  }


  public boolean requireCachedCredentials()
  {
    return requireCachedCredentials;
  }



  public String getTicketCachePath()
  {
    return ticketCachePath;
  }



  public boolean renewTGT()
  {
    return renewTGT;
  }




  public boolean enableGSSAPIDebugging()
  {
    return enableGSSAPIDebugging;
  }




  private static String getConfigFilePath(
                             final GSSAPIBindRequestProperties properties)
          throws LDAPException
  {
    try
    {
      final File f =
           File.createTempFile("GSSAPIBindRequest-JAAS-Config-", ".conf");
      f.deleteOnExit();
      final PrintWriter w = new PrintWriter(new FileWriter(f));

      try
      {
        try
        {
          final Class<?> sunModuleClass =
               Class.forName("com.sun.security.auth.module.Krb5LoginModule");
          if (sunModuleClass != null)
          {
            writeSunJAASConfig(w, properties);
            return f.getAbsolutePath();
          }
        }
        catch (final ClassNotFoundException cnfe)
        {

          debugException(cnfe);
        }


        try
        {
          final Class<?> ibmModuleClass =
               Class.forName("com.ibm.security.auth.module.Krb5LoginModule");
          if (ibmModuleClass != null)
          {
            writeIBMJAASConfig(w, properties);
            return f.getAbsolutePath();
          }
        }
        catch (final ClassNotFoundException cnfe)
        {

          debugException(cnfe);
        }


        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_GSSAPI_CANNOT_CREATE_JAAS_CONFIG.get(
                  ERR_GSSAPI_NO_SUPPORTED_JAAS_MODULE.get()));
      }
      finally
      {
        w.close();
      }
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_GSSAPI_CANNOT_CREATE_JAAS_CONFIG.get(getExceptionMessage(e)), e);
    }
  }


  private static void writeSunJAASConfig(final PrintWriter w,
                                         final GSSAPIBindRequestProperties p)
  {
    w.println(JAAS_CLIENT_NAME + " {");
    w.println("  com.sun.security.auth.module.Krb5LoginModule required");
    w.println("  client=true");

    if (p.useTicketCache())
    {
      w.println("  useTicketCache=true");
      w.println("  renewTGT=" + p.renewTGT());
      w.println("  doNotPrompt=" + p.requireCachedCredentials());

      final String ticketCachePath = p.getTicketCachePath();
      if (ticketCachePath != null)
      {
        w.println("  ticketCache=\"" + ticketCachePath + '"');
      }
    }
    else
    {
      w.println("  useTicketCache=false");
    }

    if (p.enableGSSAPIDebugging())
    {
      w.println(" debug=true");
    }

    w.println("  ;");
    w.println("};");
  }



  private static void writeIBMJAASConfig(final PrintWriter w,
                                         final GSSAPIBindRequestProperties p)
  {

    w.println(JAAS_CLIENT_NAME + " {");
    w.println("  com.ibm.security.auth.module.Krb5LoginModule required");
    w.println("  credsType=initiator");

    if (p.useTicketCache())
    {
      final String ticketCachePath = p.getTicketCachePath();
      if (ticketCachePath == null)
      {
        if (p.requireCachedCredentials())
        {
          w.println("  useDefaultCcache=true");
        }
      }
      else
      {
        final File f = new File(ticketCachePath);
        final String path = f.getAbsolutePath().replace('\\', '/');
        w.println("  useCcache=\"file://" + path + '"');
      }
    }
    else
    {
      w.println("  useDefaultCcache=false");
    }

    if (p.enableGSSAPIDebugging())
    {
      w.println(" debug=true");
    }

    w.println("  ;");
    w.println("};");
  }



  @Override()
  protected BindResult process(final LDAPConnection connection, final int depth)
            throws LDAPException
  {
    if (! conn.compareAndSet(null, connection))
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
                     ERR_GSSAPI_MULTIPLE_CONCURRENT_REQUESTS.get());
    }

    System.setProperty(PROPERTY_CONFIG_FILE, configFilePath);
    System.setProperty(PROPERTY_SUBJECT_CREDS_ONLY, "true");
    if (debugEnabled(DebugType.LDAP))
    {
      debug(Level.CONFIG, DebugType.LDAP,
           "Using config file property " + PROPERTY_CONFIG_FILE + " = '" +
                configFilePath + "'.");
      debug(Level.CONFIG, DebugType.LDAP,
           "Using subject creds only property " + PROPERTY_SUBJECT_CREDS_ONLY +
                " = 'true'.");
    }

    if (kdcAddress == null)
    {
      if (DEFAULT_KDC_ADDRESS == null)
      {
        System.clearProperty(PROPERTY_KDC_ADDRESS);
        if (debugEnabled(DebugType.LDAP))
        {
          debug(Level.CONFIG, DebugType.LDAP,
               "Clearing kdcAddress property '" + PROPERTY_KDC_ADDRESS + "'.");
        }
      }
      else
      {
        System.setProperty(PROPERTY_KDC_ADDRESS, DEFAULT_KDC_ADDRESS);
        if (debugEnabled(DebugType.LDAP))
        {
          debug(Level.CONFIG, DebugType.LDAP,
               "Using default kdcAddress property " + PROPERTY_KDC_ADDRESS +
                    " = '" + DEFAULT_KDC_ADDRESS + "'.");
        }
      }
    }
    else
    {
      System.setProperty(PROPERTY_KDC_ADDRESS, kdcAddress);
      if (debugEnabled(DebugType.LDAP))
      {
        debug(Level.CONFIG, DebugType.LDAP,
             "Using kdcAddress property " + PROPERTY_KDC_ADDRESS + " = '" +
                  kdcAddress + "'.");
      }
    }

    if (realm == null)
    {
      if (DEFAULT_REALM == null)
      {
        System.clearProperty(PROPERTY_REALM);
        if (debugEnabled(DebugType.LDAP))
        {
          debug(Level.CONFIG, DebugType.LDAP,
               "Clearing realm property '" + PROPERTY_REALM + "'.");
        }
      }
      else
      {
        System.setProperty(PROPERTY_REALM, DEFAULT_REALM);
        if (debugEnabled(DebugType.LDAP))
        {
          debug(Level.CONFIG, DebugType.LDAP,
               "Using default realm property " + PROPERTY_REALM + " = '" +
                    DEFAULT_REALM + "'.");
        }
      }
    }
    else
    {
      System.setProperty(PROPERTY_REALM, realm);
      if (debugEnabled(DebugType.LDAP))
      {
        debug(Level.CONFIG, DebugType.LDAP,
             "Using realm property " + PROPERTY_REALM + " = '" + realm + "'.");
      }
    }

    try
    {
      final LoginContext context;
      try
      {
        context = new LoginContext(JAAS_CLIENT_NAME, this);
        context.login();
      }
      catch (Exception e)
      {
        debugException(e);

        throw new LDAPException(ResultCode.LOCAL_ERROR,
                       ERR_GSSAPI_CANNOT_INITIALIZE_JAAS_CONTEXT.get(
                            getExceptionMessage(e)), e);
      }

      try
      {
        return (BindResult) Subject.doAs(context.getSubject(), this);
      }
      catch (Exception e)
      {
        debugException(e);
        if (e instanceof LDAPException)
        {
          throw (LDAPException) e;
        }
        else
        {
          throw new LDAPException(ResultCode.LOCAL_ERROR,
                         ERR_GSSAPI_AUTHENTICATION_FAILED.get(
                              getExceptionMessage(e)), e);
        }
      }
    }
    finally
    {
      conn.set(null);
    }
  }



  @InternalUseOnly()
  public Object run()
         throws LDAPException
  {
    final LDAPConnection connection = conn.get();

    final String[] mechanisms = { GSSAPI_MECHANISM_NAME };

    final HashMap<String,Object> saslProperties = new HashMap<String,Object>(2);
    saslProperties.put(Sasl.QOP, "auth");
    saslProperties.put(Sasl.SERVER_AUTH, "true");

    final SaslClient saslClient;
    try
    {
      saslClient = Sasl.createSaslClient(mechanisms, authorizationID,
           servicePrincipalProtocol, connection.getConnectedAddress(),
           saslProperties, this);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_GSSAPI_CANNOT_CREATE_SASL_CLIENT.get(getExceptionMessage(e)), e);
    }

    final SASLHelper helper = new SASLHelper(this, connection,
         GSSAPI_MECHANISM_NAME, saslClient, getControls(),
         getResponseTimeoutMillis(connection));

    try
    {
      return helper.processSASLBind();
    }
    finally
    {
      messageID = helper.getMessageID();
    }
  }




  @Override()
  public GSSAPIBindRequest getRebindRequest(final String host, final int port)
  {
    try
    {
      final GSSAPIBindRequestProperties gssapiProperties =
           new GSSAPIBindRequestProperties(authenticationID, authorizationID,
                password, realm, kdcAddress, configFilePath);
      gssapiProperties.setServicePrincipalProtocol(servicePrincipalProtocol);
      gssapiProperties.setUseTicketCache(useTicketCache);
      gssapiProperties.setRequireCachedCredentials(requireCachedCredentials);
      gssapiProperties.setRenewTGT(renewTGT);
      gssapiProperties.setTicketCachePath(ticketCachePath);
      gssapiProperties.setEnableGSSAPIDebugging(enableGSSAPIDebugging);

      return new GSSAPIBindRequest(gssapiProperties, getControls());
    }
    catch (Exception e)
    {
      debugException(e);
      return null;
    }
  }


  @InternalUseOnly()
  public void handle(final Callback[] callbacks)
  {
    for (final Callback callback : callbacks)
    {
      if (callback instanceof NameCallback)
      {
        ((NameCallback) callback).setName(authenticationID);
      }
      else if (callback instanceof PasswordCallback)
      {
        if (password == null)
        {
          throw new LDAPRuntimeException(new LDAPException(
               ResultCode.PARAM_ERROR,
               ERR_GSSAPI_NO_PASSWORD_AVAILABLE.get()));
        }
        else
        {
          ((PasswordCallback) callback).setPassword(
               password.stringValue().toCharArray());
        }
      }
      else if (callback instanceof RealmCallback)
      {
        if (realm != null)
        {
          ((RealmCallback) callback).setText(realm);
        }
      }
      else
      {
        if (debugEnabled(DebugType.LDAP))
        {
          debug(Level.WARNING, DebugType.LDAP,
                "Unexpected GSSAPI SASL callback of type " +
                callback.getClass().getName());
        }
      }
    }
  }



  @Override()
  public int getLastMessageID()
  {
    return messageID;
  }



  @Override()
  public GSSAPIBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  @Override()
  public GSSAPIBindRequest duplicate(final Control[] controls)
  {
    try
    {
      final GSSAPIBindRequestProperties gssapiProperties =
           new GSSAPIBindRequestProperties(authenticationID, authorizationID,
                password, realm, kdcAddress, configFilePath);
      gssapiProperties.setServicePrincipalProtocol(servicePrincipalProtocol);
      gssapiProperties.setUseTicketCache(useTicketCache);
      gssapiProperties.setRequireCachedCredentials(requireCachedCredentials);
      gssapiProperties.setRenewTGT(renewTGT);
      gssapiProperties.setTicketCachePath(ticketCachePath);
      gssapiProperties.setEnableGSSAPIDebugging(enableGSSAPIDebugging);

      final GSSAPIBindRequest bindRequest =
           new GSSAPIBindRequest(gssapiProperties, controls);
      bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
      return bindRequest;
    }
    catch (Exception e)
    {
      debugException(e);
      return null;
    }
  }




  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("GSSAPIBindRequest(authenticationID='");
    buffer.append(authenticationID);
    buffer.append('\'');

    if (authorizationID != null)
    {
      buffer.append(", authorizationID='");
      buffer.append(authorizationID);
      buffer.append('\'');
    }

    if (realm != null)
    {
      buffer.append(", realm='");
      buffer.append(realm);
      buffer.append('\'');
    }

    if (kdcAddress != null)
    {
      buffer.append(", kdcAddress='");
      buffer.append(kdcAddress);
      buffer.append('\'');
    }

    buffer.append(", configFilePath='");
    buffer.append(configFilePath);
    buffer.append("', servicePrincipalProtocol='");
    buffer.append(servicePrincipalProtocol);
    buffer.append("', enableGSSAPIDebugging=");
    buffer.append(enableGSSAPIDebugging);

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
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

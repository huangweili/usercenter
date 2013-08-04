
package com.hwlcn.ldap.util;



import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.ldap.sdk.ANONYMOUSBindRequest;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.CRAMMD5BindRequest;
import com.hwlcn.ldap.ldap.sdk.DIGESTMD5BindRequest;
import com.hwlcn.ldap.ldap.sdk.EXTERNALBindRequest;
import com.hwlcn.ldap.ldap.sdk.GSSAPIBindRequest;
import com.hwlcn.ldap.ldap.sdk.GSSAPIBindRequestProperties;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.PLAINBindRequest;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.ldap.sdk.SASLBindRequest;

import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.UtilityMessages.*;



@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SASLUtils
{

  public static final String SASL_OPTION_AUTH_ID = "authID";



  public static final String SASL_OPTION_AUTHZ_ID = "authzID";



  public static final String SASL_OPTION_CONFIG_FILE = "configFile";


  public static final String SASL_OPTION_DEBUG = "debug";


  public static final String SASL_OPTION_KDC_ADDRESS = "kdcAddress";



  public static final String SASL_OPTION_MECHANISM = "mech";



  public static final String SASL_OPTION_PROTOCOL = "protocol";


  public static final String SASL_OPTION_REALM = "realm";


  public static final String SASL_OPTION_REQUIRE_CACHE = "requireCache";




  public static final String SASL_OPTION_RENEW_TGT = "renewTGT";

  public static final String SASL_OPTION_TICKET_CACHE_PATH = "ticketCache";


  public static final String SASL_OPTION_TRACE = "trace";

  public static final String SASL_OPTION_USE_TICKET_CACHE = "useTicketCache";


  private static final Map<String,SASLMechanismInfo> SASL_MECHANISMS;



  static
  {
    final TreeMap<String,SASLMechanismInfo> m =
         new TreeMap<String,SASLMechanismInfo>();

    m.put(toLowerCase(ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME),
         new SASLMechanismInfo(ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME,
              INFO_SASL_ANONYMOUS_DESCRIPTION.get(), false, false,
              new SASLOption(SASL_OPTION_TRACE,
                   INFO_SASL_ANONYMOUS_OPTION_TRACE.get(), false, false)));

    m.put(toLowerCase(CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME),
         new SASLMechanismInfo(CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME,
              INFO_SASL_CRAM_MD5_DESCRIPTION.get(), true, true,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_CRAM_MD5_OPTION_AUTH_ID.get(), true, false)));

    m.put(toLowerCase(DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME),
         new SASLMechanismInfo(DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME,
              INFO_SASL_DIGEST_MD5_DESCRIPTION.get(), true, true,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_DIGEST_MD5_OPTION_AUTH_ID.get(), true, false),
              new SASLOption(SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_DIGEST_MD5_OPTION_AUTHZ_ID.get(), false, false),
              new SASLOption(SASL_OPTION_REALM,
                   INFO_SASL_DIGEST_MD5_OPTION_REALM.get(), false, false)));

    m.put(toLowerCase(EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME),
         new SASLMechanismInfo(EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME,
              INFO_SASL_EXTERNAL_DESCRIPTION.get(), false, false));

    m.put(toLowerCase(GSSAPIBindRequest.GSSAPI_MECHANISM_NAME),
         new SASLMechanismInfo(GSSAPIBindRequest.GSSAPI_MECHANISM_NAME,
              INFO_SASL_GSSAPI_DESCRIPTION.get(), true, false,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_GSSAPI_OPTION_AUTH_ID.get(), true, false),
              new SASLOption(SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_GSSAPI_OPTION_AUTHZ_ID.get(), false, false),
              new SASLOption(SASL_OPTION_CONFIG_FILE,
                   INFO_SASL_GSSAPI_OPTION_CONFIG_FILE.get(), false, false),
              new SASLOption(SASL_OPTION_DEBUG,
                   INFO_SASL_GSSAPI_OPTION_DEBUG.get(), false, false),
              new SASLOption(SASL_OPTION_KDC_ADDRESS,
                   INFO_SASL_GSSAPI_OPTION_KDC_ADDRESS.get(), false, false),
              new SASLOption(SASL_OPTION_PROTOCOL,
                   INFO_SASL_GSSAPI_OPTION_PROTOCOL.get(), false, false),
              new SASLOption(SASL_OPTION_REALM,
                   INFO_SASL_GSSAPI_OPTION_REALM.get(), false, false),
              new SASLOption(SASL_OPTION_RENEW_TGT,
                   INFO_SASL_GSSAPI_OPTION_RENEW_TGT.get(), false, false),
              new SASLOption(SASL_OPTION_REQUIRE_CACHE,
                   INFO_SASL_GSSAPI_OPTION_REQUIRE_TICKET_CACHE.get(), false,
                   false),
              new SASLOption(SASL_OPTION_TICKET_CACHE_PATH,
                   INFO_SASL_GSSAPI_OPTION_TICKET_CACHE.get(), false, false),
              new SASLOption(SASL_OPTION_USE_TICKET_CACHE,
                   INFO_SASL_GSSAPI_OPTION_USE_TICKET_CACHE.get(), false,
                   false)));

    m.put(toLowerCase(PLAINBindRequest.PLAIN_MECHANISM_NAME),
         new SASLMechanismInfo(PLAINBindRequest.PLAIN_MECHANISM_NAME,
              INFO_SASL_PLAIN_DESCRIPTION.get(), true, true,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_PLAIN_OPTION_AUTH_ID.get(), true, false),
              new SASLOption(SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_PLAIN_OPTION_AUTHZ_ID.get(), false, false)));


    try
    {
      final Class<?> c =
           Class.forName("com.hwlcn.ldap.ldap.sdk.unboundidds.SASLHelper");
      final Method addCESASLInfoMethod =
           c.getMethod("addCESASLInfo", Map.class);
      addCESASLInfoMethod.invoke(null, m);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    SASL_MECHANISMS = Collections.unmodifiableMap(m);
  }

  private SASLUtils()
  {
  }



  public static List<SASLMechanismInfo> getSupportedSASLMechanisms()
  {
    return Collections.unmodifiableList(new ArrayList<SASLMechanismInfo>(
         SASL_MECHANISMS.values()));
  }

  public static SASLMechanismInfo getSASLMechanismInfo(final String mechanism)
  {
    return SASL_MECHANISMS.get(toLowerCase(mechanism));
  }

  public static SASLBindRequest createBindRequest(final String bindDN,
                                                  final String password,
                                                  final String mechanism,
                                                  final String... options)
         throws LDAPException
  {
    return createBindRequest(bindDN,
         (password == null ? null : getBytes(password)), mechanism,
         StaticUtils.toList(options));
  }



  public static SASLBindRequest createBindRequest(final String bindDN,
                                                  final String password,
                                                  final String mechanism,
                                                  final List<String> options,
                                                  final Control... controls)
         throws LDAPException
  {
    return createBindRequest(bindDN,
         (password == null ? null : getBytes(password)), mechanism, options,
         controls);
  }



  public static SASLBindRequest createBindRequest(final String bindDN,
                                                  final byte[] password,
                                                  final String mechanism,
                                                  final String... options)
         throws LDAPException
  {
    return createBindRequest(bindDN, password, mechanism,
         StaticUtils.toList(options));
  }


  public static SASLBindRequest createBindRequest(final String bindDN,
                                                  final byte[] password,
                                                  final String mechanism,
                                                  final List<String> options,
                                                  final Control... controls)
         throws LDAPException
  {
    final String mech;
    final Map<String,String> optionsMap = parseOptions(options);
    final String mechOption =
         optionsMap.remove(toLowerCase(SASL_OPTION_MECHANISM));
    if (mechOption != null)
    {
      mech = mechOption;
      if ((mechanism != null) && (! mech.equalsIgnoreCase(mechanism)))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_MECH_CONFLICT.get(mechanism, mech));
      }
    }
    else
    {
      mech = mechanism;
    }

    if (mech == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_NO_MECH.get());
    }

    if (mech.equalsIgnoreCase(ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME))
    {
      return createANONYMOUSBindRequest(password, optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME))
    {
      return createCRAMMD5BindRequest(password, optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(
                  DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME))
    {
      return createDIGESTMD5BindRequest(password, optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME))
    {
      return createEXTERNALBindRequest(password, optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(GSSAPIBindRequest.GSSAPI_MECHANISM_NAME))
    {
      return createGSSAPIBindRequest(password, optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(PLAINBindRequest.PLAIN_MECHANISM_NAME))
    {
      return createPLAINBindRequest(password, optionsMap, controls);
    }
    else
    {
      try
      {
        final Class<?> c =
             Class.forName("com.hwlcn.ldap.ldap.sdk.unboundidds.SASLHelper");
        final Method createBindRequestMethod = c.getMethod("createBindRequest",
             String.class, StaticUtils.NO_BYTES.getClass(), String.class,
             Map.class, StaticUtils.NO_CONTROLS.getClass());
        final Object bindRequestObject = createBindRequestMethod.invoke(null,
             bindDN, password, mech, optionsMap, controls);
        if (bindRequestObject != null)
        {
          return (SASLBindRequest) bindRequestObject;
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if (e instanceof InvocationTargetException)
        {
          final InvocationTargetException ite = (InvocationTargetException) e;
          final Throwable t = ite.getTargetException();
          if (t instanceof LDAPException)
          {
            throw (LDAPException) t;
          }
        }
      }

      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_UNSUPPORTED_MECH.get(mech));
    }
  }



  private static ANONYMOUSBindRequest createANONYMOUSBindRequest(
                                           final byte[] password,
                                           final Map<String,String> options,
                                           final Control[] controls)
          throws LDAPException
  {
    if (password != null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MECH_DOESNT_ACCEPT_PASSWORD.get(
                ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME));
    }


    final String trace = options.remove(toLowerCase(SASL_OPTION_TRACE));

    ensureNoUnsupportedOptions(options,
         ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME);

    return new ANONYMOUSBindRequest(trace, controls);
  }



  private static CRAMMD5BindRequest createCRAMMD5BindRequest(
                                         final byte[] password,
                                         final Map<String,String> options,
                                         final Control[] controls)
          throws LDAPException
  {
    if (password == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MECH_REQUIRES_PASSWORD.get(
                CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME));
    }


    final String authID = options.remove(toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME));
    }

    ensureNoUnsupportedOptions(options,
         CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME);

    return new CRAMMD5BindRequest(authID, password, controls);
  }



  private static DIGESTMD5BindRequest createDIGESTMD5BindRequest(
                                           final byte[] password,
                                           final Map<String,String> options,
                                           final Control[] controls)
          throws LDAPException
  {
    if (password == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MECH_REQUIRES_PASSWORD.get(
                DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME));
    }
    final String authID = options.remove(toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME));
    }

    final String authzID = options.remove(toLowerCase(SASL_OPTION_AUTHZ_ID));

    final String realm = options.remove(toLowerCase(SASL_OPTION_REALM));

    ensureNoUnsupportedOptions(options,
         DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME);

    return new DIGESTMD5BindRequest(authID, authzID, password, realm, controls);
  }



  private static EXTERNALBindRequest createEXTERNALBindRequest(
                                          final byte[] password,
                                          final Map<String,String> options,
                                          final Control[] controls)
          throws LDAPException
  {
    if (password != null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MECH_DOESNT_ACCEPT_PASSWORD.get(
                EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME));
    }

    ensureNoUnsupportedOptions(options,
         EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME);

    return new EXTERNALBindRequest(controls);
  }




  private static GSSAPIBindRequest createGSSAPIBindRequest(
                                        final byte[] password,
                                        final Map<String,String> options,
                                        final Control[] controls)
          throws LDAPException
  {
    final String authID = options.remove(toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                GSSAPIBindRequest.GSSAPI_MECHANISM_NAME));
    }
    final GSSAPIBindRequestProperties gssapiProperties =
         new GSSAPIBindRequestProperties(authID, password);

    gssapiProperties.setAuthorizationID(
         options.remove(toLowerCase(SASL_OPTION_AUTHZ_ID)));

    gssapiProperties.setConfigFilePath(options.remove(toLowerCase(
         SASL_OPTION_CONFIG_FILE)));

    gssapiProperties.setEnableGSSAPIDebugging(getBooleanValue(options,
         SASL_OPTION_DEBUG, false));

    gssapiProperties.setKDCAddress(options.remove(
         toLowerCase(SASL_OPTION_KDC_ADDRESS)));

    final String protocol = options.remove(toLowerCase(SASL_OPTION_PROTOCOL));
    if (protocol != null)
    {
      gssapiProperties.setServicePrincipalProtocol(protocol);
    }

    gssapiProperties.setRealm(options.remove(toLowerCase(SASL_OPTION_REALM)));

    gssapiProperties.setRenewTGT(getBooleanValue(options, SASL_OPTION_RENEW_TGT,
         false));

    gssapiProperties.setRequireCachedCredentials(getBooleanValue(options,
         SASL_OPTION_REQUIRE_CACHE, false));

    gssapiProperties.setTicketCachePath(options.remove(toLowerCase(
         SASL_OPTION_TICKET_CACHE_PATH)));

    gssapiProperties.setUseTicketCache(getBooleanValue(options,
         SASL_OPTION_USE_TICKET_CACHE, true));

    ensureNoUnsupportedOptions(options,
         GSSAPIBindRequest.GSSAPI_MECHANISM_NAME);

    if (password == null)
    {
      if (! (gssapiProperties.useTicketCache() &&
           gssapiProperties.requireCachedCredentials()))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_GSSAPI_PASSWORD_REQUIRED.get());
      }
    }

    return new GSSAPIBindRequest(gssapiProperties, controls);
  }



  private static PLAINBindRequest createPLAINBindRequest(
                                        final byte[] password,
                                        final Map<String,String> options,
                                        final Control[] controls)
          throws LDAPException
  {
    if (password == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MECH_REQUIRES_PASSWORD.get(
                PLAINBindRequest.PLAIN_MECHANISM_NAME));
    }

    final String authID = options.remove(toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                PLAINBindRequest.PLAIN_MECHANISM_NAME));
    }

    final String authzID = options.remove(toLowerCase(SASL_OPTION_AUTHZ_ID));

    ensureNoUnsupportedOptions(options,
         PLAINBindRequest.PLAIN_MECHANISM_NAME);

    return new PLAINBindRequest(authID, authzID, password, controls);
  }



  private static Map<String,String>
                      parseOptions(final List<String> options)
          throws LDAPException
  {
    if (options == null)
    {
      return new HashMap<String,String>(0);
    }

    final HashMap<String,String> m = new HashMap<String,String>(options.size());
    for (final String s : options)
    {
      final int equalPos = s.indexOf('=');
      if (equalPos < 0)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_MISSING_EQUAL.get(s));
      }
      else if (equalPos == 0)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_STARTS_WITH_EQUAL.get(s));
      }

      final String name = s.substring(0, equalPos);
      final String value = s.substring(equalPos + 1);
      if (m.put(toLowerCase(name), value) != null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_NOT_MULTI_VALUED.get(name));
      }
    }

    return m;
  }



  @InternalUseOnly()
  public static void ensureNoUnsupportedOptions(
                          final Map<String,String> options,
                          final String mechanism)
          throws LDAPException
  {
    if (! options.isEmpty())
    {
      for (final String s : options.keySet())
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_UNSUPPORTED_FOR_MECH.get(s,mechanism));
      }
    }
  }


  static boolean getBooleanValue(final Map<String,String> m, final String o,
                                 final boolean d)
         throws LDAPException
  {
    final String s = toLowerCase(m.remove(toLowerCase(o)));
    if (s == null)
    {
      return d;
    }
    else if (s.equals("true") ||
             s.equals("t") ||
             s.equals("yes") ||
             s.equals("y") ||
             s.equals("on") ||
             s.equals("1"))
    {
      return true;
    }
    else if (s.equals("false") ||
             s.equals("f") ||
             s.equals("no") ||
             s.equals("n") ||
             s.equals("off") ||
             s.equals("0"))
    {
      return false;
    }
    else
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MALFORMED_BOOLEAN_VALUE.get(o));
    }
  }
}

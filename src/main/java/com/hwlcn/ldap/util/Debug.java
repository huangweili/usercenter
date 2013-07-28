package com.hwlcn.ldap.util;



import java.io.Serializable;
import java.util.EnumSet;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.ldap.ldap.sdk.DisconnectType;
import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.ldap.ldap.sdk.LDAPConnection;
import com.hwlcn.ldap.ldap.sdk.LDAPRequest;
import com.hwlcn.ldap.ldif.LDIFRecord;

import static com.hwlcn.ldap.util.StaticUtils.*;



/**
 * This class provides a means of enabling and configuring debugging in the LDAP
 * SDK.
 * <BR><BR>
 * Access to debug information can be enabled through applications that use the
 * SDK by calling the {@link com.hwlcn.ldap.util.Debug#setEnabled} methods, or it can also be
 * enabled without any code changes through the use of system properties.  In
 * particular, the {@link com.hwlcn.ldap.util.Debug#PROPERTY_DEBUG_ENABLED},
 * {@link com.hwlcn.ldap.util.Debug#PROPERTY_DEBUG_LEVEL}, and {@link com.hwlcn.ldap.util.Debug#PROPERTY_DEBUG_TYPE}
 * properties may be used to control debugging without the need to alter any
 * code within the application that uses the SDK.
 * <BR><BR>
 * The LDAP SDK debugging subsystem uses the Java logging framework available
 * through the {@code java.util.logging} package with a logger name of
 * "{@code com.hwlcn.ldap.ldap.sdk}".  The {@link com.hwlcn.ldap.util.Debug#getLogger} method may
 * be used to access the logger instance used by the LDAP SDK.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process that may be used to enable
 * debugging within the LDAP SDK and write information about all messages with
 * a {@code WARNING} level or higher to a file named "/tmp/test.log":
 * <PRE>
 *   Debug.setEnabled(true);
 *   Logger logger = Debug.getLogger();
 *
 *   FileHandler fileHandler = new FileHandler("/tmp/test.log");
 *   fileHandler.setLevel(Level.WARNING);
 *   logger.addHandler(fileHandler);
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Debug
       implements Serializable
{
  public static final String PROPERTY_DEBUG_ENABLED =
       "com.hwlcn.ldap.ldap.sdk.debug.enabled";



  public static final String PROPERTY_INCLUDE_STACK_TRACE =
       "com.hwlcn.ldap.ldap.sdk.debug.includeStackTrace";



  public static final String PROPERTY_DEBUG_LEVEL =
       "com.hwlcn.ldap.ldap.sdk.debug.level";



  public static final String PROPERTY_DEBUG_TYPE =
       "com.hwlcn.ldap.ldap.sdk.debug.type";



  public static final String LOGGER_NAME = "com.hwlcn.ldap.ldap.sdk";

  private static final Logger logger = Logger.getLogger(LOGGER_NAME);



  private static final long serialVersionUID = -6079754380415146030L;



  private static boolean debugEnabled;


  private static boolean includeStackTrace;

  private static EnumSet<DebugType> debugTypes;



  static
  {
    initialize(System.getProperties());
  }



  private Debug()
  {

  }

  public static void initialize()
  {
    includeStackTrace = false;
    debugEnabled      = false;
    debugTypes        = EnumSet.allOf(DebugType.class);

    logger.setLevel(Level.ALL);
  }



  public static void initialize(final Properties properties)
  {
    initialize();
    if ((properties == null) || properties.isEmpty())
    {

      return;
    }

    final String enabledProp = properties.getProperty(PROPERTY_DEBUG_ENABLED);
    if ((enabledProp != null) && (enabledProp.length() > 0))
    {
      if (enabledProp.equalsIgnoreCase("true"))
      {
        debugEnabled = true;
      }
      else if (enabledProp.equalsIgnoreCase("false"))
      {
        debugEnabled = false;
      }
      else
      {
        throw new IllegalArgumentException("Invalid value '" + enabledProp +
                                           "' for property " +
                                           PROPERTY_DEBUG_ENABLED +
                                           ".  The value must be either " +
                                           "'true' or 'false'.");
      }
    }

    final String stackProp =
         properties.getProperty(PROPERTY_INCLUDE_STACK_TRACE);
    if ((stackProp != null) && (stackProp.length() > 0))
    {
      if (stackProp.equalsIgnoreCase("true"))
      {
        includeStackTrace = true;
      }
      else if (stackProp.equalsIgnoreCase("false"))
      {
        includeStackTrace = false;
      }
      else
      {
        throw new IllegalArgumentException("Invalid value '" + stackProp +
                                           "' for property " +
                                           PROPERTY_INCLUDE_STACK_TRACE +
                                           ".  The value must be either " +
                                           "'true' or 'false'.");
      }
    }

    final String typesProp = properties.getProperty(PROPERTY_DEBUG_TYPE);
    if ((typesProp != null) && (typesProp.length() > 0))
    {
      debugTypes = EnumSet.noneOf(DebugType.class);
      final StringTokenizer t = new StringTokenizer(typesProp, ", ");
      while (t.hasMoreTokens())
      {
        final String debugTypeName = t.nextToken();
        final DebugType debugType = DebugType.forName(debugTypeName);
        if (debugType == null)
        {

          throw new IllegalArgumentException("Invalid value '" + debugTypeName +
                      "' for property " + PROPERTY_DEBUG_TYPE +
                      ".  Allowed values include:  " +
                      DebugType.getTypeNameList() + '.');
        }
        else
        {
          debugTypes.add(debugType);
        }
      }
    }

    final String levelProp = properties.getProperty(PROPERTY_DEBUG_LEVEL);
    if ((levelProp != null) && (levelProp.length() > 0))
    {
      logger.setLevel(Level.parse(levelProp));
    }
  }


  public static Logger getLogger()
  {
    return logger;
  }


  public static boolean debugEnabled()
  {
    return debugEnabled;
  }



  public static boolean debugEnabled(final DebugType debugType)
  {
    return (debugEnabled && debugTypes.contains(debugType));
  }


  public static void setEnabled(final boolean enabled)
  {
    debugTypes   = EnumSet.allOf(DebugType.class);
    debugEnabled = enabled;
  }


  public static void setEnabled(final boolean enabled,
                                final Set<DebugType> types)
  {
    if ((types == null) || types.isEmpty())
    {
      debugTypes = EnumSet.allOf(DebugType.class);
    }
    else
    {
      debugTypes = EnumSet.copyOf(types);
    }

    debugEnabled = enabled;
  }



  public static boolean includeStackTrace()
  {
    return includeStackTrace;
  }



  public static void setIncludeStackTrace(final boolean includeStackTrace)
  {
    Debug.includeStackTrace = includeStackTrace;
  }



  public static EnumSet<DebugType> getDebugTypes()
  {
    return debugTypes;
  }



  public static void debugException(final Throwable t)
  {
    if (debugEnabled && debugTypes.contains(DebugType.EXCEPTION))
    {
      debugException(Level.WARNING, t);
    }
  }

  public static void debugException(final Level l, final Throwable t)
  {
    if (debugEnabled && debugTypes.contains(DebugType.EXCEPTION))
    {
      final StringBuilder buffer = new StringBuilder();
      addCommonHeader(buffer, l);
      buffer.append("caughtException=\"");
      getStackTrace(t, buffer);
      buffer.append('"');

      logger.log(l, buffer.toString(), t);
    }
  }



  public static void debugConnect(final String h, final int p)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      debugConnect(Level.INFO, h, p, null);
    }
  }


  public static void debugConnect(final Level l, final String h, final int p)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      debugConnect(l, h, p, null);
    }
  }




  public static void debugConnect(final String h, final int p,
                                  final LDAPConnection c)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      debugConnect(Level.INFO, h, p, c);
    }
  }



  public static void debugConnect(final Level l, final String h, final int p,
                                  final LDAPConnection c)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      final StringBuilder buffer = new StringBuilder();
      addCommonHeader(buffer, l);
      buffer.append("connectedTo=\"");
      buffer.append(h);
      buffer.append(':');
      buffer.append(p);
      buffer.append('"');

      if (c != null)
      {
        buffer.append(" connectionID=");
        buffer.append(c.getConnectionID());

        final String connectionName = c.getConnectionName();
        if (connectionName != null)
        {
          buffer.append(" connectionName=\"");
          buffer.append(connectionName);
          buffer.append('"');
        }

        final String connectionPoolName = c.getConnectionPoolName();
        if (connectionPoolName != null)
        {
          buffer.append(" connectionPoolName=\"");
          buffer.append(connectionPoolName);
          buffer.append('"');
        }
      }

      logger.log(l, buffer.toString());
    }
  }



  public static void debugDisconnect(final String h, final int p,
                                     final DisconnectType t, final String m,
                                     final Throwable e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      debugDisconnect(Level.INFO, h, p, null, t, m, e);
    }
  }



  public static void debugDisconnect(final Level l, final String h, final int p,
                                     final DisconnectType t, final String m,
                                     final Throwable e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      debugDisconnect(l, h, p, null, t, m, e);
    }
  }


  public static void debugDisconnect(final String h, final int p,
                                     final LDAPConnection c,
                                     final DisconnectType t, final String m,
                                     final Throwable e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      debugDisconnect(Level.INFO, h, p, c, t, m, e);
    }
  }



  public static void debugDisconnect(final Level l, final String h, final int p,
                                     final LDAPConnection c,
                                     final DisconnectType t, final String m,
                                     final Throwable e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      final StringBuilder buffer = new StringBuilder();
      addCommonHeader(buffer, l);

      if (c != null)
      {
        buffer.append("connectionID=");
        buffer.append(c.getConnectionID());

        final String connectionName = c.getConnectionName();
        if (connectionName != null)
        {
          buffer.append(" connectionName=\"");
          buffer.append(connectionName);
          buffer.append('"');
        }

        final String connectionPoolName = c.getConnectionPoolName();
        if (connectionPoolName != null)
        {
          buffer.append(" connectionPoolName=\"");
          buffer.append(connectionPoolName);
          buffer.append('"');
        }

        buffer.append(' ');
      }

      buffer.append("disconnectedFrom=\"");
      buffer.append(h);
      buffer.append(':');
      buffer.append(p);
      buffer.append("\" disconnectType=\"");
      buffer.append(t.name());
      buffer.append('"');

      if (m != null)
      {
        buffer.append("\" disconnectMessage=\"");
        buffer.append(m);
        buffer.append('"');
      }

      if (e != null)
      {
        buffer.append("\" disconnectCause=\"");
        getStackTrace(e, buffer);
        buffer.append('"');
      }

      logger.log(l, buffer.toString(), c);
    }
  }



  public static void debugLDAPRequest(final LDAPRequest r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      debugLDAPRequest(Level.INFO, r, -1, null);
    }
  }


  public static void debugLDAPRequest(final Level l, final LDAPRequest r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      debugLDAPRequest(l, r, -1, null);
    }
  }



  public static void debugLDAPRequest(final LDAPRequest r, final int i,
                                      final LDAPConnection c)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      debugLDAPRequest(Level.INFO, r, i, c);
    }
  }



  public static void debugLDAPRequest(final Level l, final LDAPRequest r,
                                      final int i, final LDAPConnection c)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      final StringBuilder buffer = new StringBuilder();
      addCommonHeader(buffer, l);

      if (c != null)
      {
        buffer.append("connectionID=");
        buffer.append(c.getConnectionID());

        final String connectionName = c.getConnectionName();
        if (connectionName != null)
        {
          buffer.append(" connectionName=\"");
          buffer.append(connectionName);
          buffer.append('"');
        }

        final String connectionPoolName = c.getConnectionPoolName();
        if (connectionPoolName != null)
        {
          buffer.append(" connectionPoolName=\"");
          buffer.append(connectionPoolName);
          buffer.append('"');
        }

        buffer.append(" connectedTo=\"");
        buffer.append(c.getConnectedAddress());
        buffer.append(':');
        buffer.append(c.getConnectedPort());
        buffer.append("\" ");
      }

      if (i >= 0)
      {
        buffer.append(" messageID=");
        buffer.append(i);
        buffer.append(' ');
      }

      buffer.append("sendingLDAPRequest=\"");
      r.toString(buffer);
      buffer.append('"');

      logger.log(l,  buffer.toString());
    }
  }



  public static void debugLDAPResult(final LDAPResponse r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      debugLDAPResult(Level.INFO, r, null);
    }
  }



  public static void debugLDAPResult(final Level l, final LDAPResponse r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      debugLDAPResult(l, r, null);
    }
  }




  public static void debugLDAPResult(final LDAPResponse r,
                                     final LDAPConnection c)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      debugLDAPResult(Level.INFO, r, c);
    }
  }



  public static void debugLDAPResult(final Level l, final LDAPResponse r,
                                     final LDAPConnection c)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      final StringBuilder buffer = new StringBuilder();
      addCommonHeader(buffer, l);

      if (c != null)
      {
        buffer.append("connectionID=");
        buffer.append(c.getConnectionID());

        final String connectionName = c.getConnectionName();
        if (connectionName != null)
        {
          buffer.append(" connectionName=\"");
          buffer.append(connectionName);
          buffer.append('"');
        }

        final String connectionPoolName = c.getConnectionPoolName();
        if (connectionPoolName != null)
        {
          buffer.append(" connectionPoolName=\"");
          buffer.append(connectionPoolName);
          buffer.append('"');
        }

        buffer.append(" connectedTo=\"");
        buffer.append(c.getConnectedAddress());
        buffer.append(':');
        buffer.append(c.getConnectedPort());
        buffer.append("\" ");
      }

      buffer.append("readLDAPResult=\"");
      r.toString(buffer);
      buffer.append('"');

      logger.log(l,  buffer.toString());
    }
  }



  public static void debugASN1Write(final ASN1Element e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.ASN1))
    {
      debugASN1Write(Level.INFO, e);
    }
  }



  public static void debugASN1Write(final Level l, final ASN1Element e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.ASN1))
    {
      final StringBuilder buffer = new StringBuilder();
      addCommonHeader(buffer, l);
      buffer.append("writingASN1Element=\"");
      e.toString(buffer);
      buffer.append('"');

      logger.log(l, buffer.toString());
    }
  }



  public static void debugASN1Write(final ASN1Buffer b)
  {
    if (debugEnabled && debugTypes.contains(DebugType.ASN1))
    {
      debugASN1Write(Level.INFO, b);
    }
  }




  public static void debugASN1Write(final Level l, final ASN1Buffer b)
  {
    if (debugEnabled && debugTypes.contains(DebugType.ASN1))
    {
      final StringBuilder buffer = new StringBuilder();
      addCommonHeader(buffer, l);
      buffer.append("writingASN1Element=\"");
      toHex(b.toByteArray(), buffer);
      buffer.append('"');

      logger.log(l, buffer.toString());
    }
  }




  public static void debugASN1Read(final ASN1Element e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.ASN1))
    {
      debugASN1Read(Level.INFO, e);
    }
  }




  public static void debugASN1Read(final Level l, final ASN1Element e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.ASN1))
    {
      final StringBuilder buffer = new StringBuilder();
      addCommonHeader(buffer, l);
      buffer.append("readASN1Element=\"");
      e.toString(buffer);
      buffer.append('"');

      logger.log(l, buffer.toString());
    }
  }



  public static void debugLDIFWrite(final LDIFRecord r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDIF))
    {
      debugLDIFWrite(Level.INFO, r);
    }
  }



  public static void debugLDIFWrite(final Level l, final LDIFRecord r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDIF))
    {
      final StringBuilder buffer = new StringBuilder();
      addCommonHeader(buffer, l);
      buffer.append("writingLDIFRecord=\"");
      r.toString(buffer);
      buffer.append('"');

      logger.log(l, buffer.toString());
    }
  }



  public static void debugLDIFRead(final LDIFRecord r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDIF))
    {
      debugLDIFRead(Level.INFO, r);
    }
  }



  public static void debugLDIFRead(final Level l, final LDIFRecord r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDIF))
    {
      final StringBuilder buffer = new StringBuilder();
      addCommonHeader(buffer, l);
      buffer.append("readLDIFRecord=\"");
      r.toString(buffer);
      buffer.append('"');

      logger.log(l, buffer.toString());
    }
  }




  public static void debugMonitor(final Entry e, final String m)
  {
    if (debugEnabled && debugTypes.contains(DebugType.MONITOR))
    {
      debugMonitor(Level.FINE, e, m);
    }
  }



  public static void debugMonitor(final Level l, final Entry e, final String m)
  {
    if (debugEnabled && debugTypes.contains(DebugType.MONITOR))
    {
      final StringBuilder buffer = new StringBuilder();
      addCommonHeader(buffer, l);
      buffer.append("monitorEntryDN=\"");
      buffer.append(e.getDN());
      buffer.append("\" message=\"");
      buffer.append(m);
      buffer.append('"');

      logger.log(l, buffer.toString());
    }
  }




  public static void debugCodingError(final Throwable t)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CODING_ERROR))
    {
      final StringBuilder buffer = new StringBuilder();
      addCommonHeader(buffer, Level.SEVERE);
      buffer.append("codingError=\"");
      getStackTrace(t, buffer);
      buffer.append('"');

      logger.log(Level.SEVERE, buffer.toString());
    }
  }




  public static void debug(final Level l, final DebugType t, final String m)
  {
    if (debugEnabled && debugTypes.contains(t))
    {
      final StringBuilder buffer = new StringBuilder();
      addCommonHeader(buffer, l);
      buffer.append("message=\"");
      buffer.append(m);
      buffer.append('"');

      logger.log(l, buffer.toString());
    }
  }



  public static void debug(final Level l, final DebugType t, final String m,
                           final Throwable e)
  {
    if (debugEnabled && debugTypes.contains(t))
    {
      final StringBuilder buffer = new StringBuilder();
      addCommonHeader(buffer, l);
      buffer.append("message=\"");
      buffer.append(m);
      buffer.append('"');
      buffer.append(" exception=\"");
      getStackTrace(e, buffer);
      buffer.append('"');

      logger.log(l, buffer.toString(), e);
    }
  }



  private static void addCommonHeader(final StringBuilder buffer,
                                      final Level level)
  {
    buffer.append("level=\"");
    buffer.append(level.getName());
    buffer.append("\" threadID=");
    buffer.append(Thread.currentThread().getId());
    buffer.append(" threadName=\"");
    buffer.append(Thread.currentThread().getName());

    if (includeStackTrace)
    {
      buffer.append("\" calledFrom=\"");

      boolean appended   = false;
      boolean foundDebug = false;
      for (final StackTraceElement e : Thread.currentThread().getStackTrace())
      {
        final String className = e.getClassName();
        if (className.equals(Debug.class.getName()))
        {
          foundDebug = true;
        }
        else if (foundDebug)
        {
          if (appended)
          {
            buffer.append(" / ");
          }
          appended = true;

          buffer.append(e.getMethodName());
          buffer.append('(');
          buffer.append(e.getFileName());

          final int lineNumber = e.getLineNumber();
          if (lineNumber > 0)
          {
            buffer.append(':');
            buffer.append(lineNumber);
          }
          else if (e.isNativeMethod())
          {
            buffer.append(":native");
          }

          buffer.append(')');
        }
      }
    }

    buffer.append("\" revision=");
    buffer.append(' ');
  }
}

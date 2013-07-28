package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;



/**
 * This class provides a data structure for representing the directory server
 * root DSE.  This entry provides information about the capabilities of the
 * directory server, server vendor and version information, and published naming
 * contexts.
 * <BR><BR>
 * Note a root DSE object instance represents a read-only version of an entry,
 * so all read operations allowed for an entry will succeed, but all write
 * attempts will be rejected.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for retrieving the root DSE
 * of a directory server and using it to determine whether it supports the
 * {@link com.hwlcn.ldap.ldap.sdk.controls.ServerSideSortRequestControl}:
 * <PRE>
 *   RootDSE rootDSE = connection.getRootDSE();
 *   if (rootDSE.supportsControl(
 *            ServerSideSortRequestControl.SERVER_SIDE_SORT_REQUEST_OID))
 *   {
 *     System.out.println("The directory server supports the use of the " +
 *                        "server-side sort request control.");
 *   }
 *   else
 *   {
 *     System.out.println("The directory server does not support the use of " +
 *                        "the server-side sort request control.");
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RootDSE
       extends ReadOnlyEntry
{
  public static final String ATTR_ALT_SERVER = "altServer";

  public static final String ATTR_CHANGELOG_DN = "changelog";

  public static final String ATTR_FIRST_CHANGE_NUMBER = "firstChangeNumber";

  public static final String ATTR_LAST_CHANGE_NUMBER = "lastChangeNumber";

  public static final String ATTR_LAST_PURGED_CHANGE_NUMBER =
       "lastPurgedChangeNumber";


  public static final String ATTR_NAMING_CONTEXT = "namingContexts";


  public static final String ATTR_SUBSCHEMA_SUBENTRY = "subschemaSubentry";



  public static final String ATTR_SUPPORTED_AUTH_PASSWORD_STORAGE_SCHEME =
       "supportedAuthPasswordSchemes";


  public static final String ATTR_SUPPORTED_CONTROL = "supportedControl";



  public static final String ATTR_SUPPORTED_EXTENDED_OPERATION =
       "supportedExtension";




  public static final String ATTR_SUPPORTED_FEATURE =
       "supportedFeatures";



  public static final String ATTR_SUPPORTED_LDAP_VERSION =
       "supportedLDAPVersion";





  public static final String ATTR_SUPPORTED_SASL_MECHANISM =
       "supportedSASLMechanisms";



  public static final String ATTR_VENDOR_NAME = "vendorName";


  public static final String ATTR_VENDOR_VERSION = "vendorVersion";


  private static final String[] REQUEST_ATTRS =
  {
    "*",
    "+",
    ATTR_ALT_SERVER,
    ATTR_CHANGELOG_DN,
    ATTR_FIRST_CHANGE_NUMBER,
    ATTR_LAST_CHANGE_NUMBER,
    ATTR_LAST_PURGED_CHANGE_NUMBER,
    ATTR_NAMING_CONTEXT,
    ATTR_SUBSCHEMA_SUBENTRY,
    ATTR_SUPPORTED_AUTH_PASSWORD_STORAGE_SCHEME,
    ATTR_SUPPORTED_CONTROL,
    ATTR_SUPPORTED_EXTENDED_OPERATION,
    ATTR_SUPPORTED_FEATURE,
    ATTR_SUPPORTED_LDAP_VERSION,
    ATTR_SUPPORTED_SASL_MECHANISM,
    ATTR_VENDOR_NAME,
    ATTR_VENDOR_VERSION,
  };

  private static final long serialVersionUID = -1678182563511570981L;



  public RootDSE(final Entry rootDSEEntry)
  {
    super(rootDSEEntry);
  }


  public static RootDSE getRootDSE(final LDAPInterface connection)
         throws LDAPException
  {
    final Entry rootDSEEntry = connection.getEntry("", REQUEST_ATTRS);
    if (rootDSEEntry == null)
    {
      return null;
    }

    return new RootDSE(rootDSEEntry);
  }


  public String[] getAltServerURIs()
  {
    return getAttributeValues(ATTR_ALT_SERVER);
  }




  public String getChangelogDN()
  {
    return getAttributeValue(ATTR_CHANGELOG_DN);
  }



  public Long getFirstChangeNumber()
  {
    return getAttributeValueAsLong(ATTR_FIRST_CHANGE_NUMBER);
  }



  public Long getLastChangeNumber()
  {
    return getAttributeValueAsLong(ATTR_LAST_CHANGE_NUMBER);
  }



  public Long getLastPurgedChangeNumber()
  {
    return getAttributeValueAsLong(ATTR_LAST_PURGED_CHANGE_NUMBER);
  }




  public String[] getNamingContextDNs()
  {
    return getAttributeValues(ATTR_NAMING_CONTEXT);
  }



  public String getSubschemaSubentryDN()
  {
    return getAttributeValue(ATTR_SUBSCHEMA_SUBENTRY);
  }



  public String[] getSupportedAuthPasswordSchemeNames()
  {
    return getAttributeValues(ATTR_SUPPORTED_AUTH_PASSWORD_STORAGE_SCHEME);
  }



  public boolean supportsAuthPasswordScheme(final String scheme)
  {
    return hasAttributeValue(ATTR_SUPPORTED_AUTH_PASSWORD_STORAGE_SCHEME,
                             scheme);
  }



  public String[] getSupportedControlOIDs()
  {
    return getAttributeValues(ATTR_SUPPORTED_CONTROL);
  }

  public boolean supportsControl(final String controlOID)
  {
    return hasAttributeValue(ATTR_SUPPORTED_CONTROL, controlOID);
  }



  public String[] getSupportedExtendedOperationOIDs()
  {
    return getAttributeValues(ATTR_SUPPORTED_EXTENDED_OPERATION);
  }




  public boolean supportsExtendedOperation(final String extendedOperationOID)
  {
    return hasAttributeValue(ATTR_SUPPORTED_EXTENDED_OPERATION,
                             extendedOperationOID);
  }



  public String[] getSupportedFeatureOIDs()
  {
    return getAttributeValues(ATTR_SUPPORTED_FEATURE);
  }



  public boolean supportsFeature(final String featureOID)
  {
    return hasAttributeValue(ATTR_SUPPORTED_FEATURE, featureOID);
  }


  public int[] getSupportedLDAPVersions()
  {
    final String[] versionStrs =
         getAttributeValues(ATTR_SUPPORTED_LDAP_VERSION);
    if (versionStrs == null)
    {
      return null;
    }

    final int[] versions = new int[versionStrs.length];
    for (int i=0; i < versionStrs.length; i++)
    {
      try
      {
        versions[i] = Integer.parseInt(versionStrs[i]);
      }
      catch (final Exception e)
      {
        debugException(e);
        return null;
      }
    }

    return versions;
  }


  public boolean supportsLDAPVersion(final int ldapVersion)
  {
    return hasAttributeValue(ATTR_SUPPORTED_LDAP_VERSION,
                             String.valueOf(ldapVersion));
  }



  public String[] getSupportedSASLMechanismNames()
  {
    return getAttributeValues(ATTR_SUPPORTED_SASL_MECHANISM);
  }


  public boolean supportsSASLMechanism(final String mechanismName)
  {
    return hasAttributeValue(ATTR_SUPPORTED_SASL_MECHANISM, mechanismName);
  }




  public String getVendorName()
  {
    return getAttributeValue(ATTR_VENDOR_NAME);
  }



  public String getVendorVersion()
  {
    return getAttributeValue(ATTR_VENDOR_VERSION);
  }
}

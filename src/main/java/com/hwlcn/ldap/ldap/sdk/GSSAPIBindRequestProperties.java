package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.Validator;


@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class GSSAPIBindRequestProperties
       implements Serializable
{
  private static final long serialVersionUID = -8177334654843710502L;



  private ASN1OctetString password;

  private boolean enableGSSAPIDebugging;
  private boolean renewTGT;

  private boolean requireCachedCredentials;
  private boolean useTicketCache;

  private String authenticationID;

  private String authorizationID;

  private String configFilePath;

  private String kdcAddress;

  private String realm;

  private String servicePrincipalProtocol;

  private String ticketCachePath;



  public GSSAPIBindRequestProperties(final String authenticationID,
                                     final String password)
  {
    this(authenticationID, null,
         (password == null ? null : new ASN1OctetString(password)), null, null,
         null);
  }




  public GSSAPIBindRequestProperties(final String authenticationID,
                                     final byte[] password)
  {
    this(authenticationID, null,
         (password == null ? null : new ASN1OctetString(password)), null, null,
         null);
  }




  GSSAPIBindRequestProperties(final String authenticationID,
                              final String authorizationID,
                              final ASN1OctetString password,
                              final String realm,
                              final String kdcAddress,
                              final String configFilePath)
  {
    this.authenticationID = authenticationID;
    this.authorizationID  = authorizationID;
    this.password         = password;
    this.realm            = realm;
    this.kdcAddress       = kdcAddress;
    this.configFilePath   = configFilePath;

    servicePrincipalProtocol = "ldap";
    enableGSSAPIDebugging    = false;
    renewTGT                 = false;
    useTicketCache           = true;
    requireCachedCredentials = false;
    ticketCachePath          = null;
  }



  public String getAuthenticationID()
  {
    return authenticationID;
  }



  public void setAuthenticationID(final String authenticationID)
  {
    this.authenticationID = authenticationID;
  }



  public String getAuthorizationID()
  {
    return authorizationID;
  }



  public void setAuthorizationID(final String authorizationID)
  {
    this.authorizationID = authorizationID;
  }


  public ASN1OctetString getPassword()
  {
    return password;
  }


  public void setPassword(final String password)
  {
    if (password == null)
    {
      this.password = null;
    }
    else
    {
      this.password = new ASN1OctetString(password);
    }
  }



  public void setPassword(final byte[] password)
  {
    if (password == null)
    {
      this.password = null;
    }
    else
    {
      this.password = new ASN1OctetString(password);
    }
  }



  public void setPassword(final ASN1OctetString password)
  {
    this.password = password;
  }


  public String getRealm()
  {
    return realm;
  }


  public void setRealm(final String realm)
  {
    this.realm = realm;
  }


  public String getKDCAddress()
  {
    return kdcAddress;
  }


  public void setKDCAddress(final String kdcAddress)
  {
    this.kdcAddress = kdcAddress;
  }




  public String getConfigFilePath()
  {
    return configFilePath;
  }


  public void setConfigFilePath(final String configFilePath)
  {
    this.configFilePath = configFilePath;
  }




  public String getServicePrincipalProtocol()
  {
    return servicePrincipalProtocol;
  }




  public void setServicePrincipalProtocol(final String servicePrincipalProtocol)
  {
    Validator.ensureNotNull(servicePrincipalProtocol);

    this.servicePrincipalProtocol = servicePrincipalProtocol;
  }



  public boolean useTicketCache()
  {
    return useTicketCache;
  }



  public void setUseTicketCache(final boolean useTicketCache)
  {
    this.useTicketCache = useTicketCache;
  }


  public boolean requireCachedCredentials()
  {
    return requireCachedCredentials;
  }



  public void setRequireCachedCredentials(
                   final boolean requireCachedCredentials)
  {
    this.requireCachedCredentials = requireCachedCredentials;
  }



  public String getTicketCachePath()
  {
    return ticketCachePath;
  }


  public void setTicketCachePath(final String ticketCachePath)
  {
    this.ticketCachePath = ticketCachePath;
  }



  public boolean renewTGT()
  {
    return renewTGT;
  }



  public void setRenewTGT(final boolean renewTGT)
  {
    this.renewTGT = renewTGT;
  }




  public boolean enableGSSAPIDebugging()
  {
    return enableGSSAPIDebugging;
  }



  public void setEnableGSSAPIDebugging(final boolean enableGSSAPIDebugging)
  {
    this.enableGSSAPIDebugging = enableGSSAPIDebugging;
  }


  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }


  public void toString(final StringBuilder buffer)
  {
    buffer.append("GSSAPIBindRequestProperties(");
    if (authenticationID != null)
    {
      buffer.append("authenticationID='");
      buffer.append(authenticationID);
      buffer.append("', ");
    }

    if (authorizationID != null)
    {
      buffer.append("authorizationID='");
      buffer.append(authorizationID);
      buffer.append("', ");
    }

    if (realm != null)
    {
      buffer.append("realm='");
      buffer.append(realm);
      buffer.append("', ");
    }

    if (kdcAddress != null)
    {
      buffer.append("kdcAddress='");
      buffer.append(kdcAddress);
      buffer.append("', ");
    }

    if (useTicketCache)
    {
      buffer.append("useTicketCache=true, requireCachedCredentials=");
      buffer.append(requireCachedCredentials);
      buffer.append(", renewTGT=");
      buffer.append(renewTGT);
      buffer.append(", ");

      if (ticketCachePath != null)
      {
        buffer.append("ticketCachePath='");
        buffer.append(ticketCachePath);
        buffer.append("', ");
      }
    }
    else
    {
      buffer.append("useTicketCache=false, ");
    }

    if (configFilePath != null)
    {
      buffer.append("configFilePath='");
      buffer.append(configFilePath);
      buffer.append("', ");
    }

    buffer.append("servicePrincipalProtocol='");
    buffer.append(servicePrincipalProtocol);
    buffer.append("', enableGSSAPIDebugging=");
    buffer.append(enableGSSAPIDebugging);
    buffer.append(')');
  }
}

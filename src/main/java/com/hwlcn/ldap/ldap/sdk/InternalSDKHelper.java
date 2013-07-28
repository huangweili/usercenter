package com.hwlcn.ldap.ldap.sdk;



import javax.net.ssl.SSLContext;

import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.protocol.LDAPMessage;
import com.hwlcn.ldap.ldap.sdk.extensions.CancelExtendedRequest;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class InternalSDKHelper
{

  private InternalSDKHelper()
  {

  }




  @InternalUseOnly()
  public static void setSoTimeout(final LDAPConnection connection,
                                  final int soTimeout)
         throws LDAPException
  {
    final LDAPConnectionReader connectionReader =
         connection.getConnectionInternals(true).getConnectionReader();
    if (connectionReader != null)
    {
      connectionReader.setSoTimeout(soTimeout);
    }
  }




  @InternalUseOnly()
  public static void convertToTLS(final LDAPConnection connection,
                                  final SSLContext sslContext)
         throws LDAPException
  {
    connection.convertToTLS(sslContext);
  }




  @InternalUseOnly()
  public static AsyncRequestID createAsyncRequestID(final int targetMessageID,
                                    final LDAPConnection connection)
  {
    return new AsyncRequestID(targetMessageID, connection);
  }



  @InternalUseOnly()
  public static void cancel(final LDAPConnection connection,
                            final int targetMessageID,
                            final Control... controls)
         throws LDAPException
  {
    final CancelExtendedRequest cancelRequest =
         new CancelExtendedRequest(targetMessageID);
    connection.sendMessage(new LDAPMessage(connection.nextMessageID(),
         new ExtendedRequest(cancelRequest), controls));
  }




  @InternalUseOnly()
  public static LDAPResult readLDAPResultFrom(final int messageID,
                                final ASN1StreamReaderSequence messageSequence,
                                final ASN1StreamReader reader)
         throws LDAPException
  {
    return LDAPResult.readLDAPResultFrom(messageID, messageSequence, reader);
  }



  @InternalUseOnly()
  public static BindResult readBindResultFrom(final int messageID,
                                final ASN1StreamReaderSequence messageSequence,
                                final ASN1StreamReader reader)
         throws LDAPException
  {
    return BindResult.readBindResultFrom(messageID, messageSequence, reader);
  }



  @InternalUseOnly()
  public static CompareResult readCompareResultFrom(final int messageID,
                     final ASN1StreamReaderSequence messageSequence,
                     final ASN1StreamReader reader)
         throws LDAPException
  {
    return CompareResult.readCompareResultFrom(messageID, messageSequence,
                                               reader);
  }




  @InternalUseOnly()
  public static ExtendedResult readExtendedResultFrom(final int messageID,
                     final ASN1StreamReaderSequence messageSequence,
                     final ASN1StreamReader reader)
         throws LDAPException
  {
    return ExtendedResult.readExtendedResultFrom(messageID, messageSequence,
                                                 reader);
  }



  @InternalUseOnly()
  public static SearchResultEntry readSearchResultEntryFrom(final int messageID,
                     final ASN1StreamReaderSequence messageSequence,
                     final ASN1StreamReader reader, final Schema schema)
         throws LDAPException
  {
    return SearchResultEntry.readSearchEntryFrom(messageID, messageSequence,
                                                 reader, schema);
  }



  @InternalUseOnly()
  public static SearchResultReference readSearchResultReferenceFrom(
                     final int messageID,
                     final ASN1StreamReaderSequence messageSequence,
                     final ASN1StreamReader reader)
         throws LDAPException
  {
    return SearchResultReference.readSearchReferenceFrom(messageID,
                messageSequence, reader);
  }



  @InternalUseOnly()
  public static SearchResult readSearchResultFrom(final int messageID,
                     final ASN1StreamReaderSequence messageSequence,
                     final ASN1StreamReader reader)
         throws LDAPException
  {
    return SearchResult.readSearchResultFrom(messageID, messageSequence,
                                             reader);
  }



  @InternalUseOnly()
  public static IntermediateResponse readIntermediateResponseFrom(
                     final int messageID,
                     final ASN1StreamReaderSequence messageSequence,
                     final ASN1StreamReader reader)
         throws LDAPException
  {
    return IntermediateResponse.readFrom(messageID, messageSequence, reader);
  }



  @InternalUseOnly()
  public static Boolean followReferralsInternal(final LDAPRequest request)
  {
    return request.followReferralsInternal();
  }




  @InternalUseOnly()
  public static int nextMessageID(final LDAPConnection connection)
  {
    return connection.nextMessageID();
  }



  @InternalUseOnly()
  public static BindRequest getLastBindRequest(final LDAPConnection connection)
  {
    return connection.getLastBindRequest();
  }
}

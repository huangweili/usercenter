/*
 * Copyright 2007-2013 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2013 UnboundID Corp.
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
package com.hwlcn.ldap.ldap.sdk;



import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides a data structure for representing an LDAP search result
 * entry.  This is a {@link com.hwlcn.ldap.ldap.sdk.ReadOnlyEntry} object that may also include zero
 * or more controls included with the entry returned from the server.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchResultEntry
       extends ReadOnlyEntry
       implements LDAPResponse
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -290721544252526163L;



  // The set of controls returned with this search result entry.
  private final Control[] controls;

  // The message ID for the LDAP message containing this response.
  private final int messageID;



  /**
   * Creates a new search result entry with the provided information.
   *
   * @param  dn          The DN for this search result entry.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in this search result
   *                     entry.  It must not be {@code null}.
   * @param  controls    The set of controls for this search result entry.  It
   *                     must not be {@code null}.
   */
  public SearchResultEntry(final String dn, final Attribute[] attributes,
                           final Control... controls)
  {
    this(-1, dn, null, attributes, controls);
  }



  /**
   * Creates a new search result entry with the provided information.
   *
   * @param  messageID   The message ID for the LDAP message containing this
   *                     response.
   * @param  dn          The DN for this search result entry.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in this search result
   *                     entry.  It must not be {@code null}.
   * @param  controls    The set of controls for this search result entry.  It
   *                     must not be {@code null}.
   */
  public SearchResultEntry(final int messageID, final String dn,
                           final Attribute[] attributes,
                           final Control... controls)
  {
    this(messageID, dn, null, attributes, controls);
  }



  /**
   * Creates a new search result entry with the provided information.
   *
   * @param  messageID   The message ID for the LDAP message containing this
   *                     response.
   * @param  dn          The DN for this search result entry.  It must not be
   *                     {@code null}.
   * @param  schema      The schema to use for operations involving this entry.
   *                     It may be {@code null} if no schema is available.
   * @param  attributes  The set of attributes to include in this search result
   *                     entry.  It must not be {@code null}.
   * @param  controls    The set of controls for this search result entry.  It
   *                     must not be {@code null}.
   */
  public SearchResultEntry(final int messageID, final String dn,
                           final Schema schema, final Attribute[] attributes,
                           final Control... controls)
  {
    super(dn, schema, attributes);

    ensureNotNull(controls);

    this.messageID = messageID;
    this.controls  = controls;
  }



  /**
   * Creates a new search result entry with the provided information.
   *
   * @param  dn          The DN for this search result entry.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in this search result
   *                     entry.  It must not be {@code null}.
   * @param  controls    The set of controls for this search result entry.  It
   *                     must not be {@code null}.
   */
  public SearchResultEntry(final String dn,
                           final Collection<Attribute> attributes,
                           final Control... controls)
  {
    this(-1, dn, null, attributes, controls);
  }



  /**
   * Creates a new search result entry with the provided information.
   *
   * @param  messageID   The message ID for the LDAP message containing this
   *                     response.
   * @param  dn          The DN for this search result entry.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in this search result
   *                     entry.  It must not be {@code null}.
   * @param  controls    The set of controls for this search result entry.  It
   *                     must not be {@code null}.
   */
  public SearchResultEntry(final int messageID, final String dn,
                           final Collection<Attribute> attributes,
                           final Control... controls)
  {
    this(messageID, dn, null, attributes, controls);
  }



  /**
   * Creates a new search result entry with the provided information.
   *
   * @param  messageID   The message ID for the LDAP message containing this
   *                     response.
   * @param  dn          The DN for this search result entry.  It must not be
   *                     {@code null}.
   * @param  schema      The schema to use for operations involving this entry.
   *                     It may be {@code null} if no schema is available.
   * @param  attributes  The set of attributes to include in this search result
   *                     entry.  It must not be {@code null}.
   * @param  controls    The set of controls for this search result entry.  It
   *                     must not be {@code null}.
   */
  public SearchResultEntry(final int messageID, final String dn,
                           final Schema schema,
                           final Collection<Attribute> attributes,
                           final Control... controls)
  {
    super(dn, schema, attributes);

    ensureNotNull(controls);

    this.messageID = messageID;
    this.controls  = controls;
  }



  /**
   * Creates a new search result entry from the provided entry.
   *
   * @param  entry     The entry to use to create this search result entry.  It
   *                   must not be {@code null}.
   * @param  controls  The set of controls for this search result entry.  It
   *                   must not be {@code null}.
   */
  public SearchResultEntry(final Entry entry, final Control... controls)
  {
    this(-1, entry, controls);
  }



  /**
   * Creates a new search result entry from the provided entry.
   *
   * @param  messageID  The message ID for the LDAP message containing this
   *                    response.
   * @param  entry      The entry to use to create this search result entry.  It
   *                    must not be {@code null}.
   * @param  controls   The set of controls for this search result entry.  It
   *                    must not be {@code null}.
   */
  public SearchResultEntry(final int messageID, final Entry entry,
                           final Control... controls)
  {
    super(entry);

    ensureNotNull(controls);

    this.messageID = messageID;
    this.controls  = controls;
  }



  /**
   * Creates a new search result entry object with the protocol op and controls
   * read from the given ASN.1 stream reader.
   *
   * @param  messageID        The message ID for the LDAP message containing
   *                          this response.
   * @param  messageSequence  The ASN.1 stream reader sequence used in the
   *                          course of reading the LDAP message elements.
   * @param  reader           The ASN.1 stream reader from which to read the
   *                          protocol op and controls.
   * @param  schema           The schema to use to select the appropriate
   *                          matching rule to use for each attribute.  It may
   *                          be {@code null} if the default matching rule
   *                          should always be used.
   *
   * @return  The decoded search result entry object.
   *
   * @throws  com.hwlcn.ldap.ldap.sdk.LDAPException  If a problem occurs while reading or decoding data
   *                         from the ASN.1 stream reader.
   */
  static SearchResultEntry readSearchEntryFrom(final int messageID,
              final ASN1StreamReaderSequence messageSequence,
              final ASN1StreamReader reader, final Schema schema)
         throws LDAPException
  {
    try
    {
      reader.beginSequence();
      final String dn = reader.readString();

      final ArrayList<Attribute> attrList = new ArrayList<Attribute>(10);
      final ASN1StreamReaderSequence attrSequence = reader.beginSequence();
      while (attrSequence.hasMoreElements())
      {
        attrList.add(Attribute.readFrom(reader, schema));
      }

      Control[] controls = NO_CONTROLS;
      if (messageSequence.hasMoreElements())
      {
        final ArrayList<Control> controlList = new ArrayList<Control>(5);
        final ASN1StreamReaderSequence controlSequence = reader.beginSequence();
        while (controlSequence.hasMoreElements())
        {
          controlList.add(Control.readFrom(reader));
        }

        controls = new Control[controlList.size()];
        controlList.toArray(controls);
      }

      return new SearchResultEntry(messageID, dn, schema, attrList, controls);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SEARCH_ENTRY_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  /**
   * {@inheritDoc}
   */
  public int getMessageID()
  {
    return messageID;
  }



  /**
   * Retrieves the set of controls returned with this search result entry.
   * Individual response controls of a specific type may be retrieved and
   * decoded using the {@code get} method in the response control class.
   *
   * @return  The set of controls returned with this search result entry.
   */
  public Control[] getControls()
  {
    return controls;
  }



  /**
   * Retrieves the control with the specified OID.  If there is more than one
   * control with the given OID, then the first will be returned.
   *
   * @param  oid  The OID of the control to retrieve.
   *
   * @return  The control with the requested OID, or {@code null} if there is no
   *          such control for this search result entry.
   */
  public Control getControl(final String oid)
  {
    for (final Control c : controls)
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    return null;
  }



  /**
   * Generates a hash code for this entry.
   *
   * @return  The generated hash code for this entry.
   */
  @Override()
  public int hashCode()
  {
    int hashCode = super.hashCode();

    for (final Control c : controls)
    {
      hashCode += c.hashCode();
    }

    return hashCode;
  }



  /**
   * Indicates whether the provided object is equal to this entry.  The provided
   * object will only be considered equal to this entry if it is an entry with
   * the same DN and set of attributes.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is considered equal to this
   *          entry, or {@code false} if not.
   */
  @Override()
  public boolean equals(final Object o)
  {
    if (! super.equals(o))
    {
      return false;
    }

    if (! (o instanceof SearchResultEntry))
    {
      return false;
    }

    final SearchResultEntry e = (SearchResultEntry) o;

    if (controls.length != e.controls.length)
    {
      return false;
    }

    for (int i=0; i < controls.length; i++)
    {
      if (! controls[i].equals(e.controls[i]))
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Appends a string representation of this entry to the provided buffer.
   *
   * @param  buffer  The buffer to which to append the string representation of
   *                 this entry.
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("SearchResultEntry(dn='");
    buffer.append(getDN());
    buffer.append('\'');

    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    buffer.append(", attributes={");

    final Iterator<Attribute> iterator = getAttributes().iterator();

    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("}, controls={");

    for (int i=0; i < controls.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      controls[i].toString(buffer);
    }

    buffer.append("})");
  }
}

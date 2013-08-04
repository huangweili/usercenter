package com.hwlcn.ldap.ldif;



import com.hwlcn.ldap.ldap.sdk.ChangeType;
import com.hwlcn.ldap.ldap.sdk.DN;
import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.LDAPInterface;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.ldap.util.ByteStringBuffer;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides a base class for LDIF change records, which can be used
 * to represent add, delete, modify, and modify DN operations in LDIF form.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example iterates through all of the change records contained in
 * an LDIF file and attempts to apply those changes to a directory server:
 * <PRE>
 *   LDIFReader ldifReader = new LDIFReader(pathToLDIFFile);
 *
 *   while (true)
 *   {
 *     LDIFChangeRecord changeRecord;
 *     try
 *     {
 *       changeRecord = ldifReader.readChangeRecord();
 *       if (changeRecord == null)
 *       {
 *         System.err.println("All changes have been processed.");
 *         break;
 *       }
 *     }
 *     catch (LDIFException le)
 *     {
 *       if (le.mayContinueReading())
 *       {
 *         System.err.println("A recoverable occurred while attempting to " +
 *              "read a change record at or near line number " +
 *              le.getLineNumber() + ":  " + le.getMessage());
 *         System.err.println("The change record will be skipped.");
 *         continue;
 *       }
 *       else
 *       {
 *         System.err.println("An unrecoverable occurred while attempting to " +
 *              "read a change record at or near line number " +
 *              le.getLineNumber() + ":  " + le.getMessage());
 *         System.err.println("LDIF processing will be aborted.");
 *         break;
 *       }
 *     }
 *     catch (IOException ioe)
 *     {
 *       System.err.println("An I/O error occurred while attempting to read " +
 *            "from the LDIF file:  " + ioe.getMessage());
 *       System.err.println("LDIF processing will be aborted.");
 *       break;
 *     }
 *
 *     try
 *     {
 *       LDAPResult result = changeRecord.processChange(connection);
 *       System.out.println(changeRecord.getChangeType().getName() +
 *            " successful for entry " + changeRecord.getDN());
 *     }
 *     catch (LDAPException le)
 *     {
 *       System.err.println(changeRecord.getChangeType().getName() +
 *            " failed for entry " + changeRecord.getDN() + " -- " +
 *            le.getMessage());
 *     }
 *   }
 *
 *   ldifReader.close();
 * </PRE>
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class LDIFChangeRecord
       implements LDIFRecord
{

  private static final long serialVersionUID = 2394617613961232499L;

  private volatile DN parsedDN;

  private final String dn;

  protected LDIFChangeRecord(final String dn)
  {
    ensureNotNull(dn);

    this.dn = dn;
  }

  public final String getDN()
  {
    return dn;
  }

  public final DN getParsedDN()
         throws LDAPException
  {
    if (parsedDN == null)
    {
      parsedDN = new DN(dn);
    }

    return parsedDN;
  }

  public abstract ChangeType getChangeType();


  public abstract LDAPResult processChange(final LDAPInterface connection)
         throws LDAPException;


  final Entry toEntry()
        throws LDIFException
  {
    return new Entry(toLDIF());
  }


  public final String[] toLDIF()
  {
    return toLDIF(0);
  }

  public abstract String[] toLDIF(final int wrapColumn);


  public final void toLDIF(final ByteStringBuffer buffer)
  {
    toLDIF(buffer, 0);
  }


  public abstract void toLDIF(final ByteStringBuffer buffer,
                              final int wrapColumn);

  public final String toLDIFString()
  {
    final StringBuilder buffer = new StringBuilder();
    toLDIFString(buffer, 0);
    return buffer.toString();
  }

  public final String toLDIFString(final int wrapColumn)
  {
    final StringBuilder buffer = new StringBuilder();
    toLDIFString(buffer, wrapColumn);
    return buffer.toString();
  }


  public final void toLDIFString(final StringBuilder buffer)
  {
    toLDIFString(buffer, 0);
  }

  public abstract void toLDIFString(final StringBuilder buffer,
                                    final int wrapColumn);

  @Override()
  public abstract int hashCode();

  @Override()
  public abstract boolean equals(final Object o);


  @Override()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }

  public abstract void toString(final StringBuilder buffer);
}

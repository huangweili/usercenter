package com.hwlcn.ldap.ldap.sdk;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;

import com.hwlcn.ldap.ldif.LDIFAddChangeRecord;
import com.hwlcn.ldap.ldif.LDIFChangeRecord;
import com.hwlcn.ldap.ldif.LDIFDeleteChangeRecord;
import com.hwlcn.ldap.ldif.LDIFException;
import com.hwlcn.ldap.ldif.LDIFModifyChangeRecord;
import com.hwlcn.ldap.ldif.LDIFModifyDNChangeRecord;
import com.hwlcn.ldap.ldif.LDIFReader;
import com.hwlcn.ldap.ldap.matchingrules.BooleanMatchingRule;
import com.hwlcn.ldap.ldap.matchingrules.DistinguishedNameMatchingRule;
import com.hwlcn.ldap.ldap.matchingrules.IntegerMatchingRule;
import com.hwlcn.ldap.ldap.matchingrules.OctetStringMatchingRule;
import com.hwlcn.ldap.util.Debug;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.StaticUtils.*;



@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class ChangeLogEntry
       extends ReadOnlyEntry
{

  public static final String ATTR_CHANGE_NUMBER = "changeNumber";

  public static final String ATTR_TARGET_DN = "targetDN";

  public static final String ATTR_CHANGE_TYPE = "changeType";

  public static final String ATTR_CHANGES = "changes";

  public static final String ATTR_NEW_RDN = "newRDN";


  public static final String ATTR_DELETE_OLD_RDN = "deleteOldRDN";

  public static final String ATTR_NEW_SUPERIOR = "newSuperior";


  public static final String ATTR_DELETED_ENTRY_ATTRS = "deletedEntryAttrs";


  private static final long serialVersionUID = -4018129098468341663L;

  private final boolean deleteOldRDN;

  private final ChangeType changeType;

  private final List<Attribute> attributes;

  private final List<Modification> modifications;

  private final long changeNumber;

  private final String newRDN;

  private final String newSuperior;

  private final String targetDN;

  public ChangeLogEntry(final Entry entry)
         throws LDAPException
  {
    super(entry);


    final Attribute changeNumberAttr = entry.getAttribute(ATTR_CHANGE_NUMBER);
    if ((changeNumberAttr == null) || (! changeNumberAttr.hasValue()))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CHANGELOG_NO_CHANGE_NUMBER.get());
    }

    try
    {
      changeNumber = Long.parseLong(changeNumberAttr.getValue());
    }
    catch (NumberFormatException nfe)
    {
      Debug.debugException(nfe);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CHANGELOG_INVALID_CHANGE_NUMBER.get(changeNumberAttr.getValue()),
           nfe);
    }


    final Attribute targetDNAttr = entry.getAttribute(ATTR_TARGET_DN);
    if ((targetDNAttr == null) || (! targetDNAttr.hasValue()))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CHANGELOG_NO_TARGET_DN.get());
    }
    targetDN = targetDNAttr.getValue();


    final Attribute changeTypeAttr = entry.getAttribute(ATTR_CHANGE_TYPE);
    if ((changeTypeAttr == null) || (! changeTypeAttr.hasValue()))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CHANGELOG_NO_CHANGE_TYPE.get());
    }
    changeType = ChangeType.forName(changeTypeAttr.getValue());
    if (changeType == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CHANGELOG_INVALID_CHANGE_TYPE.get(changeTypeAttr.getValue()));
    }


    switch (changeType)
    {
      case ADD:
        attributes    = parseAddAttributeList(entry, ATTR_CHANGES, targetDN);
        modifications = null;
        newRDN        = null;
        deleteOldRDN  = false;
        newSuperior   = null;
        break;

      case DELETE:
        attributes    = parseDeletedAttributeList(entry, targetDN);
        modifications = null;
        newRDN        = null;
        deleteOldRDN  = false;
        newSuperior   = null;
        break;

      case MODIFY:
        attributes    = null;
        modifications = parseModificationList(entry, targetDN);
        newRDN        = null;
        deleteOldRDN  = false;
        newSuperior   = null;
        break;

      case MODIFY_DN:
        attributes    = null;
        modifications = parseModificationList(entry, targetDN);
        newSuperior   = getAttributeValue(ATTR_NEW_SUPERIOR);

        final Attribute newRDNAttr = getAttribute(ATTR_NEW_RDN);
        if ((newRDNAttr == null) || (! newRDNAttr.hasValue()))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_CHANGELOG_MISSING_NEW_RDN.get());
        }
        newRDN = newRDNAttr.getValue();

        final Attribute deleteOldRDNAttr = getAttribute(ATTR_DELETE_OLD_RDN);
        if ((deleteOldRDNAttr == null) || (! deleteOldRDNAttr.hasValue()))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_CHANGELOG_MISSING_DELETE_OLD_RDN.get());
        }
        final String delOldRDNStr = toLowerCase(deleteOldRDNAttr.getValue());
        if (delOldRDNStr.equals("true"))
        {
          deleteOldRDN = true;
        }
        else if (delOldRDNStr.equals("false"))
        {
          deleteOldRDN = false;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_CHANGELOG_MISSING_DELETE_OLD_RDN.get(delOldRDNStr));
        }
        break;

      default:

        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CHANGELOG_INVALID_CHANGE_TYPE.get(changeTypeAttr.getValue()));
    }
  }


  public static ChangeLogEntry constructChangeLogEntry(final long changeNumber,
                                    final LDIFChangeRecord changeRecord)
         throws LDAPException
  {
    final Entry e =
         new Entry(ATTR_CHANGE_NUMBER + '=' + changeNumber + ",cn=changelog");
    e.addAttribute("objectClass", "top", "changeLogEntry");
    e.addAttribute(new Attribute(ATTR_CHANGE_NUMBER,
         IntegerMatchingRule.getInstance(), String.valueOf(changeNumber)));
    e.addAttribute(new Attribute(ATTR_TARGET_DN,
         DistinguishedNameMatchingRule.getInstance(), changeRecord.getDN()));
    e.addAttribute(ATTR_CHANGE_TYPE, changeRecord.getChangeType().getName());

    switch (changeRecord.getChangeType())
    {
      case ADD:

        final LDIFAddChangeRecord addRecord =
             (LDIFAddChangeRecord) changeRecord;
        final Entry addEntry = new Entry(addRecord.getDN(),
             addRecord.getAttributes());
        final String[] entryLdifLines = addEntry.toLDIF(0);
        final StringBuilder entryLDIFBuffer = new StringBuilder();
        for (int i=1; i < entryLdifLines.length; i++)
        {
          entryLDIFBuffer.append(entryLdifLines[i]);
          entryLDIFBuffer.append(EOL);
        }
        e.addAttribute(new Attribute(ATTR_CHANGES,
             OctetStringMatchingRule.getInstance(),
             entryLDIFBuffer.toString()));
        break;

      case DELETE:
        break;

      case MODIFY:
        final String[] modLdifLines = changeRecord.toLDIF(0);
        final StringBuilder modLDIFBuffer = new StringBuilder();
        for (int i=2; i < modLdifLines.length; i++)
        {
          modLDIFBuffer.append(modLdifLines[i]);
          modLDIFBuffer.append(EOL);
        }
        e.addAttribute(new Attribute(ATTR_CHANGES,
             OctetStringMatchingRule.getInstance(), modLDIFBuffer.toString()));
        break;

      case MODIFY_DN:
        final LDIFModifyDNChangeRecord modDNRecord =
             (LDIFModifyDNChangeRecord) changeRecord;
        e.addAttribute(new Attribute(ATTR_NEW_RDN,
             DistinguishedNameMatchingRule.getInstance(),
             modDNRecord.getNewRDN()));
        e.addAttribute(new Attribute(ATTR_DELETE_OLD_RDN,
             BooleanMatchingRule.getInstance(),
             (modDNRecord.deleteOldRDN() ? "TRUE" : "FALSE")));
        if (modDNRecord.getNewSuperiorDN() != null)
        {
          e.addAttribute(new Attribute(ATTR_NEW_SUPERIOR,
               DistinguishedNameMatchingRule.getInstance(),
               modDNRecord.getNewSuperiorDN()));
        }
        break;
    }

    return new ChangeLogEntry(e);
  }


  protected static List<Attribute> parseAddAttributeList(final Entry entry,
                                                         final String attrName,
                                                         final String targetDN)
            throws LDAPException
  {
    final Attribute changesAttr = entry.getAttribute(attrName);
    if ((changesAttr == null) || (! changesAttr.hasValue()))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CHANGELOG_MISSING_CHANGES.get());
    }

    final ArrayList<String> ldifLines = new ArrayList<String>();
    ldifLines.add("dn: " + targetDN);

    final StringTokenizer tokenizer =
         new StringTokenizer(changesAttr.getValue(), "\r\n");
    while (tokenizer.hasMoreTokens())
    {
      ldifLines.add(tokenizer.nextToken());
    }

    final String[] lineArray = new String[ldifLines.size()];
    ldifLines.toArray(lineArray);

    try
    {
      final Entry e = LDIFReader.decodeEntry(lineArray);
      return Collections.unmodifiableList(
                  new ArrayList<Attribute>(e.getAttributes()));
    }
    catch (LDIFException le)
    {
      Debug.debugException(le);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CHANGELOG_CANNOT_PARSE_ATTR_LIST.get(attrName,
                getExceptionMessage(le)),
           le);
    }
  }

  private static List<Attribute> parseDeletedAttributeList(final Entry entry,
                                      final String targetDN)
          throws LDAPException
  {
    final Attribute deletedEntryAttrs =
         entry.getAttribute(ATTR_DELETED_ENTRY_ATTRS);
    if ((deletedEntryAttrs == null) || (! deletedEntryAttrs.hasValue()))
    {
      return null;
    }

    final byte[] valueBytes = deletedEntryAttrs.getValueByteArray();
    if ((valueBytes.length > 0) && (valueBytes[valueBytes.length-1] == 0x00))
    {
      final String valueStr = new String(valueBytes, 0, valueBytes.length-2);

      final ArrayList<String> ldifLines = new ArrayList<String>();
      ldifLines.add("dn: " + targetDN);
      ldifLines.add("changetype: modify");

      final StringTokenizer tokenizer = new StringTokenizer(valueStr, "\r\n");
      while (tokenizer.hasMoreTokens())
      {
        ldifLines.add(tokenizer.nextToken());
      }

      final String[] lineArray = new String[ldifLines.size()];
      ldifLines.toArray(lineArray);

      try
      {

        final LDIFModifyChangeRecord changeRecord =
             (LDIFModifyChangeRecord) LDIFReader.decodeChangeRecord(lineArray);
        final Modification[] mods = changeRecord.getModifications();
        final ArrayList<Attribute> attrs =
             new ArrayList<Attribute>(mods.length);
        for (final Modification m : mods)
        {
          if (! m.getModificationType().equals(ModificationType.DELETE))
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_CHANGELOG_INVALID_DELENTRYATTRS_MOD_TYPE.get(
                      ATTR_DELETED_ENTRY_ATTRS));
          }

          attrs.add(m.getAttribute());
        }

        return Collections.unmodifiableList(attrs);
      }
      catch (LDIFException le)
      {
        Debug.debugException(le);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CHANGELOG_INVALID_DELENTRYATTRS_MODS.get(
                  ATTR_DELETED_ENTRY_ATTRS, getExceptionMessage(le)), le);
      }
    }
    else
    {
      final ArrayList<String> ldifLines = new ArrayList<String>();
      ldifLines.add("dn: " + targetDN);

      final StringTokenizer tokenizer =
           new StringTokenizer(deletedEntryAttrs.getValue(), "\r\n");
      while (tokenizer.hasMoreTokens())
      {
        ldifLines.add(tokenizer.nextToken());
      }

      final String[] lineArray = new String[ldifLines.size()];
      ldifLines.toArray(lineArray);

      try
      {
        final Entry e = LDIFReader.decodeEntry(lineArray);
        return Collections.unmodifiableList(
                    new ArrayList<Attribute>(e.getAttributes()));
      }
      catch (LDIFException le)
      {
        Debug.debugException(le);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CHANGELOG_CANNOT_PARSE_DELENTRYATTRS.get(
                  ATTR_DELETED_ENTRY_ATTRS, getExceptionMessage(le)), le);
      }
    }
  }


  private static List<Modification> parseModificationList(final Entry entry,
                                                          final String targetDN)
          throws LDAPException
  {
    final Attribute changesAttr = entry.getAttribute(ATTR_CHANGES);
    if ((changesAttr == null) || (! changesAttr.hasValue()))
    {
      return null;
    }

    final byte[] valueBytes = changesAttr.getValueByteArray();
    if (valueBytes.length == 0)
    {
      return null;
    }


    final ArrayList<String> ldifLines = new ArrayList<String>();
    ldifLines.add("dn: " + targetDN);
    ldifLines.add("changetype: modify");

    final StringTokenizer tokenizer;
    if ((valueBytes.length > 0) && (valueBytes[valueBytes.length-1] == 0x00))
    {
      final String fullValue = changesAttr.getValue();
      final String realValue = fullValue.substring(0, fullValue.length()-2);
      tokenizer = new StringTokenizer(realValue, "\r\n");
    }
    else
    {
      tokenizer = new StringTokenizer(changesAttr.getValue(), "\r\n");
    }

    while (tokenizer.hasMoreTokens())
    {
      ldifLines.add(tokenizer.nextToken());
    }

    final String[] lineArray = new String[ldifLines.size()];
    ldifLines.toArray(lineArray);

    try
    {
      final LDIFModifyChangeRecord changeRecord =
           (LDIFModifyChangeRecord) LDIFReader.decodeChangeRecord(lineArray);
      return Collections.unmodifiableList(
                  Arrays.asList(changeRecord.getModifications()));
    }
    catch (LDIFException le)
    {
      Debug.debugException(le);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CHANGELOG_CANNOT_PARSE_MOD_LIST.get(ATTR_CHANGES,
                getExceptionMessage(le)),
           le);
    }
  }

  public final long getChangeNumber()
  {
    return changeNumber;
  }

  public final String getTargetDN()
  {
    return targetDN;
  }


  public final ChangeType getChangeType()
  {
    return changeType;
  }

  public final List<Attribute> getAddAttributes()
  {
    if (changeType == ChangeType.ADD)
    {
      return attributes;
    }
    else
    {
      return null;
    }
  }


  public final List<Attribute> getDeletedEntryAttributes()
  {
    if (changeType == ChangeType.DELETE)
    {
      return attributes;
    }
    else
    {
      return null;
    }
  }

  public final List<Modification> getModifications()
  {
    return modifications;
  }

  public final String getNewRDN()
  {
    return newRDN;
  }

  public final boolean deleteOldRDN()
  {
    return deleteOldRDN;
  }

  public final String getNewSuperior()
  {
    return newSuperior;
  }

  public final String getNewDN()
  {
    switch (changeType)
    {
      case ADD:
      case MODIFY:
        return targetDN;

      case MODIFY_DN:
        break;

      case DELETE:
      default:
        return null;
    }

    try
    {
      final RDN parsedNewRDN = new RDN(newRDN);

      if (newSuperior == null)
      {
        final DN parsedTargetDN = new DN(targetDN);
        final DN parentDN = parsedTargetDN.getParent();
        if (parentDN == null)
        {
          return new DN(parsedNewRDN).toString();
        }
        else
        {
          return new DN(parsedNewRDN, parentDN).toString();
        }
      }
      else
      {
        final DN parsedNewSuperior = new DN(newSuperior);
        return new DN(parsedNewRDN, parsedNewSuperior).toString();
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }

  public final LDIFChangeRecord toLDIFChangeRecord()
  {
    switch (changeType)
    {
      case ADD:
        return new LDIFAddChangeRecord(targetDN, attributes);

      case DELETE:
        return new LDIFDeleteChangeRecord(targetDN);

      case MODIFY:
        return new LDIFModifyChangeRecord(targetDN, modifications);

      case MODIFY_DN:
        return new LDIFModifyDNChangeRecord(targetDN, newRDN, deleteOldRDN,
                                            newSuperior);

      default:
        return null;
    }
  }


  public final LDAPResult processChange(final LDAPInterface connection)
         throws LDAPException
  {
    switch (changeType)
    {
      case ADD:
        return connection.add(targetDN, attributes);

      case DELETE:
        return connection.delete(targetDN);

      case MODIFY:
        return connection.modify(targetDN, modifications);

      case MODIFY_DN:
        return connection.modifyDN(targetDN, newRDN, deleteOldRDN, newSuperior);

      default:
        return null;
    }
  }
}

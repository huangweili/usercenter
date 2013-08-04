package com.hwlcn.ldap.ldif;



import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.ldap.util.Base64;
import com.hwlcn.ldap.util.LDAPSDKThreadFactory;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.ByteStringBuffer;
import com.hwlcn.ldap.util.parallel.ParallelProcessor;
import com.hwlcn.ldap.util.parallel.Result;
import com.hwlcn.ldap.util.parallel.Processor;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides an LDIF writer, which can be used to write entries and
 * change records in the LDAP Data Interchange Format as per
 * <A HREF="http://www.ietf.org/rfc/rfc2849.txt">RFC 2849</A>.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example performs a search to find all users in the "Sales"
 * department and then writes their entries to an LDIF file:
 * <PRE>
 *   SearchResult searchResult =
 *        connection.search("dc=example,dc=com", SearchScope.SUB, "(ou=Sales)");
 *
 *   LDIFWriter ldifWriter = new LDIFWriter(pathToLDIF);
 *   for (SearchResultEntry entry : searchResult.getSearchEntries())
 *   {
 *     ldifWriter.writeEntry(entry);
 *   }
 *
 *   ldifWriter.close();
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDIFWriter
{

  private static final int DEFAULT_BUFFER_SIZE = 128 * 1024;

  private final BufferedOutputStream writer;

  private final ByteStringBuffer buffer;

  private final LDIFWriterEntryTranslator entryTranslator;

  private int wrapColumn = 0;

  private int wrapColumnMinusTwo = -2;

  private final ParallelProcessor<LDIFRecord,ByteStringBuffer>
       toLdifBytesInvoker;

  public LDIFWriter(final String path)
         throws IOException
  {
    this(new FileOutputStream(path));
  }



  public LDIFWriter(final File file)
         throws IOException
  {
    this(new FileOutputStream(file));
  }



  public LDIFWriter(final OutputStream outputStream)
  {
    this(outputStream, 0);
  }


  public LDIFWriter(final OutputStream outputStream, final int parallelThreads)
  {
    this(outputStream, parallelThreads, null);
  }


  public LDIFWriter(final OutputStream outputStream, final int parallelThreads,
                    final LDIFWriterEntryTranslator entryTranslator)
  {
    ensureNotNull(outputStream);
    ensureTrue(parallelThreads >= 0,
               "LDIFWriter.parallelThreads must not be negative.");

    this.entryTranslator = entryTranslator;
    buffer = new ByteStringBuffer();

    if (outputStream instanceof BufferedOutputStream)
    {
      writer = (BufferedOutputStream) outputStream;
    }
    else
    {
      writer = new BufferedOutputStream(outputStream, DEFAULT_BUFFER_SIZE);
    }

    if (parallelThreads == 0)
    {
      toLdifBytesInvoker = null;
    }
    else
    {
      final LDAPSDKThreadFactory threadFactory =
           new LDAPSDKThreadFactory("LDIFWriter Worker", true, null);
      toLdifBytesInvoker = new ParallelProcessor<LDIFRecord,ByteStringBuffer>(
           new Processor<LDIFRecord,ByteStringBuffer>() {
             public ByteStringBuffer process(final LDIFRecord input)
                    throws IOException
             {
               final LDIFRecord r;
               if ((entryTranslator != null) && (input instanceof Entry))
               {
                 r = entryTranslator.translateEntryToWrite((Entry) input);
                 if (r == null)
                 {
                   return null;
                 }
               }
               else
               {
                 r = input;
               }

               final ByteStringBuffer b = new ByteStringBuffer(200);
               r.toLDIF(b, wrapColumn);
               return b;
             }
           }, threadFactory, parallelThreads, 5);
    }
  }



  public void flush()
         throws IOException
  {
    writer.flush();
  }


  public void close()
         throws IOException
  {
    try
    {
      if (toLdifBytesInvoker != null)
      {
        try
        {
          toLdifBytesInvoker.shutdown();
        }
        catch (InterruptedException e)
        {
          debugException(e);
        }
      }
    }
    finally
    {
      writer.close();
    }
  }

  public int getWrapColumn()
  {
    return wrapColumn;
  }

  public void setWrapColumn(final int wrapColumn)
  {
    this.wrapColumn = wrapColumn;

    wrapColumnMinusTwo = wrapColumn - 2;
  }



  public void writeEntry(final Entry entry)
         throws IOException
  {
    writeEntry(entry, null);
  }



  public void writeEntry(final Entry entry, final String comment)
         throws IOException
  {
    ensureNotNull(entry);

    final Entry e;
    if (entryTranslator == null)
    {
      e = entry;
    }
    else
    {
      e = entryTranslator.translateEntryToWrite(entry);
      if (e == null)
      {
        return;
      }
    }

    if (comment != null)
    {
      writeComment(comment, false, false);
    }

    debugLDIFWrite(entry);
    writeLDIF(entry);
  }



  public void writeChangeRecord(final LDIFChangeRecord changeRecord)
         throws IOException
  {
    ensureNotNull(changeRecord);

    debugLDIFWrite(changeRecord);
    writeLDIF(changeRecord);
  }


  public void writeChangeRecord(final LDIFChangeRecord changeRecord,
                                final String comment)
         throws IOException
  {
    ensureNotNull(changeRecord);

    debugLDIFWrite(changeRecord);
    if (comment != null)
    {
      writeComment(comment, false, false);
    }

    writeLDIF(changeRecord);
  }




  public void writeLDIFRecord(final LDIFRecord record)
         throws IOException
  {
    writeLDIFRecord(record, null);
  }


  public void writeLDIFRecord(final LDIFRecord record, final String comment)
         throws IOException
  {
    ensureNotNull(record);

    final LDIFRecord r;
    if ((entryTranslator != null) && (record instanceof Entry))
    {
      r = entryTranslator.translateEntryToWrite((Entry) record);
      if (r == null)
      {
        return;
      }
    }
    else
    {
      r = record;
    }

    debugLDIFWrite(r);
    if (comment != null)
    {
      writeComment(comment, false, false);
    }

    writeLDIF(r);
  }

  public void writeLDIFRecords(final List<? extends LDIFRecord> ldifRecords)
         throws IOException, InterruptedException
  {
    if (toLdifBytesInvoker == null)
    {
      for (final LDIFRecord ldifRecord : ldifRecords)
      {
        writeLDIFRecord(ldifRecord);
      }
    }
    else
    {
      final List<Result<LDIFRecord,ByteStringBuffer>> results =
           toLdifBytesInvoker.processAll(ldifRecords);
      for (final Result<LDIFRecord,ByteStringBuffer> result: results)
      {
        rethrow(result.getFailureCause());

        final ByteStringBuffer encodedBytes = result.getOutput();
        if (encodedBytes != null)
        {
          encodedBytes.write(writer);
          writer.write(EOL_BYTES);
        }
      }
    }
  }




  public void writeComment(final String comment, final boolean spaceBefore,
                           final boolean spaceAfter)
         throws IOException
  {
    ensureNotNull(comment);
    if (spaceBefore)
    {
      writer.write(EOL_BYTES);
    }


    if (comment.indexOf('\n') < 0)
    {
      writeSingleLineComment(comment);
    }
    else
    {

      final String[] lines = comment.split("\\r?\\n");
      for (final String line: lines)
      {
        writeSingleLineComment(line);
      }
    }

    if (spaceAfter)
    {
      writer.write(EOL_BYTES);
    }
  }



  private void writeSingleLineComment(final String comment)
          throws IOException
  {

    final int commentWrapMinusTwo;
    if (wrapColumn <= 0)
    {
      commentWrapMinusTwo = 77;
    }
    else
    {
      commentWrapMinusTwo = wrapColumnMinusTwo;
    }

    buffer.clear();
    final int length = comment.length();
    if (length <= commentWrapMinusTwo)
    {
      buffer.append("# ");
      buffer.append(comment);
      buffer.append(EOL_BYTES);
    }
    else
    {
      int minPos = 0;
      while (minPos < length)
      {
        if ((length - minPos) <= commentWrapMinusTwo)
        {
          buffer.append("# ");
          buffer.append(comment.substring(minPos));
          buffer.append(EOL_BYTES);
          break;
        }

        boolean spaceFound = false;
        final int pos = minPos + commentWrapMinusTwo;
        int     spacePos   = pos;
        while (spacePos > minPos)
        {
          if (comment.charAt(spacePos) == ' ')
          {
            spaceFound = true;
            break;
          }

          spacePos--;
        }

        if (! spaceFound)
        {
          spacePos = pos + 1;
          while (spacePos < length)
          {
            if (comment.charAt(spacePos) == ' ')
            {
              spaceFound = true;
              break;
            }

            spacePos++;
          }

          if (! spaceFound)
          {
            buffer.append("# ");
            buffer.append(comment.substring(minPos));
            buffer.append(EOL_BYTES);
            break;
          }
        }

        buffer.append("# ");
        buffer.append(comment.substring(minPos, spacePos));
        buffer.append(EOL_BYTES);

        minPos = spacePos + 1;
        while ((minPos < length) && (comment.charAt(minPos) == ' '))
        {
          minPos++;
        }
      }
    }

    buffer.write(writer);
  }



  private void writeLDIF(final LDIFRecord record)
          throws IOException
  {
    buffer.clear();
    record.toLDIF(buffer, wrapColumn);
    buffer.append(EOL_BYTES);
    buffer.write(writer);
  }



  public static List<String> wrapLines(final int wrapColumn,
                                       final String... ldifLines)
  {
    return wrapLines(wrapColumn, Arrays.asList(ldifLines));
  }


  public static List<String> wrapLines(final int wrapColumn,
                                       final List<String> ldifLines)
  {
    if (wrapColumn <= 2)
    {
      return new ArrayList<String>(ldifLines);
    }

    final ArrayList<String> newLines = new ArrayList<String>(ldifLines.size());
    for (final String s : ldifLines)
    {
      final int length = s.length();
      if (length <= wrapColumn)
      {
        newLines.add(s);
        continue;
      }

      newLines.add(s.substring(0, wrapColumn));

      int pos = wrapColumn;
      while (pos < length)
      {
        if ((length - pos + 1) <= wrapColumn)
        {
          newLines.add(' ' + s.substring(pos));
          break;
        }
        else
        {
          newLines.add(' ' + s.substring(pos, (pos+wrapColumn-1)));
          pos += wrapColumn - 1;
        }
      }
    }

    return newLines;
  }



  public static String encodeNameAndValue(final String name,
                                          final ASN1OctetString value)
  {
    final StringBuilder buffer = new StringBuilder();
    encodeNameAndValue(name, value, buffer);
    return buffer.toString();
  }



  public static void encodeNameAndValue(final String name,
                                        final ASN1OctetString value,
                                        final StringBuilder buffer)
  {
    encodeNameAndValue(name, value, buffer, 0);
  }

  public static void encodeNameAndValue(final String name,
                                        final ASN1OctetString value,
                                        final StringBuilder buffer,
                                        final int wrapColumn)
  {
    final int bufferStartPos = buffer.length();

    try
    {
      buffer.append(name);
      buffer.append(':');

      final byte[] valueBytes = value.getValue();
      final int length = valueBytes.length;
      if (length == 0)
      {
        buffer.append(' ');
        return;
      }
      switch (valueBytes[0])
      {
        case ' ':
        case ':':
        case '<':
          buffer.append(": ");
          Base64.encode(valueBytes, buffer);
          return;
      }

      if (valueBytes[length-1] == ' ')
      {
        buffer.append(": ");
        Base64.encode(valueBytes, buffer);
        return;
      }

      for (int i=0; i < length; i++)
      {
        if ((valueBytes[i] & 0x7F) != (valueBytes[i] & 0xFF))
        {
          buffer.append(": ");
          Base64.encode(valueBytes, buffer);
          return;
        }

        switch (valueBytes[i])
        {
          case 0x00:
          case 0x0A:
          case 0x0D:
            buffer.append(": ");
            Base64.encode(valueBytes, buffer);
            return;
        }
      }

      buffer.append(' ');
      buffer.append(value.stringValue());
    }
    finally
    {
      if (wrapColumn > 2)
      {
        final int length = buffer.length() - bufferStartPos;
        if (length > wrapColumn)
        {
          final String EOL_PLUS_SPACE = EOL + ' ';
          buffer.insert((bufferStartPos+wrapColumn), EOL_PLUS_SPACE);

          int pos = bufferStartPos + (2*wrapColumn) +
                    EOL_PLUS_SPACE.length() - 1;
          while (pos < buffer.length())
          {
            buffer.insert(pos, EOL_PLUS_SPACE);
            pos += (wrapColumn - 1 + EOL_PLUS_SPACE.length());
          }
        }
      }
    }
  }


  public static void encodeNameAndValue(final String name,
                                        final ASN1OctetString value,
                                        final ByteStringBuffer buffer,
                                        final int wrapColumn)
  {
    final int bufferStartPos = buffer.length();

    try
    {
      buffer.append(name);
      buffer.append(':');

      final byte[] valueBytes = value.getValue();
      final int length = valueBytes.length;
      if (length == 0)
      {
        buffer.append(' ');
        return;
      }
      switch (valueBytes[0])
      {
        case ' ':
        case ':':
        case '<':
          buffer.append(':');
          buffer.append(' ');
          Base64.encode(valueBytes, buffer);
          return;
      }

      if (valueBytes[length-1] == ' ')
      {
        buffer.append(':');
        buffer.append(' ');
        Base64.encode(valueBytes, buffer);
        return;
      }

      for (int i=0; i < length; i++)
      {
        if ((valueBytes[i] & 0x7F) != (valueBytes[i] & 0xFF))
        {
          buffer.append(':');
          buffer.append(' ');
          Base64.encode(valueBytes, buffer);
          return;
        }

        switch (valueBytes[i])
        {
          case 0x00:
          case 0x0A:
          case 0x0D:
            buffer.append(':');
            buffer.append(' ');
            Base64.encode(valueBytes, buffer);
            return;
        }
      }

      buffer.append(' ');
      buffer.append(valueBytes);
    }
    finally
    {
      if (wrapColumn > 2)
      {
        final int length = buffer.length() - bufferStartPos;
        if (length > wrapColumn)
        {
          final byte[] EOL_BYTES_PLUS_SPACE = new byte[EOL_BYTES.length + 1];
          System.arraycopy(EOL_BYTES, 0, EOL_BYTES_PLUS_SPACE, 0,
                           EOL_BYTES.length);
          EOL_BYTES_PLUS_SPACE[EOL_BYTES.length] = ' ';

          buffer.insert((bufferStartPos+wrapColumn), EOL_BYTES_PLUS_SPACE);

          int pos = bufferStartPos + (2*wrapColumn) +
                    EOL_BYTES_PLUS_SPACE.length - 1;
          while (pos < buffer.length())
          {
            buffer.insert(pos, EOL_BYTES_PLUS_SPACE);
            pos += (wrapColumn - 1 + EOL_BYTES_PLUS_SPACE.length);
          }
        }
      }
    }
  }


  static void rethrow(final Throwable t)
         throws IOException
  {
    if (t == null)
    {
      return;
    }

    if (t instanceof IOException)
    {
      throw (IOException) t;
    }
    else if (t instanceof RuntimeException)
    {
      throw (RuntimeException) t;
    }
    else if (t instanceof Error)
    {
      throw (Error) t;
    }
    else
    {
      throw new IOException(getExceptionMessage(t));
    }
  }
}

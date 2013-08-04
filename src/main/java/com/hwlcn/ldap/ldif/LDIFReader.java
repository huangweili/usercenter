package com.hwlcn.ldap.ldif;



import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.nio.charset.Charset;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.hwlcn.ldap.ldap.matchingrules.MatchingRule;
import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.ldap.ldap.sdk.Modification;
import com.hwlcn.ldap.ldap.sdk.ModificationType;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.ldap.util.AggregateInputStream;
import com.hwlcn.ldap.util.Base64;
import com.hwlcn.ldap.util.LDAPSDKThreadFactory;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.parallel.AsynchronousParallelProcessor;
import com.hwlcn.ldap.util.parallel.Result;
import com.hwlcn.ldap.util.parallel.ParallelProcessor;
import com.hwlcn.ldap.util.parallel.Processor;

import static com.hwlcn.ldap.ldif.LDIFMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;

/**
 * This class provides an LDIF reader, which can be used to read and decode
 * entries and change records from a data source using the LDAP Data Interchange
 * Format as per <A HREF="http://www.ietf.org/rfc/rfc2849.txt">RFC 2849</A>.
 * <BR>
 * This class is not synchronized.  If multiple threads read from the
 * LDIFReader, they must be synchronized externally.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example iterates through all entries contained in an LDIF file
 * and attempts to add them to a directory server:
 * <PRE>
 *   LDIFReader ldifReader = new LDIFReader(pathToLDIFFile);
 *
 *   while (true)
 *   {
 *     Entry entry;
 *     try
 *     {
 *       entry = ldifReader.readEntry();
 *       if (entry == null)
 *       {
 *         System.err.println("All entries have been processed.");
 *         break;
 *       }
 *     }
 *     catch (LDIFException le)
 *     {
 *       if (le.mayContinueReading())
 *       {
 *         System.err.println("A recoverable occurred while attempting to " +
 *              "read an entry at or near line number " + le.getLineNumber() +
 *              ":  " + le.getMessage());
 *         System.err.println("The entry will be skipped.");
 *         continue;
 *       }
 *       else
 *       {
 *         System.err.println("An unrecoverable occurred while attempting to " +
 *              "read an entry at or near line number " + le.getLineNumber() +
 *              ":  " + le.getMessage());
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
 *       connection.add(entry);
 *       System.out.println("Successfully added entry " + entry.getDN());
 *     }
 *     catch (LDAPException le)
 *     {
 *       System.err.println("Unable to add entry " + entry.getDN() + " -- " +
 *            le.getMessage());
 *     }
 *   }
 *
 *   ldifReader.close();
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDIFReader
{
  public static final int DEFAULT_BUFFER_SIZE = 128 * 1024;


  private static final int ASYNC_MIN_PER_PARSING_THREAD = 3;


  private static final int ASYNC_QUEUE_SIZE = 500;


  private static final Entry SKIP_ENTRY = new Entry("cn=skipped");


  private static final String DEFAULT_RELATIVE_BASE_PATH;
  static
  {
    final File currentDir;
    String currentDirString = System.getProperty("user.dir");
    if (currentDirString == null)
    {
      currentDir = new File(".");
    }
    else
    {
      currentDir = new File(currentDirString);
    }

    final String currentDirAbsolutePath = currentDir.getAbsolutePath();
    if (currentDirAbsolutePath.endsWith(File.separator))
    {
      DEFAULT_RELATIVE_BASE_PATH = currentDirAbsolutePath;
    }
    else
    {
      DEFAULT_RELATIVE_BASE_PATH = currentDirAbsolutePath + File.separator;
    }
  }

  private final BufferedReader reader;

  private volatile DuplicateValueBehavior duplicateValueBehavior;

  private long lineNumberCounter = 0;

  private final LDIFReaderEntryTranslator entryTranslator;

  private Schema schema;

  private volatile String relativeBasePath;

  private volatile TrailingSpaceBehavior trailingSpaceBehavior;

  private final boolean isAsync;

  private final AsynchronousParallelProcessor<UnparsedLDIFRecord, LDIFRecord>
       asyncParser;

  private final AtomicBoolean asyncParsingComplete;

  private final BlockingQueue<Result<UnparsedLDIFRecord, LDIFRecord>>
       asyncParsedRecords;



  public LDIFReader(final String path)
         throws IOException
  {
    this(new FileInputStream(path));
  }


  public LDIFReader(final String path, final int numParseThreads)
         throws IOException
  {
    this(new FileInputStream(path), numParseThreads);
  }

  public LDIFReader(final File file)
         throws IOException
  {
    this(new FileInputStream(file));
  }


  public LDIFReader(final File file, final int numParseThreads)
         throws IOException
  {
    this(new FileInputStream(file), numParseThreads);
  }


  public LDIFReader(final File[] files, final int numParseThreads,
                    final LDIFReaderEntryTranslator entryTranslator)
         throws IOException
  {
    this(createAggregateInputStream(files), numParseThreads, entryTranslator);
  }


  private static InputStream createAggregateInputStream(final File... files)
          throws IOException
  {
    if (files.length == 0)
    {
      throw new IOException(ERR_READ_NO_LDIF_FILES.get());
    }
    else if (files.length == 1)
    {
      return new FileInputStream(files[0]);
    }
    else
    {
      final File spacerFile =
           File.createTempFile("ldif-reader-spacer", ".ldif");
      spacerFile.deleteOnExit();

      final BufferedWriter spacerWriter =
           new BufferedWriter(new FileWriter(spacerFile));
      try
      {
        spacerWriter.newLine();
        spacerWriter.newLine();
      }
      finally
      {
        spacerWriter.close();
      }

      final File[] returnArray = new File[(files.length * 2) - 1];
      returnArray[0] = files[0];

      int pos = 1;
      for (int i=1; i < files.length; i++)
      {
        returnArray[pos++] = spacerFile;
        returnArray[pos++] = files[i];
      }

      return new AggregateInputStream(returnArray);
    }
  }

  public LDIFReader(final InputStream inputStream)
  {
    this(inputStream, 0);
  }


  public LDIFReader(final InputStream inputStream, final int numParseThreads)
  {
    this(new BufferedReader(new InputStreamReader(inputStream,
                                                  Charset.forName("UTF-8")),
                            DEFAULT_BUFFER_SIZE),
         numParseThreads);
  }


  public LDIFReader(final InputStream inputStream, final int numParseThreads,
                    final LDIFReaderEntryTranslator entryTranslator)
  {
    this(new BufferedReader(new InputStreamReader(inputStream,
                                                  Charset.forName("UTF-8")),
                            DEFAULT_BUFFER_SIZE),
         numParseThreads, entryTranslator);
  }


  public LDIFReader(final BufferedReader reader)
  {
    this(reader, 0);
  }


  public LDIFReader(final BufferedReader reader, final int numParseThreads)
  {
    this(reader, numParseThreads, null);
  }


  public LDIFReader(final BufferedReader reader,
                    final int numParseThreads,
                    final LDIFReaderEntryTranslator entryTranslator)
  {
    ensureNotNull(reader);
    ensureTrue(numParseThreads >= 0,
               "LDIFReader.numParseThreads must not be negative.");

    this.reader = reader;
    this.entryTranslator = entryTranslator;

    duplicateValueBehavior = DuplicateValueBehavior.STRIP;
    trailingSpaceBehavior  = TrailingSpaceBehavior.REJECT;

    relativeBasePath = DEFAULT_RELATIVE_BASE_PATH;

    if (numParseThreads == 0)
    {
      isAsync = false;
      asyncParser = null;
      asyncParsingComplete = null;
      asyncParsedRecords = null;
    }
    else
    {
      isAsync = true;
      asyncParsingComplete = new AtomicBoolean(false);

      final LDAPSDKThreadFactory threadFactory =
           new LDAPSDKThreadFactory("LDIFReader Worker", true, null);
      final ParallelProcessor<UnparsedLDIFRecord, LDIFRecord> parallelParser =
           new ParallelProcessor<UnparsedLDIFRecord, LDIFRecord>(
                new RecordParser(), threadFactory, numParseThreads,
                ASYNC_MIN_PER_PARSING_THREAD);

      final BlockingQueue<UnparsedLDIFRecord> pendingQueue = new
           ArrayBlockingQueue<UnparsedLDIFRecord>(ASYNC_QUEUE_SIZE);

      asyncParsedRecords = new ArrayBlockingQueue
           <Result<UnparsedLDIFRecord, LDIFRecord>>(2 * ASYNC_QUEUE_SIZE + 100);

      asyncParser = new AsynchronousParallelProcessor
           <UnparsedLDIFRecord, LDIFRecord>(pendingQueue, parallelParser,
                                            asyncParsedRecords);

      final LineReaderThread lineReaderThread = new LineReaderThread();
      lineReaderThread.start();
    }
  }


  public static List<Entry> readEntries(final String path)
         throws IOException, LDIFException
  {
    return readEntries(new LDIFReader(path));
  }


  public static List<Entry> readEntries(final File file)
         throws IOException, LDIFException
  {
    return readEntries(new LDIFReader(file));
  }


  public static List<Entry> readEntries(final InputStream inputStream)
         throws IOException, LDIFException
  {
    return readEntries(new LDIFReader(inputStream));
  }


  private static List<Entry> readEntries(final LDIFReader reader)
          throws IOException, LDIFException
  {
    try
    {
      final ArrayList<Entry> entries = new ArrayList<Entry>(10);
      while (true)
      {
        final Entry e = reader.readEntry();
        if (e == null)
        {
          break;
        }

        entries.add(e);
      }

      return entries;
    }
    finally
    {
      reader.close();
    }
  }



  public void close()
         throws IOException
  {
    reader.close();

    if (isAsync())
    {
      asyncParsedRecords.clear();
    }
  }



  @Deprecated()
  public boolean ignoreDuplicateValues()
  {
    return (duplicateValueBehavior == DuplicateValueBehavior.STRIP);
  }


  @Deprecated()
  public void setIgnoreDuplicateValues(final boolean ignoreDuplicateValues)
  {
    if (ignoreDuplicateValues)
    {
      duplicateValueBehavior = DuplicateValueBehavior.STRIP;
    }
    else
    {
      duplicateValueBehavior = DuplicateValueBehavior.REJECT;
    }
  }

  public DuplicateValueBehavior getDuplicateValueBehavior()
  {
    return duplicateValueBehavior;
  }


  public void setDuplicateValueBehavior(
                   final DuplicateValueBehavior duplicateValueBehavior)
  {
    this.duplicateValueBehavior = duplicateValueBehavior;
  }

  @Deprecated()
  public boolean stripTrailingSpaces()
  {
    return (trailingSpaceBehavior == TrailingSpaceBehavior.STRIP);
  }

  @Deprecated()
  public void setStripTrailingSpaces(final boolean stripTrailingSpaces)
  {
    trailingSpaceBehavior = stripTrailingSpaces
         ? TrailingSpaceBehavior.STRIP
         : TrailingSpaceBehavior.REJECT;
  }

  public TrailingSpaceBehavior getTrailingSpaceBehavior()
  {
    return trailingSpaceBehavior;
  }

  public void setTrailingSpaceBehavior(
                   final TrailingSpaceBehavior trailingSpaceBehavior)
  {
    this.trailingSpaceBehavior = trailingSpaceBehavior;
  }

  public String getRelativeBasePath()
  {
    return relativeBasePath;
  }

  public void setRelativeBasePath(final String relativeBasePath)
  {
    setRelativeBasePath(new File(relativeBasePath));
  }

  public void setRelativeBasePath(final File relativeBasePath)
  {
    final String path = relativeBasePath.getAbsolutePath();
    if (path.endsWith(File.separator))
    {
      this.relativeBasePath = path;
    }
    else
    {
      this.relativeBasePath = path + File.separator;
    }
  }

  public Schema getSchema()
  {
    return schema;
  }

  public void setSchema(final Schema schema)
  {
    this.schema = schema;
  }


  public LDIFRecord readLDIFRecord()
         throws IOException, LDIFException
  {
    if (isAsync())
    {
      return readLDIFRecordAsync();
    }
    else
    {
      return readLDIFRecordInternal();
    }
  }


  public Entry readEntry()
         throws IOException, LDIFException
  {
    if (isAsync())
    {
      return readEntryAsync();
    }
    else
    {
      return readEntryInternal();
    }
  }

  public LDIFChangeRecord readChangeRecord()
         throws IOException, LDIFException
  {
    return readChangeRecord(false);
  }

  public LDIFChangeRecord readChangeRecord(final boolean defaultAdd)
         throws IOException, LDIFException
  {
    if (isAsync())
    {
      return readChangeRecordAsync(defaultAdd);
    }
    else
    {
      return readChangeRecordInternal(defaultAdd);
    }
  }


  private LDIFRecord readLDIFRecordAsync()
          throws IOException, LDIFException
  {
    final Result<UnparsedLDIFRecord, LDIFRecord> result =
         readLDIFRecordResultAsync();
    if (result == null)
    {
      return null;
    }
    else
    {
      return result.getOutput();
    }
  }


  private Entry readEntryAsync()
          throws IOException, LDIFException
  {
    Result<UnparsedLDIFRecord, LDIFRecord> result = null;
    LDIFRecord record = null;
    while (record == null)
    {
      result = readLDIFRecordResultAsync();
      if (result == null)
      {
        return null;
      }

      record = result.getOutput();

      if (record == SKIP_ENTRY)
      {
        record = null;
      }
    }

    if (!(record instanceof Entry))
    {
      try
      {
        return ((LDIFChangeRecord)record).toEntry();
      }
      catch (LDIFException e)
      {
        debugException(e);
        final long firstLineNumber = result.getInput().getFirstLineNumber();
        throw new LDIFException(e.getExceptionMessage(),
                                firstLineNumber, true, e);
      }
    }

    return (Entry) record;
  }



  private LDIFChangeRecord readChangeRecordAsync(final boolean defaultAdd)
          throws IOException, LDIFException
  {
    final Result<UnparsedLDIFRecord, LDIFRecord> result =
         readLDIFRecordResultAsync();
    if (result == null)
    {
      return null;
    }

    final LDIFRecord record = result.getOutput();
    if (record instanceof LDIFChangeRecord)
    {
      return (LDIFChangeRecord) record;
    }
    else if (record instanceof Entry)
    {
      if (defaultAdd)
      {
        return new LDIFAddChangeRecord((Entry) record);
      }
      else
      {
        final long firstLineNumber = result.getInput().getFirstLineNumber();
        throw new LDIFException(
             ERR_READ_NOT_CHANGE_RECORD.get(firstLineNumber), firstLineNumber,
             true);
      }
    }

    throw new AssertionError("LDIFRecords must either be an Entry or an " +
                             "LDIFChangeRecord");
  }


  private Result<UnparsedLDIFRecord, LDIFRecord> readLDIFRecordResultAsync()
          throws IOException, LDIFException
  {
    Result<UnparsedLDIFRecord, LDIFRecord> result = null;

    if (asyncParsingComplete.get())
    {
      result = asyncParsedRecords.poll();
    }
    else
    {
      try
      {
        while ((result == null) && (!asyncParsingComplete.get()))
        {
          result = asyncParsedRecords.poll(1, TimeUnit.SECONDS);
        }

        if (result == null)
        {
          result = asyncParsedRecords.poll();
        }
      }
      catch (InterruptedException e)
      {
        debugException(e);
        throw new IOException(getExceptionMessage(e));
      }
    }
    if (result == null)
    {
      return null;
    }

    rethrow(result.getFailureCause());
    final UnparsedLDIFRecord unparsedRecord = result.getInput();
    if (unparsedRecord.isEOF())
    {
      asyncParsingComplete.set(true);

      try
      {
        asyncParsedRecords.put(result);
      }
      catch (InterruptedException e)
      {
        debugException(e);
      }
      return null;
    }

    return result;
  }


  private boolean isAsync()
  {
    return isAsync;
  }


  static void rethrow(final Throwable t)
         throws IOException, LDIFException
  {
    if (t == null)
    {
      return;
    }

    if (t instanceof IOException)
    {
      throw (IOException) t;
    }
    else if (t instanceof LDIFException)
    {
      throw (LDIFException) t;
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


  private LDIFRecord readLDIFRecordInternal()
       throws IOException, LDIFException
  {
    final UnparsedLDIFRecord unparsedRecord = readUnparsedRecord();
    return decodeRecord(unparsedRecord, relativeBasePath);
  }



  private Entry readEntryInternal()
       throws IOException, LDIFException
  {
    Entry e = null;
    while (e == null)
    {
      final UnparsedLDIFRecord unparsedRecord = readUnparsedRecord();
      if (unparsedRecord.isEOF())
      {
        return null;
      }

      e = decodeEntry(unparsedRecord, relativeBasePath);
      debugLDIFRead(e);

      if (entryTranslator != null)
      {
        e = entryTranslator.translate(e, unparsedRecord.getFirstLineNumber());
      }
    }
    return e;
  }


  private LDIFChangeRecord readChangeRecordInternal(final boolean defaultAdd)
       throws IOException, LDIFException
  {
    final UnparsedLDIFRecord unparsedRecord = readUnparsedRecord();
    if (unparsedRecord.isEOF())
    {
      return null;
    }

    final LDIFChangeRecord r =
         decodeChangeRecord(unparsedRecord, relativeBasePath, defaultAdd);
    debugLDIFRead(r);
    return r;
  }


  private UnparsedLDIFRecord readUnparsedRecord()
         throws IOException, LDIFException
  {
    final ArrayList<StringBuilder> lineList = new ArrayList<StringBuilder>(20);
    boolean lastWasComment = false;
    long firstLineNumber = lineNumberCounter + 1;
    while (true)
    {
      final String line = reader.readLine();
      lineNumberCounter++;

      if (line == null)
      {
        if (lineList.isEmpty())
        {
          return new UnparsedLDIFRecord(new ArrayList<StringBuilder>(0),
               duplicateValueBehavior, trailingSpaceBehavior, schema, -1);
        }
        else
        {
          break;
        }
      }

      if (line.length() == 0)
      {
        lastWasComment = false;
        if (lineList.isEmpty())
        {
          firstLineNumber++;
          continue;
        }
        else
        {
          break;
        }
      }

      if (line.charAt(0) == ' ')
      {
        if (lastWasComment)
        {
        }
        else if (lineList.isEmpty())
        {
          throw new LDIFException(
                         ERR_READ_UNEXPECTED_FIRST_SPACE.get(lineNumberCounter),
                         lineNumberCounter, false);
        }
        else
        {
          lineList.get(lineList.size() - 1).append(line.substring(1));
          lastWasComment = false;
        }
      }
      else if (line.charAt(0) == '#')
      {
        lastWasComment = true;
      }
      else
      {
        if (lineList.isEmpty() && line.startsWith("version:"))
        {
          lastWasComment = true;
        }
        else
        {
          lineList.add(new StringBuilder(line));
          lastWasComment = false;
        }
      }
    }

    return new UnparsedLDIFRecord(lineList, duplicateValueBehavior,
         trailingSpaceBehavior, schema, firstLineNumber);
  }


  public static Entry decodeEntry(final String... ldifLines)
         throws LDIFException
  {
    final Entry e = decodeEntry(prepareRecord(DuplicateValueBehavior.STRIP,
         TrailingSpaceBehavior.REJECT, null, ldifLines),
         DEFAULT_RELATIVE_BASE_PATH);
    debugLDIFRead(e);
    return e;
  }


  public static Entry decodeEntry(final boolean ignoreDuplicateValues,
                                  final Schema schema,
                                  final String... ldifLines)
         throws LDIFException
  {
    final Entry e = decodeEntry(prepareRecord(
              (ignoreDuplicateValues
                   ? DuplicateValueBehavior.STRIP
                   : DuplicateValueBehavior.REJECT),
              TrailingSpaceBehavior.REJECT, schema, ldifLines),
         DEFAULT_RELATIVE_BASE_PATH);
    debugLDIFRead(e);
    return e;
  }



  public static LDIFChangeRecord decodeChangeRecord(final String... ldifLines)
         throws LDIFException
  {
    return decodeChangeRecord(false, ldifLines);
  }



  public static LDIFChangeRecord decodeChangeRecord(final boolean defaultAdd,
                                                    final String... ldifLines)
         throws LDIFException
  {
    final LDIFChangeRecord r =
         decodeChangeRecord(
              prepareRecord(DuplicateValueBehavior.STRIP,
                   TrailingSpaceBehavior.REJECT, null, ldifLines),
              DEFAULT_RELATIVE_BASE_PATH, defaultAdd);
    debugLDIFRead(r);
    return r;
  }


  public static LDIFChangeRecord decodeChangeRecord(
                                      final boolean ignoreDuplicateValues,
                                      final Schema schema,
                                      final boolean defaultAdd,
                                      final String... ldifLines)
         throws LDIFException
  {
    final LDIFChangeRecord r = decodeChangeRecord(
         prepareRecord(
              (ignoreDuplicateValues
                   ? DuplicateValueBehavior.STRIP
                   : DuplicateValueBehavior.REJECT),
              TrailingSpaceBehavior.REJECT, schema, ldifLines),
         DEFAULT_RELATIVE_BASE_PATH, defaultAdd);
    debugLDIFRead(r);
    return r;
  }


  private static UnparsedLDIFRecord prepareRecord(
                      final DuplicateValueBehavior duplicateValueBehavior,
                      final TrailingSpaceBehavior trailingSpaceBehavior,
                      final Schema schema, final String... ldifLines)
          throws LDIFException
  {
    ensureNotNull(ldifLines);
    ensureFalse(ldifLines.length == 0,
                "LDIFReader.prepareRecord.ldifLines must not be empty.");

    boolean lastWasComment = false;
    final ArrayList<StringBuilder> lineList =
         new ArrayList<StringBuilder>(ldifLines.length);
    for (int i=0; i < ldifLines.length; i++)
    {
      final String line = ldifLines[i];
      if (line.length() == 0)
      {

        for (int j=i+1; j < ldifLines.length; j++)
        {
          if (ldifLines[j].length() > 0)
          {
            throw new LDIFException(ERR_READ_UNEXPECTED_BLANK.get(i), i, true,
                                    ldifLines, null);
          }

          if (lineList.isEmpty())
          {
            throw new LDIFException(ERR_READ_ONLY_BLANKS.get(), 0, true,
                                    ldifLines, null);
          }
          else
          {
            return new UnparsedLDIFRecord(lineList, duplicateValueBehavior,
                 trailingSpaceBehavior, schema, 0);
          }
        }
      }

      if (line.charAt(0) == ' ')
      {
        if (i > 0)
        {
          if (! lastWasComment)
          {
            lineList.get(lineList.size() - 1).append(line.substring(1));
          }
        }
        else
        {
          throw new LDIFException(
                         ERR_READ_UNEXPECTED_FIRST_SPACE_NO_NUMBER.get(), 0,
                         true, ldifLines, null);
        }
      }
      else if (line.charAt(0) == '#')
      {
        lastWasComment = true;
      }
      else
      {
        lineList.add(new StringBuilder(line));
        lastWasComment = false;
      }
    }

    if (lineList.isEmpty())
    {
      throw new LDIFException(ERR_READ_NO_DATA.get(), 0, true, ldifLines, null);
    }
    else
    {
      return new UnparsedLDIFRecord(lineList, duplicateValueBehavior,
           trailingSpaceBehavior, schema, 0);
    }
  }

  private static LDIFRecord decodeRecord(
                                 final UnparsedLDIFRecord unparsedRecord,
                                 final String relativeBasePath)
       throws LDIFException
  {
    final Exception readError = unparsedRecord.getFailureCause();
    if (readError != null)
    {
      if (readError instanceof LDIFException)
      {
        final LDIFException ldifEx = (LDIFException) readError;
        throw new LDIFException(ldifEx.getMessage(),
                                ldifEx.getLineNumber(),
                                ldifEx.mayContinueReading(),
                                ldifEx.getDataLines(),
                                ldifEx.getCause());
      }
      else
      {
        throw new LDIFException(getExceptionMessage(readError),
                                -1, true, readError);
      }
    }

    if (unparsedRecord.isEOF())
    {
      return null;
    }

    final ArrayList<StringBuilder> lineList = unparsedRecord.getLineList();
    if (unparsedRecord.getLineList() == null)
    {
      return null;
    }

    final LDIFRecord r;
    if ((lineList.size() > 1) &&
        toLowerCase(lineList.get(1).toString()).startsWith("changetype:"))
    {
      r = decodeChangeRecord(unparsedRecord, relativeBasePath, false);
    }
    else
    {
      r = decodeEntry(unparsedRecord, relativeBasePath);
    }

    debugLDIFRead(r);
    return r;
  }



  private static Entry decodeEntry(final UnparsedLDIFRecord unparsedRecord,
                                   final String relativeBasePath)
          throws LDIFException
  {
    final ArrayList<StringBuilder> ldifLines = unparsedRecord.getLineList();
    final long firstLineNumber = unparsedRecord.getFirstLineNumber();

    final Iterator<StringBuilder> iterator = ldifLines.iterator();

    final StringBuilder line = iterator.next();
    handleTrailingSpaces(line, null, firstLineNumber,
         unparsedRecord.getTrailingSpaceBehavior());
    final int colonPos = line.indexOf(":");
    if ((colonPos < 0) ||
        (! line.substring(0, colonPos).equalsIgnoreCase("dn")))
    {
      throw new LDIFException(
                     ERR_READ_DN_LINE_DOESNT_START_WITH_DN.get(firstLineNumber),
                     firstLineNumber, true, ldifLines, null);
    }

    final String dn;
    final int length = line.length();
    if (length == (colonPos+1))
    {
      dn = "";
    }
    else if (line.charAt(colonPos+1) == ':')
    {
      int pos = colonPos+2;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      try
      {
        final byte[] dnBytes = Base64.decode(line.substring(pos));
        dn = new String(dnBytes, "UTF-8");
      }
      catch (final ParseException pe)
      {
        debugException(pe);
        throw new LDIFException(
                       ERR_READ_CANNOT_BASE64_DECODE_DN.get(firstLineNumber,
                                                            pe.getMessage()),
                       firstLineNumber, true, ldifLines, pe);
      }
      catch (final Exception e)
      {
        debugException(e);
        throw new LDIFException(
                       ERR_READ_CANNOT_BASE64_DECODE_DN.get(firstLineNumber, e),
                       firstLineNumber, true, ldifLines, e);
      }
    }
    else
    {
      int pos = colonPos+1;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      dn = line.substring(pos);
    }


    if (! iterator.hasNext())
    {
      return new Entry(dn, unparsedRecord.getSchema());
    }

    return new Entry(dn, unparsedRecord.getSchema(),
         parseAttributes(dn, unparsedRecord.getDuplicateValueBehavior(),
              unparsedRecord.getTrailingSpaceBehavior(),
              unparsedRecord.getSchema(), ldifLines, iterator, relativeBasePath,
              firstLineNumber));
  }


  private static LDIFChangeRecord decodeChangeRecord(
                                       final UnparsedLDIFRecord unparsedRecord,
                                       final String relativeBasePath,
                                       final boolean defaultAdd)
          throws LDIFException
  {
    final ArrayList<StringBuilder> ldifLines = unparsedRecord.getLineList();
    final long firstLineNumber = unparsedRecord.getFirstLineNumber();

    final Iterator<StringBuilder> iterator = ldifLines.iterator();

    StringBuilder line = iterator.next();
    handleTrailingSpaces(line, null, firstLineNumber,
         unparsedRecord.getTrailingSpaceBehavior());
    int colonPos = line.indexOf(":");
    if ((colonPos < 0) ||
        (! line.substring(0, colonPos).equalsIgnoreCase("dn")))
    {
      throw new LDIFException(
           ERR_READ_CR_DN_LINE_DOESNT_START_WITH_DN.get(firstLineNumber),
           firstLineNumber, true, ldifLines, null);
    }

    final String dn;
    int length = line.length();
    if (length == (colonPos+1))
    {
      dn = "";
    }
    else if (line.charAt(colonPos+1) == ':')
    {
      int pos = colonPos+2;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      try
      {
        final byte[] dnBytes = Base64.decode(line.substring(pos));
        dn = new String(dnBytes, "UTF-8");
      }
      catch (final ParseException pe)
      {
        debugException(pe);
        throw new LDIFException(
                       ERR_READ_CR_CANNOT_BASE64_DECODE_DN.get(firstLineNumber,
                                                               pe.getMessage()),
                       firstLineNumber, true, ldifLines, pe);
      }
      catch (final Exception e)
      {
        debugException(e);
        throw new LDIFException(
                       ERR_READ_CR_CANNOT_BASE64_DECODE_DN.get(firstLineNumber,
                                                               e),
                       firstLineNumber, true, ldifLines, e);
      }
    }
    else
    {
      int pos = colonPos+1;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      dn = line.substring(pos);
    }

    if (! iterator.hasNext())
    {
      throw new LDIFException(ERR_READ_CR_TOO_SHORT.get(firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }

    final String changeType;
    if (defaultAdd &&
        (! toLowerCase(ldifLines.get(1).toString()).startsWith("changetype:")))
    {
      changeType = "add";
    }
    else
    {
      line = iterator.next();
      handleTrailingSpaces(line, dn, firstLineNumber,
           unparsedRecord.getTrailingSpaceBehavior());
      colonPos = line.indexOf(":");
      if ((colonPos < 0) ||
          (! line.substring(0, colonPos).equalsIgnoreCase("changetype")))
      {
        throw new LDIFException(
             ERR_READ_CR_CT_LINE_DOESNT_START_WITH_CT.get(firstLineNumber),
             firstLineNumber, true, ldifLines, null);
      }

      length = line.length();
      if (length == (colonPos+1))
      {
        throw new LDIFException(
             ERR_READ_CT_LINE_NO_CT_VALUE.get(firstLineNumber), firstLineNumber,
             true, ldifLines, null);
      }
      else if (line.charAt(colonPos+1) == ':')
      {
        int pos = colonPos+2;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        try
        {
          final byte[] changeTypeBytes = Base64.decode(line.substring(pos));
          changeType = new String(changeTypeBytes, "UTF-8");
        }
        catch (final ParseException pe)
        {
          debugException(pe);
          throw new LDIFException(
                         ERR_READ_CANNOT_BASE64_DECODE_CT.get(firstLineNumber,
                                                              pe.getMessage()),
                         firstLineNumber, true, ldifLines, pe);
        }
        catch (final Exception e)
        {
          debugException(e);
          throw new LDIFException(
               ERR_READ_CANNOT_BASE64_DECODE_CT.get(firstLineNumber, e),
               firstLineNumber, true, ldifLines, e);
        }
      }
      else
      {
        int pos = colonPos+1;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        changeType = line.substring(pos);
      }
    }

    final String lowerChangeType = toLowerCase(changeType);
    if (lowerChangeType.equals("add"))
    {
      if (iterator.hasNext())
      {
        final Collection<Attribute> attrs =
             parseAttributes(dn, unparsedRecord.getDuplicateValueBehavior(),
                  unparsedRecord.getTrailingSpaceBehavior(),
                  unparsedRecord.getSchema(), ldifLines, iterator,
                  relativeBasePath, firstLineNumber);
        final Attribute[] attributes = new Attribute[attrs.size()];
        final Iterator<Attribute> attrIterator = attrs.iterator();
        for (int i=0; i < attributes.length; i++)
        {
          attributes[i] = attrIterator.next();
        }

        return new LDIFAddChangeRecord(dn, attributes);
      }
      else
      {
        throw new LDIFException(ERR_READ_CR_NO_ATTRIBUTES.get(firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }
    }
    else if (lowerChangeType.equals("delete"))
    {
      if (iterator.hasNext())
      {
        throw new LDIFException(
                       ERR_READ_CR_EXTRA_DELETE_DATA.get(firstLineNumber),
                       firstLineNumber, true, ldifLines, null);
      }
      else
      {
        return new LDIFDeleteChangeRecord(dn);
      }
    }
    else if (lowerChangeType.equals("modify"))
    {
      if (iterator.hasNext())
      {
        final Modification[] mods = parseModifications(dn,
             unparsedRecord.getTrailingSpaceBehavior(), ldifLines, iterator,
             firstLineNumber);
        return new LDIFModifyChangeRecord(dn, mods);
      }
      else
      {
        throw new LDIFException(ERR_READ_CR_NO_MODS.get(firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }
    }
    else if (lowerChangeType.equals("moddn") ||
             lowerChangeType.equals("modrdn"))
    {
      if (iterator.hasNext())
      {
        return parseModifyDNChangeRecord(ldifLines, iterator, dn,
             unparsedRecord.getTrailingSpaceBehavior(), firstLineNumber);
      }
      else
      {
        throw new LDIFException(ERR_READ_CR_NO_NEWRDN.get(firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }
    }
    else
    {
      throw new LDIFException(ERR_READ_CR_INVALID_CT.get(changeType,
                                                         firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }
  }


  private static ArrayList<Attribute> parseAttributes(final String dn,
       final DuplicateValueBehavior duplicateValueBehavior,
       final TrailingSpaceBehavior trailingSpaceBehavior, final Schema schema,
       final ArrayList<StringBuilder> ldifLines,
       final Iterator<StringBuilder> iterator, final String relativeBasePath,
       final long firstLineNumber)
          throws LDIFException
  {
    final LinkedHashMap<String,Object> attributes =
         new LinkedHashMap<String,Object>(ldifLines.size());
    while (iterator.hasNext())
    {
      final StringBuilder line = iterator.next();
      handleTrailingSpaces(line, dn, firstLineNumber, trailingSpaceBehavior);
      final int colonPos = line.indexOf(":");
      if (colonPos <= 0)
      {
        throw new LDIFException(ERR_READ_NO_ATTR_COLON.get(firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }

      final String attributeName = line.substring(0, colonPos);
      final String lowerName     = toLowerCase(attributeName);

      final MatchingRule matchingRule;
      if (schema == null)
      {
        matchingRule = CaseIgnoreStringMatchingRule.getInstance();
      }
      else
      {
        matchingRule =
             MatchingRule.selectEqualityMatchingRule(attributeName, schema);
      }

      Attribute attr;
      final LDIFAttribute ldifAttr;
      final Object attrObject = attributes.get(lowerName);
      if (attrObject == null)
      {
        attr     = null;
        ldifAttr = null;
      }
      else
      {
        if (attrObject instanceof Attribute)
        {
          attr     = (Attribute) attrObject;
          ldifAttr = new LDIFAttribute(attr.getName(), matchingRule,
                                       attr.getRawValues()[0]);
          attributes.put(lowerName, ldifAttr);
        }
        else
        {
          attr     = null;
          ldifAttr = (LDIFAttribute) attrObject;
        }
      }

      final int length = line.length();
      if (length == (colonPos+1))
      {

        if (attrObject == null)
        {
          attr = new Attribute(attributeName, "");
          attributes.put(lowerName, attr);
        }
        else
        {
          try
          {
            if (! ldifAttr.addValue(new ASN1OctetString(),
                       duplicateValueBehavior))
            {
              if (duplicateValueBehavior != DuplicateValueBehavior.STRIP)
              {
                throw new LDIFException(ERR_READ_DUPLICATE_VALUE.get(dn,
                     firstLineNumber, attributeName), firstLineNumber, true,
                     ldifLines, null);
              }
            }
          }
          catch (LDAPException le)
          {
            throw new LDIFException(ERR_READ_VALUE_SYNTAX_VIOLATION.get(dn,
                 firstLineNumber, attributeName, getExceptionMessage(le)),
                 firstLineNumber, true, ldifLines, le);
          }
        }
      }
      else if (line.charAt(colonPos+1) == ':')
      {
        int pos = colonPos+2;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        try
        {
          final byte[] valueBytes = Base64.decode(line.substring(pos));
          if (attrObject == null)
          {
            attr = new Attribute(attributeName, valueBytes);
            attributes.put(lowerName, attr);
          }
          else
          {
            try
            {
              if (! ldifAttr.addValue(new ASN1OctetString(valueBytes),
                         duplicateValueBehavior))
              {
                if (duplicateValueBehavior != DuplicateValueBehavior.STRIP)
                {
                  throw new LDIFException(ERR_READ_DUPLICATE_VALUE.get(dn,
                       firstLineNumber, attributeName), firstLineNumber, true,
                       ldifLines, null);
                }
              }
            }
            catch (LDAPException le)
            {
              throw new LDIFException(ERR_READ_VALUE_SYNTAX_VIOLATION.get(dn,
                   firstLineNumber, attributeName, getExceptionMessage(le)),
                   firstLineNumber, true, ldifLines, le);
            }
          }
        }
        catch (final ParseException pe)
        {
          debugException(pe);
          throw new LDIFException(ERR_READ_CANNOT_BASE64_DECODE_ATTR.get(
                                       attributeName,  firstLineNumber,
                                       pe.getMessage()),
                                  firstLineNumber, true, ldifLines, pe);
        }
      }
      else if (line.charAt(colonPos+1) == '<')
      {
        int pos = colonPos+2;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        final String path;
        final String urlString = line.substring(pos);
        final String lowerURLString = toLowerCase(urlString);
        if (lowerURLString.startsWith("file:/"))
        {
          pos = 6;
          while ((pos < urlString.length()) && (urlString.charAt(pos) == '/'))
          {
            pos++;
          }

          path = urlString.substring(pos-1);
        }
        else if (lowerURLString.startsWith("file:"))
        {

          path = relativeBasePath + urlString.substring(5);
        }
        else
        {
          throw new LDIFException(ERR_READ_URL_INVALID_SCHEME.get(attributeName,
                                       urlString, firstLineNumber),
                                  firstLineNumber, true, ldifLines, null);
        }

        try
        {
          final File f = new File(path);
          if (! f.exists())
          {
            throw new LDIFException(ERR_READ_URL_NO_SUCH_FILE.get(attributeName,
                                         urlString, firstLineNumber,
                                         f.getAbsolutePath()),
                                    firstLineNumber, true, ldifLines, null);
          }

          final long fileSize = f.length();
          if (fileSize > (10 * 1024 * 1024))
          {
            throw new LDIFException(ERR_READ_URL_FILE_TOO_LARGE.get(
                                         attributeName, urlString,
                                         firstLineNumber, f.getAbsolutePath(),
                                         (10*1024*1024)),
                                    firstLineNumber, true, ldifLines, null);
          }

          int fileBytesRead              = 0;
          int fileBytesRemaining         = (int) fileSize;
          final byte[]          fileData = new byte[(int) fileSize];
          final FileInputStream fis      = new FileInputStream(f);
          try
          {
            while (fileBytesRead < fileSize)
            {
              final int bytesRead =
                   fis.read(fileData, fileBytesRead, fileBytesRemaining);
              if (bytesRead < 0)
              {
                throw new LDIFException(ERR_READ_URL_FILE_SIZE_CHANGED.get(
                                             attributeName, urlString,
                                             firstLineNumber,
                                             f.getAbsolutePath()),
                                        firstLineNumber, true, ldifLines, null);
              }

              fileBytesRead      += bytesRead;
              fileBytesRemaining -= bytesRead;
            }

            if (fis.read() != -1)
            {
              throw new LDIFException(ERR_READ_URL_FILE_SIZE_CHANGED.get(
                                           attributeName, urlString,
                                           firstLineNumber,
                                           f.getAbsolutePath()),
                                      firstLineNumber, true, ldifLines, null);
            }
          }
          finally
          {
            fis.close();
          }

          if (attrObject == null)
          {
            attr = new Attribute(attributeName, fileData);
            attributes.put(lowerName, attr);
          }
          else
          {
            if (! ldifAttr.addValue(new ASN1OctetString(fileData),
                       duplicateValueBehavior))
            {
              if (duplicateValueBehavior != DuplicateValueBehavior.STRIP)
              {
                throw new LDIFException(ERR_READ_DUPLICATE_VALUE.get(dn,
                     firstLineNumber, attributeName), firstLineNumber, true,
                     ldifLines, null);
              }
            }
          }
        }
        catch (LDIFException le)
        {
          debugException(le);
          throw le;
        }
        catch (Exception e)
        {
          debugException(e);
          throw new LDIFException(ERR_READ_URL_EXCEPTION.get(attributeName,
                                       urlString, firstLineNumber, e),
                                  firstLineNumber, true, ldifLines, e);
        }
      }
      else
      {
        int pos = colonPos+1;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        final String valueString = line.substring(pos);
        if (attrObject == null)
        {
          attr = new Attribute(attributeName, valueString);
          attributes.put(lowerName, attr);
        }
        else
        {
          try
          {
            if (! ldifAttr.addValue(new ASN1OctetString(valueString),
                       duplicateValueBehavior))
            {
              if (duplicateValueBehavior != DuplicateValueBehavior.STRIP)
              {
                throw new LDIFException(ERR_READ_DUPLICATE_VALUE.get(dn,
                     firstLineNumber, attributeName), firstLineNumber, true,
                     ldifLines, null);
              }
            }
          }
          catch (LDAPException le)
          {
            throw new LDIFException(ERR_READ_VALUE_SYNTAX_VIOLATION.get(dn,
                 firstLineNumber, attributeName, getExceptionMessage(le)),
                 firstLineNumber, true, ldifLines, le);
          }
        }
      }
    }

    final ArrayList<Attribute> attrList =
         new ArrayList<Attribute>(attributes.size());
    for (final Object o : attributes.values())
    {
      if (o instanceof Attribute)
      {
        attrList.add((Attribute) o);
      }
      else
      {
        attrList.add(((LDIFAttribute) o).toAttribute());
      }
    }

    return attrList;
  }


  private static Modification[] parseModifications(final String dn,
       final TrailingSpaceBehavior trailingSpaceBehavior,
       final ArrayList<StringBuilder> ldifLines,
       final Iterator<StringBuilder> iterator, final long firstLineNumber)
       throws LDIFException
  {
    final ArrayList<Modification> modList =
         new ArrayList<Modification>(ldifLines.size());

    while (iterator.hasNext())
    {
      StringBuilder line = iterator.next();
      handleTrailingSpaces(line, dn, firstLineNumber, trailingSpaceBehavior);
      int colonPos = line.indexOf(":");
      if (colonPos < 0)
      {
        throw new LDIFException(ERR_READ_MOD_CR_NO_MODTYPE.get(firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }

      final ModificationType modType;
      final String modTypeStr = toLowerCase(line.substring(0, colonPos));
      if (modTypeStr.equals("add"))
      {
        modType = ModificationType.ADD;
      }
      else if (modTypeStr.equals("delete"))
      {
        modType = ModificationType.DELETE;
      }
      else if (modTypeStr.equals("replace"))
      {
        modType = ModificationType.REPLACE;
      }
      else if (modTypeStr.equals("increment"))
      {
        modType = ModificationType.INCREMENT;
      }
      else
      {
        throw new LDIFException(ERR_READ_MOD_CR_INVALID_MODTYPE.get(modTypeStr,
                                     firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }

      final String attributeName;
      int length = line.length();
      if (length == (colonPos+1))
      {
        throw new LDIFException(ERR_READ_MOD_CR_MODTYPE_NO_ATTR.get(
                                     firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }
      else if (line.charAt(colonPos+1) == ':')
      {
        int pos = colonPos+2;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        try
        {
          final byte[] dnBytes = Base64.decode(line.substring(pos));
          attributeName = new String(dnBytes, "UTF-8");
        }
        catch (final ParseException pe)
        {
          debugException(pe);
          throw new LDIFException(
               ERR_READ_MOD_CR_MODTYPE_CANNOT_BASE64_DECODE_ATTR.get(
                    firstLineNumber, pe.getMessage()),
               firstLineNumber, true, ldifLines, pe);
        }
        catch (final Exception e)
        {
          debugException(e);
          throw new LDIFException(
               ERR_READ_MOD_CR_MODTYPE_CANNOT_BASE64_DECODE_ATTR.get(
                    firstLineNumber, e),
               firstLineNumber, true, ldifLines, e);
        }
      }
      else
      {
        int pos = colonPos+1;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        attributeName = line.substring(pos);
      }

      if (attributeName.length() == 0)
      {
        throw new LDIFException(ERR_READ_MOD_CR_MODTYPE_NO_ATTR.get(
                                     firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }


      final ArrayList<ASN1OctetString> valueList =
           new ArrayList<ASN1OctetString>(ldifLines.size());
      while (iterator.hasNext())
      {
        line = iterator.next();
        handleTrailingSpaces(line, dn, firstLineNumber, trailingSpaceBehavior);
        if (line.toString().equals("-"))
        {
          break;
        }

        colonPos = line.indexOf(":");
        if (colonPos < 0)
        {
          throw new LDIFException(ERR_READ_NO_ATTR_COLON.get(firstLineNumber),
                                  firstLineNumber, true, ldifLines, null);
        }
        else if (! line.substring(0, colonPos).equalsIgnoreCase(attributeName))
        {
          throw new LDIFException(ERR_READ_MOD_CR_ATTR_MISMATCH.get(
                                       firstLineNumber,
                                       line.substring(0, colonPos),
                                       attributeName),
                                  firstLineNumber, true, ldifLines, null);
        }

        final ASN1OctetString value;
        length = line.length();
        if (length == (colonPos+1))
        {
          value = new ASN1OctetString();
        }
        else if (line.charAt(colonPos+1) == ':')
        {
          int pos = colonPos+2;
          while ((pos < length) && (line.charAt(pos) == ' '))
          {
            pos++;
          }

          try
          {
            value = new ASN1OctetString(Base64.decode(line.substring(pos)));
          }
          catch (final ParseException pe)
          {
            debugException(pe);
            throw new LDIFException(ERR_READ_CANNOT_BASE64_DECODE_ATTR.get(
                 attributeName, firstLineNumber, pe.getMessage()),
                 firstLineNumber, true, ldifLines, pe);
          }
          catch (final Exception e)
          {
            debugException(e);
            throw new LDIFException(ERR_READ_CANNOT_BASE64_DECODE_ATTR.get(
                                         firstLineNumber, e),
                                    firstLineNumber, true, ldifLines, e);
          }
        }
        else
        {
          int pos = colonPos+1;
          while ((pos < length) && (line.charAt(pos) == ' '))
          {
            pos++;
          }

          value = new ASN1OctetString(line.substring(pos));
        }

        valueList.add(value);
      }

      final ASN1OctetString[] values = new ASN1OctetString[valueList.size()];
      valueList.toArray(values);

      if ((modType.intValue() == ModificationType.ADD.intValue()) &&
          (values.length == 0))
      {
        throw new LDIFException(ERR_READ_MOD_CR_NO_ADD_VALUES.get(attributeName,
                                     firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }

      if ((modType.intValue() == ModificationType.INCREMENT.intValue()) &&
          (values.length != 1))
      {
        throw new LDIFException(ERR_READ_MOD_CR_INVALID_INCR_VALUE_COUNT.get(
                                     firstLineNumber, attributeName),
                                firstLineNumber, true, ldifLines, null);
      }

      modList.add(new Modification(modType, attributeName, values));
    }

    final Modification[] mods = new Modification[modList.size()];
    modList.toArray(mods);
    return mods;
  }


  private static LDIFModifyDNChangeRecord parseModifyDNChangeRecord(
       final ArrayList<StringBuilder> ldifLines,
       final Iterator<StringBuilder> iterator, final String dn,
       final TrailingSpaceBehavior trailingSpaceBehavior,
       final long firstLineNumber)
       throws LDIFException
  {
    StringBuilder line = iterator.next();
    handleTrailingSpaces(line, dn, firstLineNumber, trailingSpaceBehavior);
    int colonPos = line.indexOf(":");
    if ((colonPos < 0) ||
        (! line.substring(0, colonPos).equalsIgnoreCase("newrdn")))
    {
      throw new LDIFException(ERR_READ_MODDN_CR_NO_NEWRDN_COLON.get(
                                   firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }

    final String newRDN;
    int length = line.length();
    if (length == (colonPos+1))
    {
      throw new LDIFException(ERR_READ_MODDN_CR_NO_NEWRDN_VALUE.get(
                                   firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }
    else if (line.charAt(colonPos+1) == ':')
    {
      int pos = colonPos+2;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      try
      {
        final byte[] dnBytes = Base64.decode(line.substring(pos));
        newRDN = new String(dnBytes, "UTF-8");
      }
      catch (final ParseException pe)
      {
        debugException(pe);
        throw new LDIFException(
             ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_NEWRDN.get(firstLineNumber,
                                                               pe.getMessage()),
             firstLineNumber, true, ldifLines, pe);
      }
      catch (final Exception e)
      {
        debugException(e);
        throw new LDIFException(
             ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_NEWRDN.get(firstLineNumber,
                                                               e),
             firstLineNumber, true, ldifLines, e);
      }
    }
    else
    {
      int pos = colonPos+1;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      newRDN = line.substring(pos);
    }

    if (newRDN.length() == 0)
    {
      throw new LDIFException(ERR_READ_MODDN_CR_NO_NEWRDN_VALUE.get(
                                   firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }


    if (! iterator.hasNext())
    {
      throw new LDIFException(ERR_READ_MODDN_CR_NO_DELOLDRDN_COLON.get(
                                   firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }

    line = iterator.next();
    handleTrailingSpaces(line, dn, firstLineNumber, trailingSpaceBehavior);
    colonPos = line.indexOf(":");
    if ((colonPos < 0) ||
        (! line.substring(0, colonPos).equalsIgnoreCase("deleteoldrdn")))
    {
      throw new LDIFException(ERR_READ_MODDN_CR_NO_DELOLDRDN_COLON.get(
                                   firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }

    final String deleteOldRDNStr;
    length = line.length();
    if (length == (colonPos+1))
    {
      throw new LDIFException(ERR_READ_MODDN_CR_NO_DELOLDRDN_VALUE.get(
                                   firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }
    else if (line.charAt(colonPos+1) == ':')
    {
      int pos = colonPos+2;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      try
      {
        final byte[] changeTypeBytes = Base64.decode(line.substring(pos));
        deleteOldRDNStr = new String(changeTypeBytes, "UTF-8");
      }
      catch (final ParseException pe)
      {
        debugException(pe);
        throw new LDIFException(
             ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_DELOLDRDN.get(
                  firstLineNumber, pe.getMessage()),
             firstLineNumber, true, ldifLines, pe);
      }
      catch (final Exception e)
      {
        debugException(e);
        throw new LDIFException(
             ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_DELOLDRDN.get(
                  firstLineNumber, e),
             firstLineNumber, true, ldifLines, e);
      }
    }
    else
    {
      int pos = colonPos+1;
      while ((pos < length) && (line.charAt(pos) == ' '))
      {
        pos++;
      }

      deleteOldRDNStr = line.substring(pos);
    }

    final boolean deleteOldRDN;
    if (deleteOldRDNStr.equals("0"))
    {
      deleteOldRDN = false;
    }
    else if (deleteOldRDNStr.equals("1"))
    {
      deleteOldRDN = true;
    }
    else if (deleteOldRDNStr.equalsIgnoreCase("false") ||
             deleteOldRDNStr.equalsIgnoreCase("no"))
    {
      deleteOldRDN = false;
    }
    else if (deleteOldRDNStr.equalsIgnoreCase("true") ||
             deleteOldRDNStr.equalsIgnoreCase("yes"))
    {
      deleteOldRDN = false;
    }
    else
    {
      throw new LDIFException(ERR_READ_MODDN_CR_INVALID_DELOLDRDN.get(
                                   deleteOldRDNStr, firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }


    final String newSuperiorDN;
    if (iterator.hasNext())
    {
      line = iterator.next();
      handleTrailingSpaces(line, dn, firstLineNumber, trailingSpaceBehavior);
      colonPos = line.indexOf(":");
      if ((colonPos < 0) ||
          (! line.substring(0, colonPos).equalsIgnoreCase("newsuperior")))
      {
        throw new LDIFException(ERR_READ_MODDN_CR_NO_NEWSUPERIOR_COLON.get(
                                     firstLineNumber),
                                firstLineNumber, true, ldifLines, null);
      }

      length = line.length();
      if (length == (colonPos+1))
      {
        newSuperiorDN = "";
      }
      else if (line.charAt(colonPos+1) == ':')
      {
        int pos = colonPos+2;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        try
        {
          final byte[] dnBytes = Base64.decode(line.substring(pos));
          newSuperiorDN = new String(dnBytes, "UTF-8");
        }
        catch (final ParseException pe)
        {
          debugException(pe);
          throw new LDIFException(
               ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_NEWSUPERIOR.get(
                    firstLineNumber, pe.getMessage()),
               firstLineNumber, true, ldifLines, pe);
        }
        catch (final Exception e)
        {
          debugException(e);
          throw new LDIFException(
               ERR_READ_MODDN_CR_CANNOT_BASE64_DECODE_NEWSUPERIOR.get(
                    firstLineNumber, e),
               firstLineNumber, true, ldifLines, e);
        }
      }
      else
      {
        int pos = colonPos+1;
        while ((pos < length) && (line.charAt(pos) == ' '))
        {
          pos++;
        }

        newSuperiorDN = line.substring(pos);
      }
    }
    else
    {
      newSuperiorDN = null;
    }


    if (iterator.hasNext())
    {
      throw new LDIFException(ERR_READ_CR_EXTRA_MODDN_DATA.get(firstLineNumber),
                              firstLineNumber, true, ldifLines, null);
    }

    return new LDIFModifyDNChangeRecord(dn, newRDN, deleteOldRDN,
                                        newSuperiorDN);
  }



  private static void handleTrailingSpaces(final StringBuilder buffer,
                           final String dn, final long firstLineNumber,
                           final TrailingSpaceBehavior trailingSpaceBehavior)
          throws LDIFException
  {
    int pos = buffer.length() - 1;
    boolean trailingFound = false;
    while ((pos >= 0) && (buffer.charAt(pos) == ' '))
    {
      trailingFound = true;
      pos--;
    }

    if (trailingFound && (buffer.charAt(pos) != ':'))
    {
      switch (trailingSpaceBehavior)
      {
        case STRIP:
          buffer.setLength(pos+1);
          break;

        case REJECT:
          if (dn == null)
          {
            throw new LDIFException(
                 ERR_READ_ILLEGAL_TRAILING_SPACE_WITHOUT_DN.get(firstLineNumber,
                      buffer.toString()),
                 firstLineNumber, true);
          }
          else
          {
            throw new LDIFException(
                 ERR_READ_ILLEGAL_TRAILING_SPACE_WITH_DN.get(dn,
                      firstLineNumber, buffer.toString()),
                 firstLineNumber, true);
          }

        case RETAIN:
        default:
          break;
      }
    }
  }


  private static final class UnparsedLDIFRecord
  {
    private final ArrayList<StringBuilder> lineList;
    private final long firstLineNumber;
    private final Exception failureCause;
    private final boolean isEOF;
    private final DuplicateValueBehavior duplicateValueBehavior;
    private final Schema schema;
    private final TrailingSpaceBehavior trailingSpaceBehavior;


    private UnparsedLDIFRecord(final ArrayList<StringBuilder> lineList,
                 final DuplicateValueBehavior duplicateValueBehavior,
                 final TrailingSpaceBehavior trailingSpaceBehavior,
                 final Schema schema, final long firstLineNumber)
    {
      this.lineList               = lineList;
      this.firstLineNumber        = firstLineNumber;
      this.duplicateValueBehavior = duplicateValueBehavior;
      this.trailingSpaceBehavior  = trailingSpaceBehavior;
      this.schema                 = schema;

      failureCause = null;
      isEOF =
           (firstLineNumber < 0) || ((lineList != null) && lineList.isEmpty());
    }



    private UnparsedLDIFRecord(final Exception failureCause)
    {
      this.failureCause = failureCause;

      lineList               = null;
      firstLineNumber        = 0;
      duplicateValueBehavior = DuplicateValueBehavior.REJECT;
      trailingSpaceBehavior  = TrailingSpaceBehavior.REJECT;
      schema                 = null;
      isEOF                  = false;
    }



    private ArrayList<StringBuilder> getLineList()
    {
      return lineList;
    }





    private DuplicateValueBehavior getDuplicateValueBehavior()
    {
      return duplicateValueBehavior;
    }




    private TrailingSpaceBehavior getTrailingSpaceBehavior()
    {
      return trailingSpaceBehavior;
    }



    private Schema getSchema()
    {
      return schema;
    }



    private long getFirstLineNumber()
    {
      return firstLineNumber;
    }


    private boolean isEOF()
    {
      return isEOF;
    }



    private Exception getFailureCause()
    {
      return failureCause;
    }
  }


  private final class LineReaderThread
       extends Thread
  {

    private LineReaderThread()
    {
      super("Asynchronous LDIF line reader");
      setDaemon(true);
    }



    @Override()
    public void run()
    {
      try
      {
        boolean stopProcessing = false;
        while (!stopProcessing)
        {
          UnparsedLDIFRecord unparsedRecord = null;
          try
          {
            unparsedRecord = readUnparsedRecord();
          }
          catch (IOException e)
          {
            debugException(e);
            unparsedRecord = new UnparsedLDIFRecord(e);
            stopProcessing = true;
          }
          catch (Exception e)
          {
            debugException(e);
            unparsedRecord = new UnparsedLDIFRecord(e);
          }

          try
          {
            asyncParser.submit(unparsedRecord);
          }
          catch (InterruptedException e)
          {
            debugException(e);
            stopProcessing = true;
          }

          if ((unparsedRecord == null) || (unparsedRecord.isEOF()))
          {
            stopProcessing = true;
          }
        }
      }
      finally
      {
        try
        {
          asyncParser.shutdown();
        }
        catch (InterruptedException e)
        {
          debugException(e);
        }
        finally
        {
          asyncParsingComplete.set(true);
        }
      }
    }
  }


  private final class RecordParser implements Processor<UnparsedLDIFRecord,
                                                        LDIFRecord>
  {
      public LDIFRecord process(final UnparsedLDIFRecord input)
           throws LDIFException
      {
        LDIFRecord record = decodeRecord(input, relativeBasePath);

        if ((record instanceof Entry) && (entryTranslator != null))
        {
          record = entryTranslator.translate((Entry) record,
                                   input.getFirstLineNumber());

          if (record == null)
          {
            record = SKIP_ENTRY;
          }
        }
        return record;
      }
  }
}

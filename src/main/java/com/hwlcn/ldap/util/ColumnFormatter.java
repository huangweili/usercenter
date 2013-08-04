package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;

import java.io.Serializable;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.SimpleDateFormat;
import java.util.Date;

import static com.hwlcn.ldap.util.UtilityMessages.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ColumnFormatter
       implements Serializable
{

  private static final DecimalFormatSymbols DECIMAL_FORMAT_SYMBOLS =
       new DecimalFormatSymbols();
  static
  {
    DECIMAL_FORMAT_SYMBOLS.setInfinity("inf");
    DECIMAL_FORMAT_SYMBOLS.setNaN("NaN");
  }


  private static final OutputFormat DEFAULT_OUTPUT_FORMAT =
       OutputFormat.COLUMNS;

  private static final String DEFAULT_SPACER = " ";


  private static final String DEFAULT_TIMESTAMP_FORMAT = "HH:mm:ss";



  private static final long serialVersionUID = -2524398424293401200L;

  private final boolean includeTimestamp;

  private final FormattableColumn timestampColumn;
  private final FormattableColumn[] columns;

  private final OutputFormat outputFormat;

  private final String spacer;

  private final String timestampFormat;

  private final transient ThreadLocal<DecimalFormat> decimalFormatter;

  private final transient ThreadLocal<SimpleDateFormat> timestampFormatter;



  public ColumnFormatter(final FormattableColumn... columns)
  {
    this(false, null, null, null, columns);
  }



  public ColumnFormatter(final boolean includeTimestamp,
                         final String timestampFormat,
                         final OutputFormat outputFormat, final String spacer,
                         final FormattableColumn... columns)
  {
    Validator.ensureNotNull(columns);
    Validator.ensureTrue(columns.length > 0);

    this.includeTimestamp = includeTimestamp;
    this.columns          = columns;

    decimalFormatter   = new ThreadLocal<DecimalFormat>();
    timestampFormatter = new ThreadLocal<SimpleDateFormat>();

    if (timestampFormat == null)
    {
      this.timestampFormat = DEFAULT_TIMESTAMP_FORMAT;
    }
    else
    {
      this.timestampFormat = timestampFormat;
    }

    if (outputFormat == null)
    {
      this.outputFormat = DEFAULT_OUTPUT_FORMAT;
    }
    else
    {
      this.outputFormat = outputFormat;
    }

    if (spacer == null)
    {
      this.spacer = DEFAULT_SPACER;
    }
    else
    {
      this.spacer = spacer;
    }

    if (includeTimestamp)
    {
      final SimpleDateFormat dateFormat =
           new SimpleDateFormat(this.timestampFormat);
      final String timestamp = dateFormat.format(new Date());
      final String label = INFO_COLUMN_LABEL_TIMESTAMP.get();
      final int width = Math.max(label.length(), timestamp.length());

      timestampFormatter.set(dateFormat);
      timestampColumn =
           new FormattableColumn(width, HorizontalAlignment.LEFT, label);
    }
    else
    {
      timestampColumn = null;
    }
  }


  public boolean includeTimestamps()
  {
    return includeTimestamp;
  }


  public String getTimestampFormatString()
  {
    return timestampFormat;
  }


  public OutputFormat getOutputFormat()
  {
    return outputFormat;
  }


  public String getSpacer()
  {
    return spacer;
  }


  public FormattableColumn[] getColumns()
  {
    final FormattableColumn[] copy = new FormattableColumn[columns.length];
    System.arraycopy(columns, 0, copy, 0, columns.length);
    return copy;
  }



  public String[] getHeaderLines(final boolean includeDashes)
  {
    if (outputFormat == OutputFormat.COLUMNS)
    {
      int maxColumns = 1;
      final String[][] headerLines = new String[columns.length][];
      for (int i=0; i < columns.length; i++)
      {
        headerLines[i] = columns[i].getLabelLines();
        maxColumns = Math.max(maxColumns, headerLines[i].length);
      }

      final StringBuilder[] buffers = new StringBuilder[maxColumns];
      for (int i=0; i < maxColumns; i++)
      {
        final StringBuilder buffer = new StringBuilder();
        buffers[i] = buffer;
        if (includeTimestamp)
        {
          if (i == (maxColumns - 1))
          {
            timestampColumn.format(buffer, timestampColumn.getSingleLabelLine(),
                 outputFormat);
          }
          else
          {
            timestampColumn.format(buffer, "", outputFormat);
          }
        }

        for (int j=0; j < columns.length; j++)
        {
          if (includeTimestamp || (j > 0))
          {
            buffer.append(spacer);
          }

          final int rowNumber = i + headerLines[j].length - maxColumns;
          if (rowNumber < 0)
          {
            columns[j].format(buffer, "", outputFormat);
          }
          else
          {
            columns[j].format(buffer, headerLines[j][rowNumber], outputFormat);
          }
        }
      }

      final String[] returnArray;
      if (includeDashes)
      {
        returnArray = new String[maxColumns+1];
      }
      else
      {
        returnArray = new String[maxColumns];
      }

      for (int i=0; i < maxColumns; i++)
      {
        returnArray[i] = buffers[i].toString();
      }

      if (includeDashes)
      {
        final StringBuilder buffer = new StringBuilder();
        if (timestampColumn != null)
        {
          for (int i=0; i < timestampColumn.getWidth(); i++)
          {
            buffer.append('-');
          }
        }

        for (int i=0; i < columns.length; i++)
        {
          if (includeTimestamp || (i > 0))
          {
            buffer.append(spacer);
          }

          for (int j=0; j < columns[i].getWidth(); j++)
          {
            buffer.append('-');
          }
        }

        returnArray[returnArray.length - 1] = buffer.toString();
      }

      return returnArray;
    }
    else
    {
      final StringBuilder buffer = new StringBuilder();
      if (timestampColumn != null)
      {
        timestampColumn.format(buffer, timestampColumn.getSingleLabelLine(),
             outputFormat);
      }

      for (int i=0; i < columns.length; i++)
      {
        if (includeTimestamp || (i > 0))
        {
          if (outputFormat == OutputFormat.TAB_DELIMITED_TEXT)
          {
            buffer.append('\t');
          }
          else if (outputFormat == OutputFormat.CSV)
          {
            buffer.append(',');
          }
        }

        final FormattableColumn c = columns[i];
        c.format(buffer, c.getSingleLabelLine(), outputFormat);
      }

      return new String[] { buffer.toString() };
    }
  }



  public String formatRow(final Object... columnData)
  {
    final StringBuilder buffer = new StringBuilder();

    if (includeTimestamp)
    {
      SimpleDateFormat dateFormat = timestampFormatter.get();
      if (dateFormat == null)
      {
        dateFormat = new SimpleDateFormat(timestampFormat);
        timestampFormatter.set(dateFormat);
      }

      timestampColumn.format(buffer, dateFormat.format(new Date()),
           outputFormat);
    }

    for (int i=0; i < columns.length; i++)
    {
      if (includeTimestamp || (i > 0))
      {
        switch (outputFormat)
        {
          case TAB_DELIMITED_TEXT:
            buffer.append('\t');
            break;
          case CSV:
            buffer.append(',');
            break;
          case COLUMNS:
            buffer.append(spacer);
            break;
        }
      }

      if (i >= columnData.length)
      {
        columns[i].format(buffer, "", outputFormat);
      }
      else
      {
        columns[i].format(buffer, toString(columnData[i]), outputFormat);
      }
    }

    return buffer.toString();
  }




  private String toString(final Object o)
  {
    if (o == null)
    {
      return "";
    }

    if ((o instanceof Float) || (o instanceof Double))
    {
      DecimalFormat f = decimalFormatter.get();
      if (f == null)
      {
        f = new DecimalFormat("0.000", DECIMAL_FORMAT_SYMBOLS);
        decimalFormatter.set(f);
      }

      final double d;
      if (o instanceof Float)
      {
        d = ((Float) o).doubleValue();
      }
      else
      {
        d = ((Double) o);
      }

      return f.format(d);
    }

    return String.valueOf(o);
  }
}

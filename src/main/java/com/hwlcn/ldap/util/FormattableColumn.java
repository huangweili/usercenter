
package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;

import java.io.Serializable;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FormattableColumn
       implements Serializable
{

  private static final long serialVersionUID = -67186391702592665L;

  private final HorizontalAlignment alignment;

  private final int width;
  private final String[] labelLines;



  public FormattableColumn(final int width, final HorizontalAlignment alignment,
                           final String... labelLines)
  {
    Validator.ensureTrue(width >= 1);
    Validator.ensureNotNull(alignment, labelLines);

    this.width      = width;
    this.alignment  = alignment;
    this.labelLines = labelLines;
  }



  public int getWidth()
  {
    return width;
  }



  public HorizontalAlignment getAlignment()
  {
    return alignment;
  }



  public String[] getLabelLines()
  {
    return labelLines;
  }



  public String getSingleLabelLine()
  {
    switch (labelLines.length)
    {
      case 0:
        return "";
      case 1:
        return labelLines[0];
      default:
        final StringBuilder buffer = new StringBuilder();
        buffer.append(labelLines[0]);
        for (int i=1; i < labelLines.length; i++)
        {
          buffer.append(' ');
          buffer.append(labelLines[i]);
        }
        return buffer.toString();
    }
  }



  public void format(final StringBuilder buffer, final String text,
                     final OutputFormat format)
  {
    switch (format)
    {
      case TAB_DELIMITED_TEXT:
        buffer.append(text);
        break;

      case CSV:
        boolean quotesNeeded = false;
        final int length = text.length();
        final int startPos = buffer.length();
        for (int i=0; i < length; i++)
        {
          final char c = text.charAt(i);
          if (c == ',')
          {
            buffer.append(',');
            quotesNeeded = true;
          }
          else if (c == '"')
          {
            buffer.append("\"\"");
            quotesNeeded = true;
          }
          else if ((c >= ' ') && (c <= '~'))
          {
            buffer.append(c);
          }
        }

        if (quotesNeeded)
        {
          buffer.insert(startPos, '"');
          buffer.append('"');
        }
        break;

      case COLUMNS:
        alignment.format(buffer, text, width);
        break;
    }
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
    buffer.append("FormattableColumn(width=");
    buffer.append(width);
    buffer.append(", alignment=");
    buffer.append(alignment);
    buffer.append(", label=\"");
    buffer.append(getSingleLabelLine());
    buffer.append("\")");
  }
}

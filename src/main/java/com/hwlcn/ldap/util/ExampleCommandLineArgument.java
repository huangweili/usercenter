
package com.hwlcn.ldap.util;



import com.hwlcn.core.annotation.ThreadSafety;

import java.util.List;
import java.util.ArrayList;
import java.io.Serializable;

import static com.hwlcn.ldap.util.Validator.*;



@ThreadSafety(level = ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ExampleCommandLineArgument implements Serializable
{
  private static final long serialVersionUID = 2468880329239320437L;


  private final String rawForm;


  private final String unixForm;


  private final String windowsForm;



  private ExampleCommandLineArgument(final String rawForm,
                                     final String unixForm,
                                     final String windowsForm)
  {
    this.rawForm = rawForm;
    this.unixForm     = unixForm;
    this.windowsForm  = windowsForm;
  }




  public String getRawForm()
  {
    return rawForm;
  }





  public String getUnixForm()
  {
    return unixForm;
  }



  public String getWindowsForm()
  {
    return windowsForm;
  }




  public String getLocalForm()
  {
    if (StaticUtils.isWindows())
    {
      return getWindowsForm();
    }
    else
    {
      return getUnixForm();
    }
  }



  public static ExampleCommandLineArgument getCleanArgument(
                                             final String argument)
  {
    return new ExampleCommandLineArgument(argument,
                                          getUnixForm(argument),
                                          getWindowsForm(argument));
  }


  public static String getUnixForm(final String argument)
  {
    ensureNotNull(argument);

    final QuotingRequirements requirements = getRequiredUnixQuoting(argument);

    String quotedArgument = argument;
    if (requirements.requiresSingleQuotesOnUnix())
    {
      if (requirements.includesSingleQuote())
      {

        quotedArgument = quotedArgument.replace("'", "'\"'\"'");
      }
      quotedArgument = "'" + quotedArgument + "'";
    }
    else if (requirements.requiresDoubleQuotesOnUnix())
    {
      quotedArgument = "\"" + quotedArgument + "\"";
    }

    return quotedArgument;
  }


  public static String getWindowsForm(final String argument)
  {
    ensureNotNull(argument);

    final QuotingRequirements requirements = getRequiredUnixQuoting(argument);

    String quotedArgument = argument;


    if (requirements.requiresSingleQuotesOnUnix() ||
        requirements.requiresDoubleQuotesOnUnix())
    {
      if (requirements.includesDoubleQuote())
      {
        quotedArgument = quotedArgument.replace("\"", "\"\"");
      }
      quotedArgument = "\"" + quotedArgument + "\"";
    }

    return quotedArgument;
  }





  public static List<String> parseExampleCommandLine(
                                 final String exampleCommandLine)
  {
    ensureNotNull(exampleCommandLine);

    boolean inDoubleQuote = false;
    boolean inSingleQuote = false;

    List<String> args = new ArrayList<String>();

    StringBuilder currentArg = new StringBuilder();
    boolean inArg = false;
    for (int i = 0; i < exampleCommandLine.length(); i++) {
      Character c = exampleCommandLine.charAt(i);

      Character nextChar = null;
      if (i < (exampleCommandLine.length() - 1))
      {
        nextChar = exampleCommandLine.charAt(i + 1);
      }

      if (inDoubleQuote)
      {
        if (c == '"')
        {
          if ((nextChar != null) && (nextChar == '"'))
          {
            currentArg.append('\"');
            i++;
          }
          else
          {
            inDoubleQuote = false;
          }
        }
        else
        {
          currentArg.append(c);
        }
      }
      else if (inSingleQuote)
      {
        if (c == '\'')
        {
          inSingleQuote = false;
        }
        else
        {
          currentArg.append(c);
        }
      }
      else if (c == '"')
      {
        inDoubleQuote = true;
        inArg = true;
      }
      else if (c == '\'')
      {
        inSingleQuote = true;
        inArg = true;
      }
      else if (c == ' ')
      {
        if (inArg)
        {
          args.add(currentArg.toString());
          currentArg = new StringBuilder();
          inArg = false;
        }
      }
      else
      {
        currentArg.append(c);
        inArg = true;
      }
    }

    if (inArg)
    {
      args.add(currentArg.toString());
    }

    return args;
  }


  private static QuotingRequirements getRequiredUnixQuoting(
                                         final String argument)
  {
    boolean requiresDoubleQuotes = false;
    boolean requiresSingleQuotes = false;
    boolean includesDoubleQuote = false;
    boolean includesSingleQuote = false;

    if (argument.length() == 0)
    {
      requiresDoubleQuotes = true;
    }

    for (int i=0; i < argument.length(); i++)
    {
      final char c = argument.charAt(i);
      switch (c)
      {
        case '"':
          includesDoubleQuote = true;
          requiresSingleQuotes = true;
          break;
        case '\\':
        case '!':
        case '`':
        case '$':
        case '@':
        case '*':
          requiresSingleQuotes = true;
          break;

        case '\'':
          includesSingleQuote = true;
          requiresDoubleQuotes = true;
          break;
        case ' ':
        case '|':
        case '&':
        case ';':
        case '(':
        case ')':
        case '<':
        case '>':
          requiresDoubleQuotes = true;
          break;

        case ',':
        case '=':
        case '-':
        case '_':
        case ':':
        case '.':
        case '/':
          break;

        default:
          if (((c >= 'a') && (c <= 'z')) ||
              ((c >= 'A') && (c <= 'Z')) ||
              ((c >= '0') && (c <= '9')))
          {
          }
          else
          {
            requiresDoubleQuotes = true;
          }
      }
    }

    if (requiresSingleQuotes)
    {
      requiresDoubleQuotes = false;
    }

    return new QuotingRequirements(requiresSingleQuotes, requiresDoubleQuotes,
                                   includesSingleQuote, includesDoubleQuote);
  }
}

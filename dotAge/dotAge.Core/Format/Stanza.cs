using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DotAge.Core.Format
{
    /// <summary>
    /// Represents a recipient stanza in the age file format.
    /// </summary>
    public class Stanza
    {
        // The type of the stanza (e.g., "X25519", "scrypt")
        public string Type { get; }

        // The arguments of the stanza
        public List<string> Arguments { get; } = new List<string>();

        // The body of the stanza
        public List<string> Body { get; } = new List<string>();

        /// <summary>
        /// Creates a new stanza with the specified type, arguments, and body.
        /// </summary>
        /// <param name="type">The type of the stanza.</param>
        /// <param name="arguments">The arguments of the stanza.</param>
        /// <param name="body">The body of the stanza.</param>
        public Stanza(string type, IEnumerable<string>? arguments = null, IEnumerable<string>? body = null)
        {
            if (string.IsNullOrEmpty(type))
                throw new ArgumentException("Stanza type cannot be null or empty", nameof(type));

            Type = type;

            if (arguments != null)
            {
                // Convert to list to ensure we're working with a stable collection
                var argList = arguments.ToList();
                foreach (var arg in argList)
                {
                    Arguments.Add(arg);
                }
            }

            if (body != null)
            {
                // Convert to list to ensure we're working with a stable collection
                var bodyList = body.ToList();
                // Add each body line individually to ensure they're all added
                foreach (var line in bodyList)
                {
                    Body.Add(line);
                }
            }
        }

        /// <summary>
        /// Creates a new stanza by parsing the specified raw text lines.
        /// </summary>
        /// <param name="type">The type of the stanza.</param>
        /// <param name="rawTextLines">The raw text lines to parse.</param>
        /// <returns>A new stanza.</returns>
        public static Stanza Parse(string type, IEnumerable<string> rawTextLines)
        {
            if (string.IsNullOrEmpty(type))
                throw new ArgumentException("Stanza type cannot be null or empty", nameof(type));

            if (rawTextLines == null)
                return new Stanza(type);

            var linesList = rawTextLines.ToList();
            var arguments = new List<string>();
            var body = new List<string>();

            // The first line contains the arguments
            if (linesList.Count > 0)
            {
                var firstLine = linesList[0];

                // Check if the first line is the type (which would be the case if this is a stanza header line)
                if (firstLine.StartsWith(type))
                {
                    // Extract arguments from the first line after the type
                    var argsString = firstLine.Substring(type.Length).Trim();
                    var args = argsString.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    arguments.AddRange(args);
                }
                else
                {
                    // If the first line doesn't start with the type, it might contain multiple arguments
                    var args = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    arguments.AddRange(args);
                }

                // The rest of the lines are the body
                if (linesList.Count > 1)
                {
                    body.AddRange(linesList.Skip(1));
                }
            }

            return new Stanza(type, arguments, body);
        }

        /// <summary>
        /// Encodes the stanza as a string.
        /// </summary>
        /// <returns>The encoded stanza as a string.</returns>
        public string Encode()
        {
            var sb = new StringBuilder();

            // Add the stanza type line
            sb.Append("-> ");
            sb.Append(Type);

            // Add the arguments
            if (Arguments.Count > 0)
            {
                // Add arguments on the same line for all types
                sb.Append(" ");
                sb.Append(string.Join(" ", Arguments));
            }

            // Add the line ending after type and arguments
            sb.Append("\r\n");

            // Add the body
            foreach (var line in Body)
            {
                sb.Append(line);
                sb.Append("\r\n");
            }

            return sb.ToString();
        }
    }
}

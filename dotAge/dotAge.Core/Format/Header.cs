using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace DotAge.Core.Format
{
    /// <summary>
    /// Represents the header of an age-encrypted file.
    /// </summary>
    public class Header
    {
        // The age file format version
        public const string Version = "age-encryption.org/v1";

        // The list of recipient stanzas
        public List<Stanza> Stanzas { get; } = new List<Stanza>();

        // The MAC (Message Authentication Code) of the header
        public byte[]? Mac { get; set; }

        /// <summary>
        /// Creates a new header with the specified recipient stanzas.
        /// </summary>
        /// <param name="stanzas">The recipient stanzas.</param>
        public Header(IEnumerable<Stanza>? stanzas = null)
        {
            if (stanzas != null)
            {
                Stanzas.AddRange(stanzas);
            }
        }

        /// <summary>
        /// Encodes the header as a string.
        /// </summary>
        /// <returns>The encoded header as a string.</returns>
        public string Encode()
        {
            var sb = new StringBuilder();

            // Add the version line
            sb.Append(Version);
            sb.Append("\r\n");

            // Add the recipient stanzas
            foreach (var stanza in Stanzas)
            {
                sb.Append(stanza.Encode());
            }

            // Add the MAC line if available
            if (Mac != null)
            {
                sb.Append($"---{Convert.ToBase64String(Mac)}");
                sb.Append("\r\n");
            }

            return sb.ToString();
        }

        /// <summary>
        /// Decodes a header from a string.
        /// </summary>
        /// <param name="encoded">The encoded header as a string.</param>
        /// <returns>The decoded header.</returns>
        public static Header Decode(string encoded)
        {
            if (string.IsNullOrEmpty(encoded))
                throw new ArgumentException("Encoded header cannot be null or empty", nameof(encoded));

            var lines = encoded.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);

            if (lines.Length < 1)
                throw new FormatException("Invalid header format: empty header");

            if (lines[0] != Version)
                throw new FormatException($"Invalid header format: expected version {Version}, got {lines[0]}");

            var header = new Header();

            for (var i = 1; i < lines.Length; i++)
            {
                var line = lines[i];

                // Skip empty lines
                if (string.IsNullOrEmpty(line))
                    continue;

                // Check if this is a MAC line
                if (line.StartsWith("---"))
                {
                    var macBase64 = line.Substring(3);
                    header.Mac = Convert.FromBase64String(macBase64);
                    break;
                }

                // Check if this is a new stanza
                if (line.StartsWith("->"))
                {
                    // Parse the stanza type and arguments
                    var stanzaContent = line.Substring(2).Trim();
                    var parts = stanzaContent.Split(' ', 2);
                    var stanzaType = parts[0];
                    var stanzaArgs = parts.Length > 1 ? parts[1] : string.Empty;

                    // Create a new stanza with the type and arguments
                    var stanza = new Stanza(stanzaType);

                    // Add the arguments if there are any
                    if (!string.IsNullOrEmpty(stanzaArgs))
                    {
                        var args = stanzaArgs.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                        foreach (var arg in args)
                        {
                            stanza.Arguments.Add(arg);
                        }
                    }

                    // Read the body lines until the next stanza or MAC line
                    var bodyLines = new List<string>();
                    while (i + 1 < lines.Length && !lines[i + 1].StartsWith("->") && !lines[i + 1].StartsWith("---"))
                    {
                        i++;
                        if (!string.IsNullOrEmpty(lines[i]))
                        {
                            bodyLines.Add(lines[i]);
                        }
                    }

                    // Add the body lines to the stanza
                    foreach (var bodyLine in bodyLines)
                    {
                        stanza.Body.Add(bodyLine);
                    }

                    // Add the stanza to the header
                    header.Stanzas.Add(stanza);
                }
            }

            return header;
        }
    }
}

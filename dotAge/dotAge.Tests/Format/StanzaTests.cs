using System;
using System.Collections.Generic;
using System.Linq;
using DotAge.Core.Format;
using Xunit;

namespace DotAge.Tests.Format
{
    public class StanzaTests
    {
        [Fact]
        public void Constructor_ShouldCreateValidStanza_WhenGivenTypeOnly()
        {
            // Arrange
            var type = "X25519";

            // Act
            var stanza = new Stanza(type);

            // Assert
            Assert.Equal(type, stanza.Type);
            Assert.Empty(stanza.Arguments);
            Assert.Empty(stanza.Body);
        }

        [Fact]
        public void Constructor_ShouldCreateValidStanza_WhenGivenTypeAndArguments()
        {
            // Arrange
            var type = "X25519";
            var arguments = new List<string> { "arg1", "arg2" };

            // Act
            var stanza = new Stanza(type, arguments);

            // Assert
            Assert.Equal(type, stanza.Type);
            Assert.Equal(arguments, stanza.Arguments);
            Assert.Empty(stanza.Body);
        }

        [Fact]
        public void Constructor_ShouldCreateValidStanza_WhenGivenTypeArgumentsAndBody()
        {
            // Arrange
            var type = "X25519";
            var arguments = new List<string> { "arg1", "arg2" };
            var body = new List<string> { "line1", "line2" };

            // Act
            var stanza = new Stanza(type, arguments, body);

            // Assert
            Assert.Equal(type, stanza.Type);
            Assert.Equal(arguments, stanza.Arguments);
            Assert.Equal(body, stanza.Body);
        }

        [Fact]
        public void Parse_ShouldCreateValidStanza_WhenGivenTypeAndLines()
        {
            // Arrange
            var type = "X25519";
            var lines = new List<string> { "arg1 arg2", "line1", "line2" };

            // Act
            var stanza = Stanza.Parse(type, lines);

            // Assert
            Assert.Equal(type, stanza.Type);
            Assert.Equal(new List<string> { "arg1", "arg2" }, stanza.Arguments);
            Assert.Equal(new List<string> { "line1", "line2" }, stanza.Body);
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenGivenNullType()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() => new Stanza(null));
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenGivenEmptyType()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() => new Stanza(""));
        }

        [Fact]
        public void Encode_ShouldReturnValidString_WhenStanzaHasNoArgumentsOrBody()
        {
            // Arrange
            var type = "X25519";
            var stanza = new Stanza(type);

            // Act
            var encoded = stanza.Encode();

            // Assert
            Assert.Equal($"-> {type}\r\n", encoded);
        }

        [Fact]
        public void Encode_ShouldReturnValidString_WhenStanzaHasArguments()
        {
            // Arrange
            var type = "X25519";
            var arguments = new List<string> { "arg1", "arg2" };

            var stanza = new Stanza(type, arguments);

            // Act
            var encoded = stanza.Encode();

            // Assert
            Assert.Equal($"-> {type} arg1 arg2\r\n", encoded);
        }

        [Fact]
        public void Encode_ShouldReturnValidString_WhenStanzaHasArgumentsAndBody()
        {
            // Arrange
            var type = "X25519";
            var arguments = new List<string> { "arg1", "arg2" };
            var body = new List<string> { "line1", "line2" };
            var stanza = new Stanza(type, arguments, body);

            // Act
            var encoded = stanza.Encode();

            // Assert
            Assert.Equal($"-> {type} arg1 arg2\r\nline1\r\nline2\r\n", encoded);
        }
    }
}

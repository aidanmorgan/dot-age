using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dotAge.Core.Format;
using Xunit;

namespace dotAge.Tests.Format
{
    public class HeaderTests
    {
        [Fact]
        public void Constructor_ShouldCreateValidHeader_WhenGivenNoStanzas()
        {
            // Act
            var header = new Header();
            
            // Assert
            Assert.Empty(header.Stanzas);
            Assert.Null(header.Mac);
        }
        
        [Fact]
        public void Constructor_ShouldCreateValidHeader_WhenGivenStanzas()
        {
            // Arrange
            var stanzas = new List<Stanza>
            {
                new Stanza("X25519", new List<string> { "arg1" }),
                new Stanza("scrypt", new List<string> { "arg2" })
            };
            
            // Act
            var header = new Header(stanzas);
            
            // Assert
            Assert.Equal(stanzas, header.Stanzas);
            Assert.Null(header.Mac);
        }
        
        [Fact]
        public void Encode_ShouldReturnValidString_WhenHeaderHasNoStanzasOrMac()
        {
            // Arrange
            var header = new Header();
            
            // Act
            var encoded = header.Encode();
            
            // Assert
            Assert.Equal($"{Header.Version}\r\n", encoded);
        }
        
        [Fact]
        public void Encode_ShouldReturnValidString_WhenHeaderHasStanzas()
        {
            // Arrange
            var stanzas = new List<Stanza>
            {
                new Stanza("X25519", new List<string> { "arg1" }),
                new Stanza("scrypt", new List<string> { "arg2" })
            };
            var header = new Header(stanzas);
            
            // Act
            var encoded = header.Encode();
            
            // Assert
            var expected = $"{Header.Version}\r\n-> X25519 arg1\r\n-> scrypt arg2\r\n";
            Assert.Equal(expected, encoded);
        }
        
        [Fact]
        public void Encode_ShouldReturnValidString_WhenHeaderHasStanzasAndMac()
        {
            // Arrange
            var stanzas = new List<Stanza>
            {
                new Stanza("X25519", new List<string> { "arg1" }),
                new Stanza("scrypt", new List<string> { "arg2" })
            };
            var header = new Header(stanzas);
            header.Mac = new byte[] { 0x01, 0x02, 0x03 };
            
            // Act
            var encoded = header.Encode();
            
            // Assert
            var expected = $"{Header.Version}\r\n-> X25519 arg1\r\n-> scrypt arg2\r\n---{Convert.ToBase64String(header.Mac)}\r\n";
            Assert.Equal(expected, encoded);
        }
        
        [Fact]
        public void Decode_ShouldReturnValidHeader_WhenGivenValidEncodedHeader()
        {
            // Arrange
            var encoded = $"{Header.Version}\r\n-> X25519 arg1\r\n-> scrypt arg2\r\n---AQID\r\n";
            
            // Act
            var header = Header.Decode(encoded);
            
            // Assert
            Assert.Equal(2, header.Stanzas.Count);
            Assert.Equal("X25519", header.Stanzas[0].Type);
            Assert.Equal(new List<string> { "arg1" }, header.Stanzas[0].Arguments);
            Assert.Equal("scrypt", header.Stanzas[1].Type);
            Assert.Equal(new List<string> { "arg2" }, header.Stanzas[1].Arguments);
            Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, header.Mac);
        }
        
        [Fact]
        public void Decode_ShouldReturnValidHeader_WhenGivenValidEncodedHeaderWithoutMac()
        {
            // Arrange
            var encoded = $"{Header.Version}\r\n-> X25519 arg1\r\n-> scrypt arg2\r\n";
            
            // Act
            var header = Header.Decode(encoded);
            
            // Assert
            Assert.Equal(2, header.Stanzas.Count);
            Assert.Equal("X25519", header.Stanzas[0].Type);
            Assert.Equal(new List<string> { "arg1" }, header.Stanzas[0].Arguments);
            Assert.Equal("scrypt", header.Stanzas[1].Type);
            Assert.Equal(new List<string> { "arg2" }, header.Stanzas[1].Arguments);
            Assert.Null(header.Mac);
        }
        
        [Fact]
        public void Decode_ShouldThrowException_WhenGivenNullEncodedHeader()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() => Header.Decode(null));
        }
        
        [Fact]
        public void Decode_ShouldThrowException_WhenGivenEmptyEncodedHeader()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() => Header.Decode(""));
        }
        
        [Fact]
        public void Decode_ShouldThrowException_WhenGivenInvalidVersion()
        {
            // Arrange
            var encoded = "invalid-version\r\n-> X25519 arg1\r\n";
            
            // Act & Assert
            Assert.Throws<FormatException>(() => Header.Decode(encoded));
        }
    }
}
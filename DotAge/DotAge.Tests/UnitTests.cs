using System.Text;
using DotAge.Core;
using DotAge.Core.Crypto;
using DotAge.Core.Exceptions;
using DotAge.Core.Format;
using DotAge.Core.Recipients;
using DotAge.Core.Utils;

namespace DotAge.Tests;

public class UnitTests
{
    [Fact]
    public void X25519_KeyGeneration_ProducesValidKeys()
    {
        var (privateKey, publicKey) = X25519.GenerateKeyPair();

        Assert.NotNull(privateKey);
        Assert.NotNull(publicKey);
        Assert.Equal(32, privateKey.Length);
        Assert.Equal(32, publicKey.Length);

        // Verify the public key can be derived from the private key
        var derivedPublicKey = X25519.GetPublicKeyFromPrivateKey(privateKey);
        Assert.Equal(publicKey, derivedPublicKey);
    }

    [Fact]
    public void X25519_KeyAgreement_WorksWithGeneratedKeys()
    {
        var (alicePrivate, alicePublic) = X25519.GenerateKeyPair();
        var (bobPrivate, bobPublic) = X25519.GenerateKeyPair();

        var aliceShared = X25519.KeyAgreement(alicePrivate, bobPublic);
        var bobShared = X25519.KeyAgreement(bobPrivate, alicePublic);

        Assert.NotNull(aliceShared);
        Assert.NotNull(bobShared);
        Assert.Equal(32, aliceShared.Length);
        Assert.Equal(32, bobShared.Length);
        Assert.Equal(aliceShared, bobShared);
    }

    [Fact]
    public void ChaCha20Poly1305_EncryptionDecryption_Works()
    {
        var key = RandomUtils.GenerateRandomBytes(32);
        var nonce = RandomUtils.GenerateRandomBytes(12);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

        var ciphertext = ChaCha20Poly1305.Encrypt(key, nonce, plaintext);
        var decrypted = ChaCha20Poly1305.Decrypt(key, nonce, ciphertext);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void ChaCha20Poly1305_Authentication_FailsWithWrongKey()
    {
        var key1 = RandomUtils.GenerateRandomBytes(32);
        var key2 = RandomUtils.GenerateRandomBytes(32);
        var nonce = RandomUtils.GenerateRandomBytes(12);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

        var ciphertext = ChaCha20Poly1305.Encrypt(key1, nonce, plaintext);

        Assert.Throws<AgeCryptoException>(() =>
            ChaCha20Poly1305.Decrypt(key2, nonce, ciphertext));
    }

    [Fact]
    public void Scrypt_KeyDerivation_ProducesConsistentResults()
    {
        var password = "test-password";
        var salt = RandomUtils.GenerateRandomBytes(16);
        var key1 = Scrypt.DeriveKey(password, salt, 15, 8);
        var key2 = Scrypt.DeriveKey(password, salt, 15, 8);

        Assert.Equal(key1, key2);
    }

    [Fact]
    public void Base64Utils_EncodingDecoding_Works()
    {
        var data = Encoding.UTF8.GetBytes("Hello, World!");
        var encoded = Base64Utils.EncodeToString(data);
        var decoded = Base64Utils.DecodeString(encoded);

        Assert.Equal(data, decoded);
    }

    [Fact]
    public void Bech32_EncodingDecoding_Works()
    {
        var data = Encoding.UTF8.GetBytes("test data");
        var encoded = Bech32.Encode("age", data);
        var (hrp, decoded) = Bech32.Decode(encoded);

        Assert.Equal("age", hrp);
        Assert.Equal(data, decoded);
    }

    [Fact]
    public void Header_Parsing_Works()
    {
        // Valid stanza: 16-byte base64 body ("AAAAAAAAAAAAAAAAAAAAAA==")
        var headerText = "age-encryption.org/v1\n-> X25519 test-arg\nAAAAAAAAAAAAAAAAAAAAAA==\n";
        var header = Header.Decode(headerText);

        Assert.Equal("age-encryption.org/v1", Header.Version);
        Assert.Single(header.Stanzas);
        Assert.Equal("X25519", header.Stanzas[0].Type);
    }

    [Fact]
    public void Header_Serialization_Works()
    {
        var stanza = new Stanza("X25519", new[] { "test-arg" }, Convert.FromBase64String("dGVzdA=="));
        var header = new Header(new[] { stanza });

        var serialized = header.Encode();
        var parsed = Header.Decode(serialized);

        Assert.Equal(Header.Version, Header.Version);
        Assert.Equal(header.Stanzas[0].Type, parsed.Stanzas[0].Type);
    }

    [Fact]
    public void X25519Recipient_EncryptionDecryption_Works()
    {
        var (privateKey, publicKey) = X25519.GenerateKeyPair();
        var recipient = new X25519Recipient(publicKey);
        var fileKey = RandomUtils.GenerateRandomBytes(16);

        var stanza = recipient.CreateStanza(fileKey);
        var identity = new X25519Recipient(privateKey, publicKey);
        var unwrappedKey = identity.UnwrapKey(stanza);

        Assert.Equal(fileKey, unwrappedKey);
    }

    [Fact]
    public void ScryptRecipient_EncryptionDecryption_Works()
    {
        var password = "test-password";
        var recipient = new ScryptRecipient(password);
        var fileKey = RandomUtils.GenerateRandomBytes(16);

        var stanza = recipient.CreateStanza(fileKey);
        var identity = new ScryptIdentity(password);
        var unwrappedKey = identity.UnwrapKey(stanza);

        Assert.Equal(fileKey, unwrappedKey);
    }

    [Fact]
    public void Age_EncryptionDecryption_Works()
    {
        var (privateKey, publicKey) = X25519.GenerateKeyPair();
        var age = new Age();
        age.AddRecipient(new X25519Recipient(publicKey));

        var plaintext = "Hello, World!";
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

        var ciphertext = age.Encrypt(plaintextBytes);
        var decryptAge = new Age();
        decryptAge.AddIdentity(new X25519Recipient(privateKey, publicKey));
        var decryptedBytes = decryptAge.Decrypt(ciphertext);

        var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
        Assert.Equal(plaintext, decryptedText);
    }

    [Fact]
    public void RandomUtils_GeneratesRandomBytes()
    {
        var bytes1 = RandomUtils.GenerateRandomBytes(32);
        var bytes2 = RandomUtils.GenerateRandomBytes(32);

        Assert.Equal(32, bytes1.Length);
        Assert.Equal(32, bytes2.Length);
        Assert.NotEqual(bytes1, bytes2);
    }

    [Fact]
    public void Hkdf_DerivesKeys()
    {
        var salt = RandomUtils.GenerateRandomBytes(32);
        var ikm = RandomUtils.GenerateRandomBytes(32);
        var info = "test-info";

        var key1 = Hkdf.DeriveKey(salt, ikm, info, 32);
        var key2 = Hkdf.DeriveKey(salt, ikm, info, 32);

        Assert.Equal(32, key1.Length);
        Assert.Equal(key1, key2);
    }

    [Fact]
    public void Age_ThrowsOnInvalidKey()
    {
        var age = new Age();

        Assert.Throws<AgeKeyException>(() =>
            age.AddRecipient(new X25519Recipient(new byte[31]))); // Wrong key size
    }

    [Fact]
    public void Age_ThrowsOnInvalidFile()
    {
        var age = new Age();
        var invalidData = new byte[] { 0x00, 0x01, 0x02, 0x03 };
        age.AddIdentity(new X25519Recipient(RandomUtils.GenerateRandomBytes(32), RandomUtils.GenerateRandomBytes(32)));
        Assert.Throws<AgeFormatException>(() =>
            age.Decrypt(invalidData));
    }
}
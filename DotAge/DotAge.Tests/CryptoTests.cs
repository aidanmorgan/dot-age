using System.Text;
using DotAge.Core.Crypto;
using DotAge.Core.Exceptions;
using DotAge.Core.Recipients;
using DotAge.Core.Utils;

namespace DotAge.Tests;

/// <summary>
///     Tests for cryptographic operations including X25519, ChaCha20Poly1305, Scrypt, and HKDF.
/// </summary>
public class CryptoTests
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
    public void ChaCha20Poly1305_InvalidKeySize_ThrowsException()
    {
        var nonce = RandomUtils.GenerateRandomBytes(12);
        var plaintext = Encoding.UTF8.GetBytes("test");
        Assert.Throws<AgeCryptoException>(() =>
            ChaCha20Poly1305.Encrypt(new byte[31], nonce, plaintext));
        Assert.Throws<AgeCryptoException>(() =>
            ChaCha20Poly1305.Encrypt(new byte[33], nonce, plaintext));
    }

    [Fact]
    public void ChaCha20Poly1305_InvalidNonceSize_ThrowsException()
    {
        var key = RandomUtils.GenerateRandomBytes(32);
        var plaintext = Encoding.UTF8.GetBytes("test");
        Assert.Throws<AgeCryptoException>(() =>
            ChaCha20Poly1305.Encrypt(key, new byte[11], plaintext));
        Assert.Throws<AgeCryptoException>(() =>
            ChaCha20Poly1305.Encrypt(key, new byte[13], plaintext));
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
    public void Scrypt_InvalidParameters_ThrowsException()
    {
        var password = "test";
        var salt = RandomUtils.GenerateRandomBytes(16);
        Assert.Throws<AgeCryptoException>(() =>
            Scrypt.DeriveKey(password, salt, 0, 8));
        Assert.Throws<AgeCryptoException>(() =>
            Scrypt.DeriveKey(password, salt, 31, 0));
        Assert.Throws<AgeCryptoException>(() =>
            Scrypt.DeriveKey(password, salt, 31, 8, 0));
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
    public void Hkdf_InvalidParameters_ThrowsException()
    {
        var salt = RandomUtils.GenerateRandomBytes(32);
        var ikm = RandomUtils.GenerateRandomBytes(32);
        var info = "test";
        Assert.Throws<ArgumentException>(() =>
            Hkdf.DeriveKey(salt, ikm, info, 0));
        Assert.Throws<ArgumentException>(() =>
            Hkdf.DeriveKey(salt, ikm, info, -1));
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
    public void X25519Recipient_InvalidKeySize_ThrowsException()
    {
        Assert.Throws<AgeKeyException>(() => new X25519Recipient(new byte[31]));
        Assert.Throws<AgeKeyException>(() => new X25519Recipient(new byte[33]));
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
    public void ScryptRecipient_EmptyPassword_ThrowsException()
    {
        Assert.Throws<AgeKeyException>(() => new ScryptRecipient(""));
        Assert.Throws<AgeKeyException>(() => new ScryptRecipient(null!));
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
}
using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace dotAge.Core.Crypto
{
    /// <summary>
    /// Provides Scrypt key derivation functionality.
    /// </summary>
    public static class Scrypt
    {
        // Default parameters for Scrypt
        public const int DefaultN = 32768; // CPU/memory cost parameter
        public const int DefaultR = 8;     // Block size parameter
        public const int DefaultP = 1;     // Parallelization parameter

        // Default salt size in bytes
        public const int DefaultSaltSize = 16;

        // Default key size in bytes
        public const int DefaultKeySize = 32;

        /// <summary>
        /// Derives a key using the Scrypt key derivation function.
        /// </summary>
        /// <param name="password">The password as a string.</param>
        /// <param name="salt">The salt as a byte array.</param>
        /// <param name="n">The CPU/memory cost parameter.</param>
        /// <param name="r">The block size parameter.</param>
        /// <param name="p">The parallelization parameter.</param>
        /// <param name="keyLength">The length of the derived key in bytes.</param>
        /// <returns>The derived key as a byte array.</returns>
        public static byte[] DeriveKey(string password, byte[] salt, int n = DefaultN, int r = DefaultR, int p = DefaultP, int keyLength = DefaultKeySize)
        {
            ValidateParameters(password, salt, n, r, p, keyLength);

            // Convert password to bytes
            var passwordBytes = Encoding.UTF8.GetBytes(password);

            return DeriveKeyInternal(passwordBytes, salt, n, r, p, keyLength);
        }

        /// <summary>
        /// Derives a key using the Scrypt key derivation function asynchronously.
        /// </summary>
        /// <param name="password">The password as a string.</param>
        /// <param name="salt">The salt as a byte array.</param>
        /// <param name="n">The CPU/memory cost parameter.</param>
        /// <param name="r">The block size parameter.</param>
        /// <param name="p">The parallelization parameter.</param>
        /// <param name="keyLength">The length of the derived key in bytes.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the derived key as a byte array.</returns>
        public static async Task<byte[]> DeriveKeyAsync(string password, byte[] salt, int n = DefaultN, int r = DefaultR, int p = DefaultP, int keyLength = DefaultKeySize, CancellationToken cancellationToken = default)
        {
            ValidateParameters(password, salt, n, r, p, keyLength);

            // Convert password to bytes
            var passwordBytes = Encoding.UTF8.GetBytes(password);

            return await Task.Run(() => DeriveKeyInternal(passwordBytes, salt, n, r, p, keyLength), cancellationToken);
        }

        /// <summary>
        /// Generates a random salt for Scrypt.
        /// </summary>
        /// <param name="saltLength">The length of the salt in bytes.</param>
        /// <returns>A random salt as a byte array.</returns>
        public static byte[] GenerateSalt(int saltLength = DefaultSaltSize)
        {
            if (saltLength <= 0)
                throw new ArgumentException("Salt length must be positive", nameof(saltLength));

            var salt = new byte[saltLength];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);
            return salt;
        }

        /// <summary>
        /// Generates a random salt for Scrypt asynchronously.
        /// </summary>
        /// <param name="saltLength">The length of the salt in bytes.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains a random salt as a byte array.</returns>
        public static async Task<byte[]> GenerateSaltAsync(int saltLength = DefaultSaltSize, CancellationToken cancellationToken = default)
        {
            if (saltLength <= 0)
                throw new ArgumentException("Salt length must be positive", nameof(saltLength));

            return await Task.Run(() => 
            {
                var salt = new byte[saltLength];
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(salt);
                return salt;
            }, cancellationToken);
        }

        /// <summary>
        /// Validates the parameters for the Scrypt key derivation function.
        /// </summary>
        private static void ValidateParameters(string password, byte[] salt, int n, int r, int p, int keyLength)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            if (salt == null || salt.Length == 0)
                throw new ArgumentException("Salt cannot be null or empty", nameof(salt));

            if (n <= 0 || !IsPowerOfTwo(n))
                throw new ArgumentException("N must be a positive power of 2", nameof(n));

            if (r <= 0)
                throw new ArgumentException("R must be positive", nameof(r));

            if (p <= 0)
                throw new ArgumentException("P must be positive", nameof(p));

            if (keyLength <= 0)
                throw new ArgumentException("Key length must be positive", nameof(keyLength));

            // Check for potential integer overflow
            if ((long)r * 128 >= int.MaxValue)
                throw new ArgumentException("Parameter r is too large", nameof(r));

            if ((long)p * ((long)r * 128) >= int.MaxValue)
                throw new ArgumentException("Parameters p or r are too large", nameof(p));
        }

        /// <summary>
        /// Internal implementation of the Scrypt key derivation function.
        /// </summary>
        private static byte[] DeriveKeyInternal(byte[] password, byte[] salt, int n, int r, int p, int keyLength)
        {
            // Step 1: Generate initial key using PBKDF2-HMAC-SHA256 with 1 iteration
            byte[] b = Pbkdf2(password, salt, 1, p * 128 * r);

            // Step 2: Mix the key using ROMix function
            var blocks = new byte[p][];
            var blockSize = 128 * r;

            for (int i = 0; i < p; i++)
            {
                blocks[i] = new byte[blockSize];
                Buffer.BlockCopy(b, i * blockSize, blocks[i], 0, blockSize);
                blocks[i] = ROMix(blocks[i], n, r);
            }

            // Combine the mixed blocks
            byte[] result = new byte[p * blockSize];
            for (int i = 0; i < p; i++)
            {
                Buffer.BlockCopy(blocks[i], 0, result, i * blockSize, blockSize);
            }

            // Step 3: Generate final key using PBKDF2-HMAC-SHA256 with 1 iteration
            return Pbkdf2(password, result, 1, keyLength);
        }

        /// <summary>
        /// ROMix function used in Scrypt.
        /// </summary>
        /// <param name="inputBlock">The input block to mix.</param>
        /// <param name="n">The CPU/memory cost parameter.</param>
        /// <param name="r">The block size parameter.</param>
        /// <returns>The mixed block.</returns>
        private static byte[] ROMix(byte[] inputBlock, int n, int r)
        {
            int blockSize = 128 * r;
            byte[] workingBlock = new byte[inputBlock.Length];
            Buffer.BlockCopy(inputBlock, 0, workingBlock, 0, inputBlock.Length);

            // Allocate memory for V array
            var blockArray = ArrayPool<byte[]>.Shared.Rent(n);
            try
            {
                // Initialize V array
                for (int i = 0; i < n; i++)
                {
                    blockArray[i] = new byte[blockSize];
                    Buffer.BlockCopy(workingBlock, 0, blockArray[i], 0, blockSize);

                    // Apply BlockMix to the block
                    workingBlock = BlockMix(workingBlock, r);
                }

                // Mix the blocks
                for (int i = 0; i < n; i++)
                {
                    // Interpret the last 8 bytes of block as a little-endian integer j
                    int blockIndex = (int)(BitConverter.ToUInt64(workingBlock, workingBlock.Length - 8) & ((ulong)n - 1));

                    // XOR block with V[j]
                    byte[] tempBlock = new byte[blockSize];
                    Buffer.BlockCopy(blockArray[blockIndex], 0, tempBlock, 0, blockSize);

                    for (int k = 0; k < blockSize; k++)
                    {
                        workingBlock[k] ^= tempBlock[k];
                    }

                    // Apply BlockMix to the block
                    workingBlock = BlockMix(workingBlock, r);
                }

                return workingBlock;
            }
            finally
            {
                // Return the array to the pool
                ArrayPool<byte[]>.Shared.Return(blockArray);
            }
        }

        /// <summary>
        /// BlockMix function used in Scrypt.
        /// </summary>
        /// <param name="inputBlock">The input block to mix.</param>
        /// <param name="r">The block size parameter.</param>
        /// <returns>The mixed block.</returns>
        private static byte[] BlockMix(byte[] inputBlock, int r)
        {
            int blockSize = 128 * r;
            byte[] mixingBlock = new byte[64];
            byte[] resultBlock = new byte[blockSize];

            // Initialize mixing block with the last 64 bytes of input block
            Buffer.BlockCopy(inputBlock, blockSize - 64, mixingBlock, 0, 64);

            // Iterate through the blocks
            for (int i = 0; i < r * 2; i++)
            {
                // XOR mixing block with the current 64-byte block of input block
                for (int j = 0; j < 64; j++)
                {
                    mixingBlock[j] ^= inputBlock[i * 64 + j];
                }

                // Apply Salsa20/8 to mixing block
                mixingBlock = Salsa208(mixingBlock);

                // Copy mixing block to the appropriate position in result block
                Buffer.BlockCopy(mixingBlock, 0, resultBlock, (i / 2 + (i % 2) * r) * 64, 64);
            }

            return resultBlock;
        }

        /// <summary>
        /// Salsa20/8 function used in Scrypt.
        /// </summary>
        /// <param name="inputBlock">The input block to transform.</param>
        /// <returns>The transformed block.</returns>
        private static byte[] Salsa208(byte[] inputBlock)
        {
            // Convert bytes to 16 little-endian 32-bit words
            uint[] inputWords = new uint[16];
            for (int i = 0; i < 16; i++)
            {
                inputWords[i] = BitConverter.ToUInt32(inputBlock, i * 4);
            }

            // Create a copy of the input for transformation
            uint[] workingWords = new uint[16];
            Array.Copy(inputWords, workingWords, 16);

            // Perform 8 rounds of the Salsa20 core (4 iterations of double round)
            for (int i = 0; i < 4; i++)
            {
                // Column round
                workingWords[4] ^= RotateLeft(workingWords[0] + workingWords[12], 7);
                workingWords[8] ^= RotateLeft(workingWords[4] + workingWords[0], 9);
                workingWords[12] ^= RotateLeft(workingWords[8] + workingWords[4], 13);
                workingWords[0] ^= RotateLeft(workingWords[12] + workingWords[8], 18);

                workingWords[9] ^= RotateLeft(workingWords[5] + workingWords[1], 7);
                workingWords[13] ^= RotateLeft(workingWords[9] + workingWords[5], 9);
                workingWords[1] ^= RotateLeft(workingWords[13] + workingWords[9], 13);
                workingWords[5] ^= RotateLeft(workingWords[1] + workingWords[13], 18);

                workingWords[14] ^= RotateLeft(workingWords[10] + workingWords[6], 7);
                workingWords[2] ^= RotateLeft(workingWords[14] + workingWords[10], 9);
                workingWords[6] ^= RotateLeft(workingWords[2] + workingWords[14], 13);
                workingWords[10] ^= RotateLeft(workingWords[6] + workingWords[2], 18);

                workingWords[3] ^= RotateLeft(workingWords[15] + workingWords[11], 7);
                workingWords[7] ^= RotateLeft(workingWords[3] + workingWords[15], 9);
                workingWords[11] ^= RotateLeft(workingWords[7] + workingWords[3], 13);
                workingWords[15] ^= RotateLeft(workingWords[11] + workingWords[7], 18);

                // Row round
                workingWords[1] ^= RotateLeft(workingWords[0] + workingWords[3], 7);
                workingWords[2] ^= RotateLeft(workingWords[1] + workingWords[0], 9);
                workingWords[3] ^= RotateLeft(workingWords[2] + workingWords[1], 13);
                workingWords[0] ^= RotateLeft(workingWords[3] + workingWords[2], 18);

                workingWords[6] ^= RotateLeft(workingWords[5] + workingWords[4], 7);
                workingWords[7] ^= RotateLeft(workingWords[6] + workingWords[5], 9);
                workingWords[4] ^= RotateLeft(workingWords[7] + workingWords[6], 13);
                workingWords[5] ^= RotateLeft(workingWords[4] + workingWords[7], 18);

                workingWords[11] ^= RotateLeft(workingWords[10] + workingWords[9], 7);
                workingWords[8] ^= RotateLeft(workingWords[11] + workingWords[10], 9);
                workingWords[9] ^= RotateLeft(workingWords[8] + workingWords[11], 13);
                workingWords[10] ^= RotateLeft(workingWords[9] + workingWords[8], 18);

                workingWords[12] ^= RotateLeft(workingWords[15] + workingWords[14], 7);
                workingWords[13] ^= RotateLeft(workingWords[12] + workingWords[15], 9);
                workingWords[14] ^= RotateLeft(workingWords[13] + workingWords[12], 13);
                workingWords[15] ^= RotateLeft(workingWords[14] + workingWords[13], 18);
            }

            // Add the input to the output
            for (int i = 0; i < 16; i++)
            {
                workingWords[i] += inputWords[i];
            }

            // Convert back to bytes
            byte[] resultBlock = new byte[64];
            for (int i = 0; i < 16; i++)
            {
                BitConverter.GetBytes(workingWords[i]).CopyTo(resultBlock, i * 4);
            }

            return resultBlock;
        }

        /// <summary>
        /// PBKDF2-HMAC-SHA256 implementation.
        /// </summary>
        /// <param name="password">The password bytes.</param>
        /// <param name="salt">The salt bytes.</param>
        /// <param name="iterations">The number of iterations.</param>
        /// <param name="outputLength">The desired output length in bytes.</param>
        /// <returns>The derived key.</returns>
        private static byte[] Pbkdf2(byte[] password, byte[] salt, int iterations, int outputLength)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(outputLength);
        }

        /// <summary>
        /// Rotates a 32-bit unsigned integer to the left.
        /// </summary>
        /// <param name="value">The value to rotate.</param>
        /// <param name="count">The number of bits to rotate by.</param>
        /// <returns>The rotated value.</returns>
        private static uint RotateLeft(uint value, int count)
        {
            return (value << count) | (value >> (32 - count));
        }

        /// <summary>
        /// Checks if a number is a power of 2.
        /// </summary>
        /// <param name="x">The number to check.</param>
        /// <returns>True if the number is a power of 2, false otherwise.</returns>
        private static bool IsPowerOfTwo(int x)
        {
            return x > 0 && (x & (x - 1)) == 0;
        }
    }
}

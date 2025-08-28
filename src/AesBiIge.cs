using System.Buffers;
using System.Security.Cryptography;

namespace dotnet_aes_ige.src
{
    public sealed class AesBiIge
    {
        private static readonly ArrayPool<byte> _bufferPool = ArrayPool<byte>.Shared;
        private const int _blockSize = AesIge.BlockSize;

        public static byte[] EncryptBiIge(
            ReadOnlySpan<byte> plainText,
            ReadOnlySpan<byte> key1,
            ReadOnlySpan<byte> key2,
            ReadOnlySpan<byte> iv)
        {
            AesIgeHelper.ValidateBiIgeInputs(plainText, key1, key2, iv);

            var blockCount = plainText.Length / _blockSize;
            var intermediate = new byte[plainText.Length];
            var cipherText = new byte[plainText.Length];

            using var aes1 = AesIge.CreateAes(key1);
            using var aes2 = AesIge.CreateAes(key2);
            using var encryptor1 = aes1.CreateEncryptor();
            using var encryptor2 = aes2.CreateEncryptor();

            Span<byte> x0 = stackalloc byte[_blockSize];
            Span<byte> z0 = stackalloc byte[_blockSize];
            Span<byte> zn_plus_1 = stackalloc byte[_blockSize];
            Span<byte> y0 = stackalloc byte[_blockSize];

            iv[.._blockSize].CopyTo(x0);
            iv[_blockSize..(_blockSize * 2)].CopyTo(z0);
            iv[(_blockSize * 2)..(_blockSize * 3)].CopyTo(zn_plus_1);
            iv[(_blockSize * 3)..(_blockSize * 4)].CopyTo(y0);

            EncryptBiIgeForwardPass(plainText, encryptor1, x0, z0, intermediate);

            EncryptBiIgeBackwardPass(intermediate, encryptor2, zn_plus_1, y0, cipherText);

            return cipherText;
        }

        private static void EncryptBiIgeForwardPass(
            ReadOnlySpan<byte> plainText,
            ICryptoTransform encryptor,
            ReadOnlySpan<byte> x0,
            ReadOnlySpan<byte> z0,
            Span<byte> intermediate)
        {
            var blockCount = plainText.Length / _blockSize;
            Span<byte> x_prev = stackalloc byte[_blockSize];
            Span<byte> z_prev = stackalloc byte[_blockSize];

            x0.CopyTo(x_prev);
            z0.CopyTo(z_prev);

            // While theoretically it would be more useful to use stackalloc here in a loop, it would not cover
            // some extreme edge cases where our plainText input may go beyond stack limit, which is around 1 mb,
            // so it would easily cause nasty stack overflows really fast.
            // Dynamically renting an arraypool and clearing it after is not as efficient as stackalloc,
            // but covers more cases and works too (Plus arraypools are awesome).
            var buffer = _bufferPool.Rent(_blockSize);

            try
            {
                for (int i = 0; i < blockCount; i++)
                {
                    var plainTextBlock = plainText.Slice(i * _blockSize, _blockSize);
                    var intermediateBlock = intermediate.Slice(i * _blockSize, _blockSize);

                    AesIgeHelper.Xor(plainTextBlock, z_prev, buffer);

                    encryptor.TransformBlock(buffer, 0, _blockSize, buffer, 0);

                    AesIgeHelper.Xor(buffer, x_prev, intermediateBlock);

                    plainTextBlock.CopyTo(x_prev);
                    intermediateBlock.CopyTo(z_prev);
                }
            }
            finally
            {
                _bufferPool.Return(buffer, clearArray: true);
            }
        }

        private static void EncryptBiIgeBackwardPass(
            ReadOnlySpan<byte> intermediate,
            ICryptoTransform encryptor,
            ReadOnlySpan<byte> zn_plus_1,
            ReadOnlySpan<byte> y0,
            Span<byte> cipherText)
        {
            var blockCount = intermediate.Length / _blockSize;
            Span<byte> y_prev = stackalloc byte[_blockSize];
            Span<byte> z_next = stackalloc byte[_blockSize];

            y0.CopyTo(y_prev);
            zn_plus_1.CopyTo(z_next);

            var buffer = _bufferPool.Rent(_blockSize);

            try
            {
                for (int i = 0; i < blockCount; i++)
                {
                    var intermediateBlock = intermediate.Slice((blockCount - 1 - i) * _blockSize, _blockSize);
                    var cipherTextBlock = cipherText.Slice((blockCount - 1 - i) * _blockSize, _blockSize);

                    AesIgeHelper.Xor(intermediateBlock, y_prev, buffer);

                    encryptor.TransformBlock(buffer, 0, _blockSize, buffer, 0);

                    AesIgeHelper.Xor(buffer, z_next, cipherTextBlock);

                    cipherTextBlock.CopyTo(y_prev);
                    intermediateBlock.CopyTo(z_next);
                }
            }
            finally
            {
                _bufferPool.Return(buffer, clearArray: true);
            }
        }

        public static byte[] DecryptBiIge(ReadOnlySpan<byte> cipherText, ReadOnlySpan<byte> key1, ReadOnlySpan<byte> key2, ReadOnlySpan<byte> iv)
        {
            AesIgeHelper.ValidateBiIgeInputs(cipherText, key1, key2, iv);

            var blockCount = cipherText.Length / _blockSize;
            var intermediate = new byte[cipherText.Length];
            var plainText = new byte[cipherText.Length];

            using var aes1 = AesIge.CreateAes(key1);
            using var aes2 = AesIge.CreateAes(key2);
            using var decryptor1 = aes1.CreateDecryptor();
            using var decryptor2 = aes2.CreateDecryptor();

            Span<byte> x0 = stackalloc byte[_blockSize];
            Span<byte> z0 = stackalloc byte[_blockSize];
            Span<byte> zn_plus_1 = stackalloc byte[_blockSize];
            Span<byte> y0 = stackalloc byte[_blockSize];

            iv[.._blockSize].CopyTo(x0);
            iv[_blockSize..(_blockSize * 2)].CopyTo(z0);
            iv[(_blockSize * 2)..(_blockSize * 3)].CopyTo(zn_plus_1);
            iv[(_blockSize * 3)..(_blockSize * 4)].CopyTo(y0);

            DecryptBiIgeBackwardPass(cipherText, decryptor2, zn_plus_1, y0, intermediate);

            DecryptBiIgeForwardPass(intermediate, decryptor1, x0, z0, plainText);

            return plainText;
        }

        private static void DecryptBiIgeForwardPass(
            ReadOnlySpan<byte> intermediate,
            ICryptoTransform decryptor,
            ReadOnlySpan<byte> x0,
            ReadOnlySpan<byte> z0,
            Span<byte> plainText)
        {
            var blockCount = intermediate.Length / _blockSize;
            Span<byte> x_prev = stackalloc byte[_blockSize];
            Span<byte> z_prev = stackalloc byte[_blockSize];

            x0.CopyTo(x_prev);
            z0.CopyTo(z_prev);

            var buffer = _bufferPool.Rent(_blockSize);

            try
            {
                for (int i = 0; i < blockCount; i++)
                {
                    var intermediateBlock = intermediate.Slice(i * _blockSize, _blockSize);
                    var plaintextBlock = plainText.Slice(i * _blockSize, _blockSize);

                    AesIgeHelper.Xor(intermediateBlock, x_prev, buffer);

                    decryptor.TransformBlock(buffer, 0, _blockSize, buffer, 0);

                    AesIgeHelper.Xor(buffer, z_prev, plaintextBlock);

                    plaintextBlock.CopyTo(x_prev);
                    intermediateBlock.CopyTo(z_prev);
                }
            }
            finally
            {
                _bufferPool.Return(buffer, clearArray: true);
            }
        }

        /// <summary>
        /// Performs the reverse backward pass of bi-directional IGE decryption.
        /// </summary>
        private static void DecryptBiIgeBackwardPass(
            ReadOnlySpan<byte> cipherText,
            ICryptoTransform decryptor,
            ReadOnlySpan<byte> zn_plus_1,
            ReadOnlySpan<byte> y0,
            Span<byte> intermediate)
        {
            var blockCount = cipherText.Length / _blockSize;
            Span<byte> y_prev = stackalloc byte[_blockSize];
            Span<byte> z_next = stackalloc byte[_blockSize];

            y0.CopyTo(y_prev);
            zn_plus_1.CopyTo(z_next);

            var buffer = _bufferPool.Rent(_blockSize);

            try
            {
                for (int i = 0; i < blockCount; i++)
                {
                    var ciphertextBlock = cipherText.Slice((blockCount - 1 - i) * _blockSize, _blockSize);
                    var intermediateBlock = intermediate.Slice((blockCount - 1 - i) * _blockSize, _blockSize);

                    AesIgeHelper.Xor(ciphertextBlock, z_next, buffer);

                    decryptor.TransformBlock(buffer, 0, _blockSize, buffer, 0);

                    AesIgeHelper.Xor(buffer, y_prev, intermediateBlock);

                    ciphertextBlock.CopyTo(y_prev);
                    intermediateBlock.CopyTo(z_next);
                }
            }
            finally
            {
                _bufferPool.Return(buffer, clearArray: true);
            }
        }
    }
}

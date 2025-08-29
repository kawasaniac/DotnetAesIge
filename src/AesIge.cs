using System.Security.Cryptography;

namespace dotnet_aes_ige.src
{
    public sealed class AesIge
    {
        public const int BlockSize = 16;

        public static Aes CreateAes(ReadOnlySpan<byte> key)
        {
            var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = key.ToArray();
            return aes;
        }

        public static byte[] EncryptIge(
            ReadOnlySpan<byte> plainText,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> iv)
        {
            AesIgeHelper.ValidateIgeInputs(plainText, key, iv);

            var cipherText = new byte[plainText.Length];
            var plainTextSpan = plainText;
            var cipherTextSpan = cipherText.AsSpan();

            using var aes = CreateAes(key);
            using var encryptor = aes.CreateEncryptor();

            Span<byte> x_prev = stackalloc byte[BlockSize];
            Span<byte> y_prev = stackalloc byte[BlockSize];

            iv[..BlockSize].CopyTo(x_prev);
            iv[BlockSize..(BlockSize * 2)].CopyTo(y_prev);

            var blockCount = plainText.Length / BlockSize;

            for (int i = 0; i < blockCount; i++)
            {
                var currentPlainTextBlock = plainTextSpan.Slice(i * BlockSize, BlockSize);
                var currentCipherTextBlock = cipherTextSpan.Slice(i * BlockSize, BlockSize);

                EncryptIgeBlock(
                    encryptor,
                    currentPlainTextBlock,
                    x_prev,
                    y_prev,
                    currentCipherTextBlock
                );

                currentPlainTextBlock.CopyTo(x_prev);
                currentCipherTextBlock.CopyTo(y_prev);
            }

            return cipherText;
        }

        public static byte[] DecryptIge(
            ReadOnlySpan<byte> cipherText,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> iv)
        {
            AesIgeHelper.ValidateIgeInputs(cipherText, key, iv);

            var plainText = new byte[cipherText.Length];
            var cipherTextSpan = cipherText;
            var plainTextSpan = plainText.AsSpan();

            using var aes = CreateAes(key);
            using var encryptor = aes.CreateDecryptor();

            Span<byte> x_prev = stackalloc byte[BlockSize];
            Span<byte> y_prev = stackalloc byte[BlockSize];

            iv[..BlockSize].CopyTo(x_prev);
            iv[BlockSize..(BlockSize * 2)].CopyTo(y_prev);

            var blockCount = cipherText.Length / BlockSize;

            for (int i = 0; i < blockCount; i++)
            {
                var currentCipherTextBlock = cipherTextSpan.Slice(i * BlockSize, BlockSize);
                var currentPlainTextBlock = plainTextSpan.Slice(i * BlockSize, BlockSize);

                DecryptIgeBlock(
                    encryptor,
                    currentCipherTextBlock,
                    x_prev,
                    y_prev,
                    currentPlainTextBlock
                );

                currentPlainTextBlock.CopyTo(x_prev);
                currentCipherTextBlock.CopyTo(y_prev);
            }

            return plainText;
        }

        private static void EncryptIgeBlock(
            ICryptoTransform encryptor,
            ReadOnlySpan<byte> plainTextBlock,
            ReadOnlySpan<byte> x_prev,
            ReadOnlySpan<byte> y_prev,
            Span<byte> cipherTextBlock)
        {
            // Though my previous array implementation is technically correct,
            // it performs the same way as my stackalloc, but on the heap.
            // Potentially constant heap allocation vs reusing constant buffer in stackalloc
            // will be more costly for the garbage collector in the long run.
            // While not tested, that's my thoughts and it's still beter to use stacks for any AES operations.
            /*
            byte[] temp = new byte[BlockSize];
            AesIgeHelper.Xor(plainTextBlock, y_prev, temp);
            encryptor.TransformBlock(temp, 0, BlockSize, temp, 0);
            AesIgeHelper.Xor(temp, x_prev, cipherTextBlock);
            */

            Span<byte> temp = stackalloc byte[BlockSize];
            AesIgeHelper.Xor(plainTextBlock, y_prev, temp);

            byte[] buffer = new byte[BlockSize];
            temp.CopyTo(buffer);

            encryptor.TransformBlock(buffer, 0, BlockSize, buffer, 0);
            buffer.CopyTo(temp);

            AesIgeHelper.Xor(temp, x_prev, cipherTextBlock);
        }

        private static void DecryptIgeBlock(
            ICryptoTransform encryptor,
            ReadOnlySpan<byte> cipherTextBlock,
            ReadOnlySpan<byte> x_prev,
            ReadOnlySpan<byte> y_prev,
            Span<byte> plainTextBlock)
        {
            /*
            byte[] temp = new byte[BlockSize];
            AesIgeHelper.Xor(cipherTextBlock, x_prev, temp);
            encryptor.TransformBlock(temp, 0, BlockSize, temp, 0);
            AesIgeHelper.Xor(temp, y_prev, plainTextBlock);
            */

            Span<byte> temp = stackalloc byte[BlockSize];
            AesIgeHelper.Xor(cipherTextBlock, x_prev, temp);

            byte[] buffer = new byte[BlockSize];
            temp.CopyTo(buffer);

            encryptor.TransformBlock(buffer, 0, BlockSize, buffer, 0);
            buffer.CopyTo(temp);

            AesIgeHelper.Xor(temp, y_prev, plainTextBlock);
        }
    }
}

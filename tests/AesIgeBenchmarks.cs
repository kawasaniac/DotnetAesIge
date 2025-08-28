using BenchmarkDotNet.Attributes;
using dotnet_aes_ige.src;
using System.Security.Cryptography;

namespace dotnet_aes_ige.tests
{
    public class AesIgeBenchmarks
    {
        public const int BlockSize = 16;

        private ICryptoTransform? _encryptor;
        private byte[]? _cipherTextBlock;
        private byte[]? _xPrev;
        private byte[]? _yPrev;
        private byte[]? _plainTextBlock;
        private byte[]? _buffer; // reusable buffer for TransformBlock

        [GlobalSetup]
        public void Setup()
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            _encryptor = aes.CreateEncryptor();

            _cipherTextBlock = new byte[BlockSize];
            _xPrev = new byte[BlockSize];
            _yPrev = new byte[BlockSize];
            _plainTextBlock = new byte[BlockSize];
            _buffer = new byte[BlockSize];
        }

        [Benchmark]
        public void DecryptIgeBlock_Stackalloc()
        {
            Span<byte> temp = stackalloc byte[BlockSize];
            AesIgeHelper.Xor(_cipherTextBlock, _xPrev, temp);

            // copy into reusable array buffer
            temp.CopyTo(_buffer);
            _ = _encryptor!.TransformBlock(_buffer!, 0, BlockSize, _buffer!, 0);

            AesIgeHelper.Xor(_buffer, _yPrev, _plainTextBlock);
        }

        [Benchmark]
        public void DecryptIgeBlock_Array()
        {
            byte[] temp = new byte[BlockSize]; // allocates every call
            AesIgeHelper.Xor(_cipherTextBlock, _xPrev, temp);

            _ = _encryptor!.TransformBlock(temp, 0, BlockSize, temp, 0);

            AesIgeHelper.Xor(temp, _yPrev, _plainTextBlock);
        }
    }
}

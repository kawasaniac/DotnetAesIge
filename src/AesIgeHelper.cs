namespace dotnet_aes_ige.src
{
    public static class AesIgeHelper
    {
        private const int _blockSize = AesIge.BlockSize;

        public static void Xor(
            ReadOnlySpan<byte> a,
            ReadOnlySpan<byte> b,
            Span<byte> result)
        {
            for (int i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
        }

        public static void ValidateIgeInputs(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> iv)
        {
            if (data.Length == 0)
                throw new ArgumentException("Plaintext data cannot be empty!", nameof(data));

            if (data.Length % _blockSize != 0)
                throw new ArgumentException($"Data length must be a multiple of {_blockSize} bytes!", nameof(data));

            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("Key must be 16, 24 or 32 bytes long!", nameof(key));

            if (iv.Length != _blockSize * 2)
                throw new ArgumentException($"Initiliazation vector must be {_blockSize * 2} bytes long for IGE mode!", nameof(iv));
        }

        public static void ValidateBiIgeInputs(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> key1,
            ReadOnlySpan<byte> key2,
            ReadOnlySpan<byte> iv)
        {
            if (data.Length == 0)
                throw new ArgumentException("Plaintext data cannot be empty!", nameof(data));

            if (data.Length % _blockSize != 0)
                throw new ArgumentException($"Data length must be a multiple of {_blockSize} bytes!", nameof(data));

            if (key1.Length != 16 && key1.Length != 24 && key1.Length != 32)
                throw new ArgumentException("Key1 argument must be 16, 24 or 32 bytes long!", nameof(key1));

            if (key2.Length != 16 && key2.Length != 24 && key2.Length != 32)
                throw new ArgumentException("Key2 argument must be 16, 24 or 32 bytes long!", nameof(key2));

            if (iv.Length != _blockSize * 4)
                throw new ArgumentException($"Initiliazation vector must be {_blockSize * 4} bytes long for bi-directonal IGE mode!", nameof(iv));
        }
    }
}

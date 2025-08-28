using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace dotnet_aes_ige.src
{
    internal class AesIgeHmac
    {
        private const int HmacSha256Size = 32;
        private const int HmacSha512Size = 64;

        /// <summary>
        /// Encrypts data using AES-IGE and appends HMAC-SHA256 for authentication.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="encryptionKey"></param>
        /// <param name="hmacKey"></param>
        /// <param name="iv"></param>
        /// <returns>IV + ciphertext + HMAC tag</returns>
        public static byte[] EncryptWithHmac(
            ReadOnlySpan<byte> plainText,
            ReadOnlySpan<byte> encryptionKey,
            ReadOnlySpan<byte> hmacKey,
            ReadOnlySpan<byte> iv)
        {
            var cipherText = AesIge.EncryptIge(plainText, encryptionKey, iv);

            var dataToAuthenticate = new byte[iv.Length + cipherText.Length];
            iv.CopyTo(dataToAuthenticate);
            cipherText.CopyTo(dataToAuthenticate.AsSpan(iv.Length));

            using var hmac = new HMACSHA256(hmacKey.ToArray());
            var tag = hmac.ComputeHash(dataToAuthenticate);

            var result = new byte[iv.Length + cipherText.Length + HmacSha256Size];
            iv.CopyTo(result);
            cipherText.CopyTo(result.AsSpan(iv.Length));
            tag.CopyTo(result.AsSpan(iv.Length + cipherText.Length));

            return result;
        }

        public static (byte[] EncryptionKey, byte[] HmacKey) DeriveKeys(
            ReadOnlySpan<byte> masterKey,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            int encryptionKeySize = 32)
        {
            var totalKeyMaterial = encryptionKeySize + HmacSha256Size;
            var pseudoRandomKey = HKDF.Extract(HashAlgorithmName.SHA256, masterKey.ToArray(), salt.ToArray());

            var derivedKeys = HKDF.Expand(HashAlgorithmName.SHA256, pseudoRandomKey, totalKeyMaterial, info.ToArray());

            var encryptionKey = derivedKeys[..encryptionKeySize];
            var hmacKey = derivedKeys[encryptionKeySize..];

            return (encryptionKey, hmacKey);
        }

        public static (byte[] EncryptionKey1, byte[] EncryptionKey2, byte[] HmacKey) DeriveBiIgeKeys(
            ReadOnlySpan<byte> masterKey,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            int encryptionKeySize = 32)
        {
            var totalKeyMaterial = (encryptionKeySize * 2) + HmacSha512Size;
            var pseudoRandomKey = HKDF.Extract(HashAlgorithmName.SHA512, masterKey.ToArray(), salt.ToArray());

            var derivedKeys = HKDF.Expand(HashAlgorithmName.SHA512, pseudoRandomKey, totalKeyMaterial, info.ToArray());

            var encryptionKey1 = derivedKeys[..encryptionKeySize];
            var encryptionKey2 = derivedKeys[encryptionKeySize..(encryptionKeySize * 2)];
            var hmacKey = derivedKeys[(encryptionKeySize * 2)..];

            return (encryptionKey1, encryptionKey2, hmacKey);
        }
    }
}

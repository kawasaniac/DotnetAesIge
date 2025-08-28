using dotnet_aes_ige.src;
using System.Text;

namespace dotnet_aes_ige.tests
{
    /// <summary>
    /// Contains tests for AesIge, AesBiIge, and AesIgeHelper classes.
    /// </summary>
    public static class AesIgeTests
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Running AES IGE Tests...");
            Console.WriteLine(new string('-', 30));

            TestXor();
            Console.WriteLine();

            TestAesIgeEncryptDecrypt();
            Console.WriteLine();

            TestAesBiIgeEncryptDecrypt();
            Console.WriteLine();

            TestInputValidation();
            Console.WriteLine();

            Console.WriteLine(new string('-', 30));
            Console.WriteLine("All tests completed.");
        }

        /// <summary>
        /// Tests the Xor helper method.
        /// </summary>
        private static void TestXor()
        {
            Console.WriteLine("--> Running TestXor");
            var a = new byte[] { 1, 2, 3, 4 };
            var b = new byte[] { 5, 6, 7, 8 };
            var expected = new byte[] { 4, 4, 4, 12 };
            var result = new byte[4];

            AesIgeHelper.Xor(a, b, result);

            if (result.SequenceEqual(expected))
            {
                Console.WriteLine("TestXor PASSED");
            }
            else
            {
                Console.WriteLine("TestXor FAILED");
                Console.WriteLine($"Expected: {BitConverter.ToString(expected)}");
                Console.WriteLine($"Got:      {BitConverter.ToString(result)}");
            }
        }

        /// <summary>
        /// Tests the standard IGE encryption and decryption cycle.
        /// </summary>
        private static void TestAesIgeEncryptDecrypt()
        {
            Console.WriteLine("--> Running TestAesIgeEncryptDecrypt");
            try
            {
                // Prepare data
                var key = new byte[32];
                var iv = new byte[32];
                // Fix: The original string was 45 bytes long. A 48-byte string is required for a multiple of BlockSize (16 bytes).
                var plainText = Encoding.UTF8.GetBytes("This is a test message that is 48 bytes long...!"); // Now exactly 48 bytes = 3 blocks

                Random.Shared.NextBytes(key);
                Random.Shared.NextBytes(iv);

                Console.WriteLine($"Plaintext:  {Encoding.UTF8.GetString(plainText)}");
                Console.WriteLine($"Key:        {Convert.ToHexString(key)}");
                Console.WriteLine($"IV:         {Convert.ToHexString(iv)}");

                // Encrypt
                var cipherText = AesIge.EncryptIge(plainText, key, iv);
                Console.WriteLine($"Ciphertext: {Convert.ToHexString(cipherText)}");

                // Decrypt
                var decryptedText = AesIge.DecryptIge(cipherText, key, iv);
                Console.WriteLine($"Decrypted:  {Encoding.UTF8.GetString(decryptedText)}");

                // Verify
                if (plainText.SequenceEqual(decryptedText))
                {
                    Console.WriteLine("TestAesIgeEncryptDecrypt PASSED");
                }
                else
                {
                    Console.WriteLine("TestAesIgeEncryptDecrypt FAILED: Decrypted text does not match original plaintext.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"TestAesIgeEncryptDecrypt FAILED with exception: {ex.Message}");
            }
        }

        /// <summary>
        /// Tests the bi-directional IGE encryption and decryption cycle.
        /// </summary>
        private static void TestAesBiIgeEncryptDecrypt()
        {
            Console.WriteLine("--> Running TestAesBiIgeEncryptDecrypt");
            try
            {
                // Prepare data
                var key1 = new byte[32];
                var key2 = new byte[32];
                var iv = new byte[64]; // 4 * 16 bytes
                var plainText = Encoding.UTF8.GetBytes("Another test message for bi-ige, also 48 bytes! "); // 48 bytes

                Random.Shared.NextBytes(key1);
                Random.Shared.NextBytes(key2);
                Random.Shared.NextBytes(iv);

                Console.WriteLine($"Plaintext: {Encoding.UTF8.GetString(plainText)}");
                Console.WriteLine($"Key 1:     {Convert.ToHexString(key1)}");
                Console.WriteLine($"Key 2:     {Convert.ToHexString(key2)}");
                Console.WriteLine($"IV:        {Convert.ToHexString(iv)}");

                // Encrypt
                var cipherText = AesBiIge.EncryptBiIge(plainText, key1, key2, iv);
                Console.WriteLine($"Ciphertext: {Convert.ToHexString(cipherText)}");

                // Decrypt
                var decryptedText = AesBiIge.DecryptBiIge(cipherText, key1, key2, iv);
                Console.WriteLine($"Decrypted:  {Encoding.UTF8.GetString(decryptedText)}");

                // Verify
                if (plainText.SequenceEqual(decryptedText))
                {
                    Console.WriteLine("TestAesBiIgeEncryptDecrypt PASSED");
                }
                else
                {
                    Console.WriteLine("TestAesBiIgeEncryptDecrypt FAILED: Decrypted text does not match original plaintext.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"TestAesBiIgeEncryptDecrypt FAILED with exception: {ex.Message}");
            }
        }

        /// <summary>
        /// Tests the input validation helpers to ensure they throw exceptions for invalid input.
        /// </summary>
        private static void TestInputValidation()
        {
            Console.WriteLine("--> Running TestInputValidation");
            bool allPassed = true;

            // Test case 1: Data length not a multiple of block size
            try
            {
                AesIgeHelper.ValidateIgeInputs(new byte[17], new byte[16], new byte[32]);
                Console.WriteLine("Validation FAILED: Did not throw for invalid data length.");
                allPassed = false;
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"Validation PASSED: Caught expected exception for data length: {ex.Message}");
            }

            // Test case 2: Invalid key size
            try
            {
                AesIgeHelper.ValidateIgeInputs(new byte[16], new byte[10], new byte[32]);
                Console.WriteLine("Validation FAILED: Did not throw for invalid key size.");
                allPassed = false;
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"Validation PASSED: Caught expected exception for key size: {ex.Message}");
            }

            // Test case 3: Invalid IV size for IGE
            try
            {
                AesIgeHelper.ValidateIgeInputs(new byte[16], new byte[16], new byte[31]);
                Console.WriteLine("Validation FAILED: Did not throw for invalid IV size.");
                allPassed = false;
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"Validation PASSED: Caught expected exception for IV size: {ex.Message}");
            }

            // Test case 4: Invalid IV size for Bi-IGE
            try
            {
                AesIgeHelper.ValidateBiIgeInputs(new byte[16], new byte[16], new byte[16], new byte[63]);
                Console.WriteLine("Validation FAILED: Did not throw for invalid Bi-IGE IV size.");
                allPassed = false;
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"Validation PASSED: Caught expected exception for Bi-IGE IV size: {ex.Message}");
            }

            Console.WriteLine(allPassed ? "TestInputValidation PASSED" : "TestInputValidation FAILED");
        }
    }
}
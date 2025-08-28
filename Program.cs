using BenchmarkDotNet.Running;
using dotnet_aes_ige.tests;

namespace dotnet_aes_ige
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BenchmarkRunner.Run<AesIgeBenchmarks>();
            // Initialize and run the tests from the AesIgeTests class.
            tests.AesIgeTests.Main(args);
        }
    }
}

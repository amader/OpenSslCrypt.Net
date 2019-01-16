using System;
using OpenSslCrypt;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace OpenSslCrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Crypto c1 = new Crypto(CryptoUtil.MessageDigest.SHA256);

                c1.EncryptFile(System.Security.Cryptography.CipherMode.CBC, "PASSPHRASE", @"INFILE", @"OUTFILE");
                c1.DecryptFile(System.Security.Cryptography.CipherMode.CBC, "PASSPHRASE", @"INFILE", @"OUTFILE");
            }
            catch(Exception c) {
                Console.WriteLine(c.Message);
                Console.WriteLine(c.InnerException.Message);
            }
            Console.WriteLine("process ended.");
            Console.ReadKey();

        }
    }
}

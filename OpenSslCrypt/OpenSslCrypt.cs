using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace OpenSslCrypt
{
    public abstract class CryptoUtil
    {
        //Attributes
        private MessageDigest _hashAlgorithm = MessageDigest.MD5;

        public int _BlockSize { get; set; }

        public Byte[] saltPrefix = Encoding.ASCII.GetBytes("Salted__");

        public enum MessageDigest
        {
            MD5,
            SHA1,
            SHA256
        }

        //Methods
        public CryptoUtil(int BlockSize = 4096) {
            _BlockSize = BlockSize;
        }

        public CryptoUtil(MessageDigest md, int BlockSize = 4096) {
            _hashAlgorithm = md;
            _BlockSize = BlockSize;
        }

        public virtual void CreateSalt(out byte[] salt)
        {
            salt = new byte[8];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetNonZeroBytes(salt);
        }

        public virtual void DeriveKeyIV(string passPhrase, byte[] salt, out byte[] key, out byte[] iv)
        {
            int hashSize = 48;

            key = new byte[32];
            iv = new byte[16];

            byte[] password = Encoding.UTF8.GetBytes(passPhrase);
            byte[] currentHash = new byte[0];
            List<byte> concatenatedHashes = new List<byte>(hashSize);

            using (HashAlgorithm hashAlgorithm = HashAlgorithm.Create(_hashAlgorithm.ToString()))
            {
                while (concatenatedHashes.Count() < hashSize)
                {
                    int preHashLength = currentHash.Length + password.Length + salt.Length;
                    byte[] preHash = new byte[preHashLength];

                    Buffer.BlockCopy(currentHash, 0, preHash, 0, currentHash.Length);
                    Buffer.BlockCopy(password, 0, preHash, currentHash.Length, password.Length);
                    Buffer.BlockCopy(salt, 0, preHash, currentHash.Length + password.Length, salt.Length);

                    currentHash = hashAlgorithm.ComputeHash(preHash);
                    concatenatedHashes.AddRange(currentHash);
                }

                concatenatedHashes.CopyTo(0, key, 0, 32);
                concatenatedHashes.CopyTo(32, iv, 0, 16);

                hashAlgorithm.Clear();
            }
        }
    }

    public class Crypto : CryptoUtil
    {
        //Constructors
        public Crypto(int BlockSize = 4096) : base(BlockSize) {}

        public Crypto(MessageDigest md, int BlockSize = 4096) : base(md, BlockSize) {}

        //Methods
        public bool EncryptFile(CipherMode cipher, string passPhrase, string inFile, string outFile) 
        {
            byte[] key, iv;
            byte[] salt = new byte[8];

            try
            {
                CreateSalt(out salt);
                DeriveKeyIV(passPhrase, salt, out key, out iv);

                bool result = false;
                using (RijndaelManaged aesAlg = new RijndaelManaged { Mode = cipher, KeySize = 256, BlockSize = 128, Key = key, IV = iv })
                {
                    EncryptFile(aesAlg, inFile, outFile, salt);

                    aesAlg.Clear();
                }

                return result;
            }
            catch (Exception c) { throw new SystemException(c.Message, c); }
        }

        private bool EncryptFile(RijndaelManaged aesAlg, string inFile, string outFile, byte[] salt)
        {
            try
            {
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (FileStream fwStream = new FileStream(outFile, FileMode.Create, FileAccess.Write))
                {
                    fwStream.Write(saltPrefix, 0, saltPrefix.Length);
                    fwStream.Write(salt, 0, salt.Length);

                    using (CryptoStream cStream = new CryptoStream(fwStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (FileStream frStream = new FileStream(inFile, FileMode.Open, FileAccess.Read))
                        {
                            byte[] data = new byte[_BlockSize];
                            int readedBytes = 0;
                            while ((readedBytes = frStream.Read(data, 0, _BlockSize)) > 0)
                            {
                                cStream.Write(data, 0, readedBytes);
                            }

                            frStream.Flush();
                            frStream.Close();
                        }
                        cStream.Flush();
                        cStream.Close();
                    }
                }

                return true;
            }
            catch (Exception c) { throw new SystemException(c.Message, c); }
            finally { aesAlg.Clear(); }
        }

        public bool DecryptFile(CipherMode cipher, string passPhrase, string inFile, string outFile)
        {
            byte[] key, iv;
            byte[] salt = new byte[8];

            try
            {
                using (FileStream fsReader = new FileStream(inFile, FileMode.Open, FileAccess.Read))
                {
                    byte[] saltValue = new byte[16];
                    fsReader.Read(saltValue, 0, 16);
                    Buffer.BlockCopy(saltValue, 8, salt, 0, salt.Length);
                    fsReader.Close();
                }

                DeriveKeyIV(passPhrase, salt, out key, out iv);

                using (RijndaelManaged aesAlg = new RijndaelManaged { Mode = cipher, KeySize = 256, BlockSize = 128, Key = key, IV = iv })
                {
                    DecryptFile(aesAlg, inFile, outFile, salt);

                    aesAlg.Clear();
                }

                return true;
            }
            catch (Exception c) { throw new SystemException(c.Message, c); }
        }

        private bool DecryptFile(RijndaelManaged aesAlg, string inFile, string outFile, byte[] salt)
        {
            try
            {
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (FileStream frStream = new FileStream(inFile, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    frStream.Seek((saltPrefix.Length + salt.Length), SeekOrigin.Begin);

                    using (CryptoStream cStream = new CryptoStream(frStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (FileStream fwStream = new FileStream(outFile, FileMode.Create, FileAccess.Write))
                        {
                            byte[] data = new byte[_BlockSize];

                            int readedBytes = 0;
                            while ((readedBytes = cStream.Read(data, 0, _BlockSize)) > 0)
                            {
                                fwStream.Write(data, 0, readedBytes);

                                readedBytes = 0;
                            }

                            fwStream.Flush();
                            fwStream.Close();
                        }
                        cStream.Flush();
                        cStream.Close();
                    }
                }

                return true;
            }
            catch (Exception c) { throw new SystemException(c.Message, c); }
            finally { aesAlg.Clear(); }
        }
    }

    public class CryptoAsync : CryptoUtil
    {
        //Constructors
        public CryptoAsync(int BlockSize = 4096) : base(BlockSize) { }

        public CryptoAsync(MessageDigest md, int BlockSize = 4096) : base(md, BlockSize) { }

        //Methods
        public async Task<bool> EncryptFileAsync(CipherMode cipher, string passPhrase, string inFile, string outFile)
        {
            byte[] key, iv;
            byte[] salt = new byte[8];

            try
            {


                CreateSalt(out salt);
                DeriveKeyIV(passPhrase, salt, out key, out iv);

                bool result = false;
                using (RijndaelManaged aesAlg = new RijndaelManaged { Mode = cipher, KeySize = 256, BlockSize = 128, Key = key, IV = iv })
                {
                    result = await EncryptFileAsync(aesAlg, inFile, outFile, salt);

                    aesAlg.Clear();
                    return result;
                }
            }
            catch (Exception c) { throw new SystemException(c.Message, c); }
        }

        private Task<bool> EncryptFileAsync(RijndaelManaged aesAlg, string inFile, string outFile, byte[] salt)
        {
            try
            {
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (FileStream fwStream = new FileStream(outFile, FileMode.Create, FileAccess.Write))
                {
                    fwStream.Write(saltPrefix, 0, saltPrefix.Length);
                    fwStream.Write(salt, 0, salt.Length);

                    using (CryptoStream cStream = new CryptoStream(fwStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (FileStream frStream = new FileStream(inFile, FileMode.Open, FileAccess.Read))
                        {
                            byte[] data = new byte[_BlockSize];
                            int readedBytes = 0;
                            while ((readedBytes = frStream.Read(data, 0, _BlockSize)) > 0)
                            {
                                cStream.Write(data, 0, readedBytes);
                            }

                            frStream.Flush();
                            frStream.Close();
                        }
                        cStream.Flush();
                        cStream.Close();
                    }
                }
            }
            catch (Exception c) { throw new SystemException(c.Message); }
            finally { aesAlg.Clear(); }

            return Task.FromResult(true);
        }

        public bool DecryptFile(CipherMode cipher, string passPhrase, string inFile, string outFile)
        {
            byte[] key, iv;
            byte[] salt = new byte[8];

            try
            {
                using (FileStream fsReader = new FileStream(inFile, FileMode.Open, FileAccess.Read))
                {
                    byte[] saltValue = new byte[16];
                    fsReader.Read(saltValue, 0, 16);
                    Buffer.BlockCopy(saltValue, 8, salt, 0, salt.Length);
                    fsReader.Close();
                }

                DeriveKeyIV(passPhrase, salt, out key, out iv);

                using (RijndaelManaged aesAlg = new RijndaelManaged { Mode = cipher, KeySize = 256, BlockSize = 128, Key = key, IV = iv })
                {
                    DecryptFile(aesAlg, inFile, outFile, salt);

                    aesAlg.Clear();
                }
                return true;
            }
            catch (Exception c) { throw new SystemException(c.Message); }
        }

        private bool DecryptFile(RijndaelManaged aesAlg, string inFile, string outFile, byte[] salt)
        {
            try
            {
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (FileStream frStream = new FileStream(inFile, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    frStream.Seek((saltPrefix.Length + salt.Length), SeekOrigin.Begin);

                    using (CryptoStream cStream = new CryptoStream(frStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (FileStream fwStream = new FileStream(outFile, FileMode.Create, FileAccess.Write))
                        {
                            byte[] data = new byte[_BlockSize];

                            int readedBytes = 0;
                            while ((readedBytes = cStream.Read(data, 0, _BlockSize)) > 0)
                            {
                                fwStream.Write(data, 0, readedBytes);

                                readedBytes = 0;
                            }

                            fwStream.Flush();
                            fwStream.Close();
                        }
                        cStream.Flush();
                        cStream.Close();
                    }
                }
                return true;
            }
            catch (Exception c) { throw new SystemException(c.Message); }
            finally { aesAlg.Clear(); }
        }
    }
}

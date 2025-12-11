using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.Serialization;
using Common.Models;

namespace Manager.Cryptography
{
    public class AESHelper
    {
        public static byte[] Encrypt(Zalba zalba, string secretKey)
        {
            try
            {
                // 1. Serialize objekat
                byte[] serializedData = SerializeZalba(zalba);

                // 2. Enkriptuj AES ECB
                return EncryptAES_ECB(serializedData, secretKey);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[AES-ENCRYPT] Error: {ex.Message}");
                throw;
            }
        }

        public static Zalba Decrypt(byte[] encryptedData, string secretKey)
        {
            try
            {
                // 1. Dekriptuj AES ECB
                byte[] decryptedData = DecryptAES_ECB(encryptedData, secretKey);

                // 2. Deserialize objekat
                return DeserializeZalba(decryptedData);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[AES-DECRYPT] Error: {ex.Message}");
                throw;
            }
        }

        private static byte[] EncryptAES_ECB(byte[] data, string secretKey)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = Encoding.UTF8.GetBytes(secretKey.PadRight(32).Substring(0, 32));
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        private static byte[] DecryptAES_ECB(byte[] encryptedData, string secretKey)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = Encoding.UTF8.GetBytes(secretKey.PadRight(32).Substring(0, 32));
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                using (MemoryStream ms = new MemoryStream(encryptedData))
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    byte[] decryptedData = new byte[encryptedData.Length];
                    int bytesRead = cs.Read(decryptedData, 0, decryptedData.Length);

                    // Trim padding
                    byte[] result = new byte[bytesRead];
                    Array.Copy(decryptedData, result, bytesRead);
                    return result;
                }
            }
        }

        private static byte[] SerializeZalba(Zalba zalba)
        {
            DataContractSerializer serializer = new DataContractSerializer(typeof(Zalba));
            using (MemoryStream ms = new MemoryStream())
            {
                serializer.WriteObject(ms, zalba);
                return ms.ToArray();
            }
        }

        private static Zalba DeserializeZalba(byte[] data)
        {
            DataContractSerializer serializer = new DataContractSerializer(typeof(Zalba));
            using (MemoryStream ms = new MemoryStream(data))
            {
                return (Zalba)serializer.ReadObject(ms);
            }
        }
    }
}
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Manager.Cryptography
{
    public enum HashAlgorithm
    {
        SHA1,
        SHA256
    }

    public class DigitalSignature
    {
        public static byte[] Create(byte[] data, HashAlgorithm hashAlgorithm, X509Certificate2 certificate)
        {
            try
            {
                if (!certificate.HasPrivateKey)
                {
                    throw new Exception("Certificate must have private key for signing");
                }

                using (RSA rsa = certificate.GetRSAPrivateKey())
                {
                    HashAlgorithmName hashAlgName = hashAlgorithm == HashAlgorithm.SHA256
                        ? HashAlgorithmName.SHA256
                        : HashAlgorithmName.SHA1;

                    return rsa.SignData(data, hashAlgName, RSASignaturePadding.Pkcs1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DIGITAL-SIGNATURE] Create error: {ex.Message}");
                throw;
            }
        }

        public static bool Verify(byte[] data, HashAlgorithm hashAlgorithm, byte[] signature, X509Certificate2 certificate)
        {
            try
            {
                using (RSA rsa = certificate.GetRSAPublicKey())
                {
                    HashAlgorithmName hashAlgName = hashAlgorithm == HashAlgorithm.SHA256
                        ? HashAlgorithmName.SHA256
                        : HashAlgorithmName.SHA1;

                    return rsa.VerifyData(data, signature, hashAlgName, RSASignaturePadding.Pkcs1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DIGITAL-SIGNATURE] Verify error: {ex.Message}");
                return false;
            }
        }
    }
}
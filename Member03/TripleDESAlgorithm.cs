using System;
using System.Text;
using System.Security.Cryptography;

namespace InformationSecurityTool.Member03 
{
    public class TripleDESAlgorithm
    {
        public static string Encrypt(string plainText, string key)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key.PadRight(24, '0').Substring(0, 24));

            using (var tdes = TripleDES.Create())
            {
                tdes.Key = keyBytes;
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;

                using (var encryptor = tdes.CreateEncryptor())
                {
                    byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    return Convert.ToBase64String(cipherBytes);
                }
            }
        }

        public static string Decrypt(string cipherText, string key)
        {
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key.PadRight(24, '0').Substring(0, 24));

            using (var tdes = TripleDES.Create())
            {
                tdes.Key = keyBytes;
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;

                using (var decryptor = tdes.CreateDecryptor())
                {
                    byte[] plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                    return Encoding.UTF8.GetString(plainBytes);
                }
            }
        }
    }
}
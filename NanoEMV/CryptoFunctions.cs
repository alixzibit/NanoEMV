using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace NanoEMV
{
    public class SessionKeyDerivation
    {
        // Example Master Key (replace with actual key)
        public static readonly byte[] ICCMasterKey = HexStringToByteArray("6E46FE409DF704BCA75E7FF270B65E73");
        public static readonly byte[] ExpectedKCV = HexStringToByteArray("944A44");

        public static byte[] DeriveSessionKey(byte[] masterKey, byte[] atc)
        {
            // Ensure the ATC is the correct length
            if (atc.Length != 2)
            {
                throw new ArgumentException("ATC must be 2 bytes.");
            }

            // Prepare the diversification value R
            byte[] diversificationValue = new byte[8];
            Buffer.BlockCopy(atc, 0, diversificationValue, 0, atc.Length);
            // Remaining bytes are already zero-initialized

            // Calculate F1 and F2
            byte[] f1 = (byte[])diversificationValue.Clone();
            f1[2] = 0xF0;  // The third byte is set to 0xF0
            byte[] f2 = (byte[])diversificationValue.Clone();
            f2[2] = 0x0F;  // The third byte is set to 0x0F

            // Encrypt F1 and F2 with Triple DES
            byte[] encryptedF1 = EncryptWithTripleDES(masterKey, f1);
            byte[] encryptedF2 = EncryptWithTripleDES(masterKey, f2);

            // Concatenate the results and take the leftmost 16 bytes
            byte[] sessionKey = new byte[16];
            Buffer.BlockCopy(encryptedF1, 0, sessionKey, 0, 8);
            Buffer.BlockCopy(encryptedF2, 0, sessionKey, 8, 8);

            // Adjust parity of the session key
            sessionKey = AdjustParity(sessionKey);

            Debug.WriteLine($"Derived Session Key: {BitConverter.ToString(sessionKey).Replace("-", "")}");
            return sessionKey;
        }

        public static byte[] DeriveSessionKeyEMVCSK(byte[] udk, byte[] atc)
        {
            // Ensure the ATC is the correct length
            if (atc.Length != 2)
            {
                throw new ArgumentException("ATC must be 2 bytes.");
            }

            // Prepare the diversification value R
            byte[] diversificationValue = new byte[8];
            Buffer.BlockCopy(atc, 0, diversificationValue, 0, atc.Length);
            // Remaining bytes are already zero-initialized (6 bytes of '00')

            // Generate F1 and F2
            byte[] f1 = (byte[])diversificationValue.Clone();
            f1[2] = 0xF0;  // The third byte is set to 0xF0
            byte[] f2 = (byte[])diversificationValue.Clone();
            f2[2] = 0x0F;  // The third byte is set to 0x0F

            // Encrypt F1 and F2 with Triple DES using the UDK
            byte[] sessionKeyA = EncryptWithTripleDESECB(udk, f1);
            byte[] sessionKeyB = EncryptWithTripleDESECB(udk, f2);

            // Concatenate the results and adjust parity
            byte[] sessionKey = new byte[16];
            Buffer.BlockCopy(sessionKeyA, 0, sessionKey, 0, 8);
            Buffer.BlockCopy(sessionKeyB, 0, sessionKey, 8, 8);
            sessionKey = AdjustParity(sessionKey);

            Debug.WriteLine($"Derived Session Key EMVCSK: {BitConverter.ToString(sessionKey).Replace("-", "")}");
            return sessionKey;
        }


        public static byte[] DeriveSessionKeyMC(byte[] udk, byte[] atc, byte[] un)
        {
            if (atc.Length != 2)
            {
                throw new ArgumentException("ATC must be 2 bytes.");
            }
            if (un.Length != 4)
            {
                throw new ArgumentException("UN must be 4 bytes.");
            }

            // Form R as ATC + "0000" + UN
            byte[] r = new byte[8];
            Buffer.BlockCopy(atc, 0, r, 0, atc.Length);
            Buffer.BlockCopy(new byte[] { 0x00, 0x00 }, 0, r, 2, 2);
            Buffer.BlockCopy(un, 0, r, 4, un.Length);

            // Prepare SKL and SKR
            byte[] skLi = new byte[8];
            byte[] skRi = new byte[8];
            Buffer.BlockCopy(r, 0, skLi, 0, 2); // R0-R1
            Buffer.BlockCopy(r, 3, skLi, 3, 5); // R3-R4-R5-R6-R7
            Buffer.BlockCopy(r, 0, skRi, 0, 2); // R0-R1
            Buffer.BlockCopy(r, 3, skRi, 3, 5); // R3-R4-R5-R6-R7
            skLi[2] = 0xF0;
            skRi[2] = 0x0F;

            // Encrypt SKL and SKR with Triple DES using masterKey
            byte[] sessionKeyLeft = EncryptWithTripleDESECB(udk, skLi);
            byte[] sessionKeyRight = EncryptWithTripleDESECB(udk, skRi);

            // Concatenate SKL and SKR
            byte[] sessionKey = new byte[16];
            Buffer.BlockCopy(sessionKeyLeft, 0, sessionKey, 0, 8);
            Buffer.BlockCopy(sessionKeyRight, 0, sessionKey, 8, 8);

            return sessionKey;
        }

        private static byte[] EncryptWithTripleDESECB(byte[] key, byte[] data)
        {
            if (key.Length != 16 && key.Length != 24)
            {
                throw new ArgumentException("Key length must be 16 or 24 bytes for Triple DES.");
            }

            key = AdjustParity2(key);

            // Ensure the key is 24 bytes (192 bits)
            if (key.Length == 16)
            {
                key = key.Concat(key.Take(8)).ToArray();
            }

            using (var des = TripleDES.Create())
            {
                des.Key = key;
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;

                using (var encryptor = des.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }


        private static byte[] AdjustParity2(byte[] key)
        {
            for (int i = 0; i < key.Length; i++)
            {
                key[i] = SetOddParityForByte2(key[i]);
            }
            return key;
        }

        private static byte SetOddParityForByte2(byte b)
        {
            int bitCount = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & (1 << i)) != 0)
                {
                    bitCount++;
                }
            }
            if (bitCount % 2 == 0)
            {
                b ^= 1; // Flip the least significant bit to ensure odd parity
            }
            return b;
        }

        public static void VerifyMasterKey()
        {
            byte[] calculatedKCV = CalculateKCV(ICCMasterKey);
            if (calculatedKCV.SequenceEqual(ExpectedKCV))
            {
                Debug.WriteLine("Master Key KCV is valid.");
            }
            else
            {
                Debug.WriteLine("Master Key KCV is invalid.");
            }
        }

        public static byte[] DeriveUDK(byte[] masterKey, string pan, string panSequenceNumber)
        {
            // Concatenate PAN and PAN Sequence Number
            string x = pan + panSequenceNumber;
            if (x.Length < 16)
            {
                x = x.PadLeft(16, '0');
            }
            else
            {
                x = x.Substring(x.Length - 16);
            }

            byte[] y = HexStringToByteArray(x);

            if (masterKey.Length == 16)
            {
                masterKey = masterKey.Concat(masterKey.Take(8)).ToArray();
            }

            byte[] zl = EncryptWithTripleDES(masterKey, y);
            byte[] zr = EncryptWithTripleDES(masterKey, XorWithFF(y));

            byte[] udk = new byte[zl.Length + zr.Length];
            Buffer.BlockCopy(zl, 0, udk, 0, zl.Length);
            Buffer.BlockCopy(zr, 0, udk, zl.Length, zr.Length);

            udk = AdjustParity(udk);
            Debug.WriteLine($"Derived UDK: {BitConverter.ToString(udk).Replace("-", "")}");
            return udk;
        }



        private static byte[] CalculateKCV(byte[] key)
        {
            if (key.Length != 16 && key.Length != 24)
            {
                throw new ArgumentException("Key length must be 16 or 24 bytes for Triple DES.");
            }

            if (key.Length == 16)
            {
                key = key.Concat(key.Take(8)).ToArray();
            }

            using (var des = TripleDES.Create())
            {
                des.Key = key;
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;

                byte[] zeroBlock = new byte[8];
                byte[] encryptedBlock;

                using (var encryptor = des.CreateEncryptor())
                {
                    encryptedBlock = encryptor.TransformFinalBlock(zeroBlock, 0, zeroBlock.Length);
                }

                return encryptedBlock.Take(3).ToArray();
            }
        }

        public static byte[] DeriveMasterKey(byte[] imk, string pan, string panSequenceNumber)
        {
            // Concatenate PAN and PAN Sequence Number
            string x = pan + panSequenceNumber;
            if (x.Length < 16)
            {
                x = x.PadLeft(16, '0');
            }
            else
            {
                x = x.Substring(x.Length - 16);
            }

            byte[] y = HexStringToByteArray(x);

            if (imk.Length != 16 && imk.Length != 24)
            {
                throw new ArgumentException("IMK length must be 16 or 24 bytes.");
            }

            if (imk.Length == 16)
            {
                imk = imk.Concat(imk.Take(8)).ToArray();
            }

            byte[] zl = EncryptWithTripleDES(imk, y);
            byte[] zr = EncryptWithTripleDES(imk, XorWithFF(y));

            byte[] z = new byte[zl.Length + zr.Length];
            Buffer.BlockCopy(zl, 0, z, 0, zl.Length);
            Buffer.BlockCopy(zr, 0, z, zl.Length, zr.Length);

            for (int i = 0; i < z.Length; i++)
            {
                z[i] = SetOddParityForByte(z[i]);
            }

            Debug.WriteLine($"Derived Master Key: {BitConverter.ToString(z).Replace("-", "")}");
            return z;
        }

        // Convert hex string to byte array
        private static byte[] HexStringToByteArray(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        // Encrypt data with Triple DES
        private static byte[] EncryptWithTripleDES(byte[] key, byte[] data, byte[] iv = null)
        {
            if (key.Length != 16 && key.Length != 24)
            {
                throw new ArgumentException("Key length must be 16 or 24 bytes for Triple DES.");
            }

            // Adjust key parity
            key = AdjustParity(key);

            using (var des = TripleDES.Create())
            {
                // Triple DES requires a key size of either 128 or 192 bits
                if (key.Length == 16)
                {
                    // For a 16-byte key, duplicate the first 8 bytes to form a 24-byte key
                    key = key.Concat(key.Take(8)).ToArray();
                }

                des.Key = key;
                des.Mode = CipherMode.CBC;
                des.Padding = PaddingMode.None;
                des.IV = iv ?? new byte[8]; // Use provided IV or default to zero-initialized IV

                using (var encryptor = des.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        // XOR byte array with FF
        private static byte[] XorWithFF(byte[] data)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ 0xFF);
            }
            return result;
        }

        public static byte[] AdjustParity(byte[] key)
        {
            for (int i = 0; i < key.Length; i++)
            {
                key[i] = SetOddParityForByte(key[i]);
            }
            return key;
        }

        // Set odd parity for a single byte
        private static byte SetOddParityForByte(byte b)
        {
            int bitCount = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & (1 << i)) != 0)
                {
                    bitCount++;
                }
            }
            if (bitCount % 2 == 0)
            {
                b ^= 1; // Flip the least significant bit to ensure odd parity
            }
            return b;
        }
    }
}

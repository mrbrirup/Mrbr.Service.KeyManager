using System.Security.Cryptography;

namespace Mrbr.Service.KeyManager.Utilities;

public static class KeyGenerator {
    /// <summary>
    /// The chars that can be used for the random string
    /// </summary>
    public const string chars = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    /// <summary>
    /// The length of the chars string
    /// </summary>
    public static readonly int charLength = chars.Length;
    /// <summary>
    /// Generates a random string of the specified length.
    /// </summary>
    /// <param name="stringLength"></param>
    /// <remarks>
    /// Uses unsafe code for performance
    /// </remarks>
    /// <returns></returns>
    public static unsafe string GenerateRandomString(int stringLength) {
        var bytes = new byte[stringLength];
        using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(bytes); }
        fixed (byte* pBytes = bytes) {
            var result = new string('\0', stringLength);
            fixed (char* pResult = result) {
                for (int i = 0; i < stringLength; i++) {
                    pResult[i] = chars[pBytes[i] % charLength];
                }
            }
            return result;
        }
    }
}
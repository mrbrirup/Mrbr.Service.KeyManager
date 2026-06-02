using Mrbr.Service.KeyManager.Configuration;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Mrbr.Service.KeyManager.Services;

/// <summary>
/// Key Service Class
/// </summary>
public sealed class KeyService(KeyServiceOptions options) : IKeyService, IDisposable {
    private KeyServiceOptions KeyServiceOptions { get; init; } = options;
    public sealed record KeyServiceRecord(int Id, string Value, int MaxCharPosition, int KeyIdMask);

    /// <summary>
    /// Maximum number of keys in collection
    /// </summary>
    public const int MaxKeyCount = 8;
    /// <summary>
    /// Binary Shift Size for Key
    /// </summary>
    public const int keyPositionSize = 3;
    /// <summary>
    /// Binary Shift Size for Key Length    
    /// </summary>
    public const int keyLengthSize = 10;
    /// <summary>
    /// Binary Mask for Key
    /// </summary>
    /// <remarks>
    /// 0-7:3  0-1023:10    0-128:8
    /// [keyId][keyPosition][keyLength]
    /// </remarks>
    public const int keyIdMask = 7;
    /// <summary>
    /// Minimum supported KeyIdMask value. Lowest 3 key-id bits must remain unset.
    /// </summary>
    public const int MinKeyIdMaskValue = 8;
    /// <summary>
    /// Maximum supported KeyIdMask value. Lowest 3 key-id bits must remain unset.
    /// </summary>
    public const int MaxKeyIdMaskValue = int.MaxValue & ~7;
    /// <summary>
    /// Binary Mask for Key Position
    /// </summary>
    public const int keyPositionMask = 1023;
    /// <summary>
    /// Binary Mask for Key Length
    /// </summary>
    public const int keyLengthMask = 127;
    /// <summary>
    /// Minimum Mask Length
    /// </summary>
    public const int minMaskLength = 64;
    /// <summary>
    /// Calculated size of key position and length
    /// </summary>
    public const int keyPositionAndLength = keyPositionSize + keyLengthSize;
    /// <summary>
    /// Random Mask Length. Total Mask Length = minMaskLength + randomMaskLength * 2
    /// </summary>
    public const int randomMaskLength = 32;
    /// <summary>
    /// Maximum Mask Length
    /// </summary>
    /// <remarks>
    /// Total Mask Length = minMaskLength + randomMaskLength * 2
    /// </remarks>
    public const int MaxMaskLength = minMaskLength + randomMaskLength * 2;
    public const int KeySize128 = 16;
    public const int KeySize192 = 24;
    public const int KeySize256 = 32;
    /// <summary>
    /// Array of Keys. Large key source strings to pull keys from
    /// </summary>
    /// <remarks>
    /// KeyId: Key
    /// </remarks>
    private static KeyServiceRecord?[] Keys => KeyServiceOptions.Keys;
    private static int KeyCount => KeyServiceOptions.KeyCount;
    /// <summary>
    /// Generate a New Key for the Key Manager
    /// </summary>
    /// <param name="keyResult">Integer key to calculate size and position from</param>
    /// <returns>String value of key, as substring of the Key Source in the Keys dictionary</returns>
    /// <remarks>
    /// 0-7:3  0-1023:10    0-128:8        
    ///  [keyId][keyPosition][keyLength]
    /// </remarks>
    public ReadOnlyMemory<char> GenerateKey(out int keyResult) {
        var keyServiceRecord = GetKeyServiceRecord(GetRandomKeyId());
        int keyLength = minMaskLength + (RandomNumberGenerator.GetInt32(randomMaskLength) << 1),
            keyPosition = RandomNumberGenerator.GetInt32(keyServiceRecord.MaxCharPosition);
        //   0-7:3  0-1023:10    0-128:8        
        //  [keyId][keyPosition][keyLength]
        var originalKeyResult = keyServiceRecord.Id +
                                (keyPosition << keyPositionSize) +
                                (keyLength << keyPositionAndLength);
        keyResult = ApplyKeyIdMask(originalKeyResult, keyServiceRecord.KeyIdMask);
        return KeyServiceOptions.KeyMemory[keyServiceRecord.Id].Slice(keyPosition, keyLength);
    }

    public byte[] GenerateKey128(out int keyResult, KeyDerivationOptions options = default) => GenerateKeyBytes(KeySize128, out keyResult, options);
    public byte[] GenerateKey192(out int keyResult, KeyDerivationOptions options = default) => GenerateKeyBytes(KeySize192, out keyResult, options);
    public byte[] GenerateKey256(out int keyResult, KeyDerivationOptions options = default) => GenerateKeyBytes(KeySize256, out keyResult, options);

    public void GenerateKeyBytes(Span<byte> destination, out int keyResult, KeyDerivationOptions options = default) {
        ValidateKeySize(destination.Length);
        var keyMaterial = GenerateKey(out keyResult);
        DeriveKeyBytes(keyMaterial, keyResult, destination, options);
    }

    public byte[] GenerateKeyBytes(int keySizeInBytes, out int keyResult, KeyDerivationOptions options = default) {
        ValidateKeySize(keySizeInBytes);
        var keyMaterial = GenerateKey(out keyResult);
        return DeriveKeyBytes(keyMaterial, keyResult, keySizeInBytes, options);
    }

    public void GenerateKey128(Span<byte> destination, out int keyResult, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize128);
        GenerateKeyBytes(destination, out keyResult, options);
    }

    public void GenerateKey192(Span<byte> destination, out int keyResult, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize192);
        GenerateKeyBytes(destination, out keyResult, options);
    }

    public void GenerateKey256(Span<byte> destination, out int keyResult, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize256);
        GenerateKeyBytes(destination, out keyResult, options);
    }

    public Task<(ReadOnlyMemory<char> Key, int Id)> GenerateKeyAsync() {
        var keyServiceRecord = GetKeyServiceRecord(GetRandomKeyId());
        int keyLength = minMaskLength + (RandomNumberGenerator.GetInt32(randomMaskLength) << 1),
            keyPosition = RandomNumberGenerator.GetInt32(keyServiceRecord.MaxCharPosition);
        //   0-7:3  0-1023:10    0-128:8        
        //  [keyId][keyPosition][keyLength]
        var originalKeyResult = keyServiceRecord.Id +
                                (keyPosition << keyPositionSize) +
                                (keyLength << keyPositionAndLength);
        int maskedKeyResult = ApplyKeyIdMask(originalKeyResult, keyServiceRecord.KeyIdMask);
        return Task.FromResult((KeyServiceOptions.KeyMemory[keyServiceRecord.Id].Slice(keyPosition, keyLength), maskedKeyResult));
    }

    /// <summary>
    /// Get the Key text from the Source Keys using the Key Id
    /// </summary>
    /// <param name="keyResult"></param>
    /// <returns></returns>
    public ReadOnlyMemory<char> GetKey(int keyResult) {
        int keyId = keyResult & keyIdMask;
        var keyServiceRecord = GetKeyServiceRecord(keyId);
        var unmaskedKeyResult = UnmaskKeyResult(keyResult, keyServiceRecord);

        int keyPosition = (unmaskedKeyResult >> keyPositionSize) & keyPositionMask,
            keyLength = (unmaskedKeyResult >> keyPositionAndLength) & keyLengthMask;

        return KeyServiceOptions.KeyMemory[keyId].Slice(keyPosition, keyLength);
    }

    public byte[] GetKey128(int keyResult, KeyDerivationOptions options = default) => GetKeyBytes(keyResult, KeySize128, options);
    public byte[] GetKey192(int keyResult, KeyDerivationOptions options = default) => GetKeyBytes(keyResult, KeySize192, options);
    public byte[] GetKey256(int keyResult, KeyDerivationOptions options = default) => GetKeyBytes(keyResult, KeySize256, options);

    public void GetKeyBytes(int keyResult, Span<byte> destination, KeyDerivationOptions options = default) {
        ValidateKeySize(destination.Length);
        var keyMaterial = GetKey(keyResult);
        DeriveKeyBytes(keyMaterial, keyResult, destination, options);
    }

    public byte[] GetKeyBytes(int keyResult, int keySizeInBytes, KeyDerivationOptions options = default) {
        ValidateKeySize(keySizeInBytes);
        var keyMaterial = GetKey(keyResult);
        return DeriveKeyBytes(keyMaterial, keyResult, keySizeInBytes, options);
    }

    public void GetKey128(int keyResult, Span<byte> destination, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize128);
        GetKeyBytes(keyResult, destination, options);
    }

    public void GetKey192(int keyResult, Span<byte> destination, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize192);
        GetKeyBytes(keyResult, destination, options);
    }

    public void GetKey256(int keyResult, Span<byte> destination, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize256);
        GetKeyBytes(keyResult, destination, options);
    }

    public Task<ReadOnlyMemory<char>> GetKeyAsync(int keyResult) {
        int keyId = keyResult & keyIdMask;
        var keyServiceRecord = GetKeyServiceRecord(keyId);
        var unmaskedKeyResult = UnmaskKeyResult(keyResult, keyServiceRecord);

        int keyPosition = (unmaskedKeyResult >> keyPositionSize) & keyPositionMask,
            keyLength = (unmaskedKeyResult >> keyPositionAndLength) & keyLengthMask;

        return Task.FromResult(KeyServiceOptions.KeyMemory[keyId].Slice(keyPosition, keyLength));
    }

    /// <summary>
    /// Does the Key Service contain the Key Id
    /// </summary>
    /// <param name="keyId"></param>
    /// <returns></returns>
    public bool ContainsKey(int keyId) => keyId >= 0 && keyId < KeyService.MaxKeyCount && Keys[keyId] != null;
    /// <summary>
    /// Delete the Key Id from the Key Manager
    /// </summary>
    /// <param name="keyId"></param>
    /// <returns></returns>
    public bool DeleteKey(int keyId) => KeyServiceOptions.DeleteKey(keyId);

    /// <summary>
    /// Delete all Keys from the Key Manager
    /// </summary>
    /// <returns></returns>
    public bool DeleteAllKeys() => KeyServiceOptions.DeleteAllKeys();

    /// <summary>
    /// Get a Random Key Id
    /// </summary>
    /// <returns></returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int GetRandomKeyId() => RandomNumberGenerator.GetInt32(KeyCount);
    /// <summary>
    /// Get the Key Service Record
    /// </summary>
    /// <param name="keyId"></param>
    /// <returns></returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static KeyServiceRecord GetKeyServiceRecord(int keyId) {
        if (keyId >= 0 && keyId < KeyService.MaxKeyCount) {
            var record = Keys[keyId];
            if (record != null) {
                return record;
            }
        }

        throw new KeyNotFoundException($"No key configuration exists for key id '{keyId}'.");
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int ApplyKeyIdMask(int keyResult, int keyMaskId) {
        var effectiveMask = keyMaskId & ~keyIdMask;
        return keyResult ^ effectiveMask;
    }

    private static int UnmaskKeyResult(int maskedKeyResult, KeyServiceRecord keyServiceRecord) {
        var unmaskedKeyResult = ApplyKeyIdMask(maskedKeyResult, keyServiceRecord.KeyIdMask);
        int decodedKeyId = unmaskedKeyResult & keyIdMask,
            keyPosition = (unmaskedKeyResult >> keyPositionSize) & keyPositionMask,
            keyLength = (unmaskedKeyResult >> keyPositionAndLength) & keyLengthMask;

        if (decodedKeyId != keyServiceRecord.Id) {
            throw new InvalidOperationException($"KeyIdMask for key id '{keyServiceRecord.Id}' modifies key id bits and is invalid.");
        }

        if (keyLength < minMaskLength || keyLength > MaxMaskLength) {
            throw new ArgumentOutOfRangeException(nameof(maskedKeyResult), "Decoded key length is outside supported range.");
        }

        if (keyPosition < 0 || keyPosition + keyLength > keyServiceRecord.Value.Length) {
            throw new ArgumentOutOfRangeException(nameof(maskedKeyResult), "Decoded key position and length are outside configured key bounds.");
        }

        return unmaskedKeyResult;
    }

    private static byte[] DeriveKeyBytes(ReadOnlyMemory<char> keyMaterial, int keyResult, int keySizeInBytes, KeyDerivationOptions options) {
        var derivedKey = GC.AllocateUninitializedArray<byte>(keySizeInBytes);
        DeriveKeyBytes(keyMaterial, keyResult, derivedKey, options);
        return derivedKey;
    }

    private static void DeriveKeyBytes(ReadOnlyMemory<char> keyMaterial, int keyResult, Span<byte> destination, KeyDerivationOptions options) {
        ValidateKeySize(destination.Length);

        var keyChars = keyMaterial.Span;
        int byteCount = Encoding.UTF8.GetByteCount(keyChars);
        byte[] rentedBytes = ArrayPool<byte>.Shared.Rent(byteCount);
        try {
            int bytesWritten = Encoding.UTF8.GetBytes(keyChars, rentedBytes);
            var sourceKey = rentedBytes.AsSpan(0, bytesWritten);
            switch (options.Algorithm) {
                case KeyDerivationAlgorithm.Sha256:
                    DeriveSha256(sourceKey, destination);
                    break;
                case KeyDerivationAlgorithm.HkdfSha256:
                    DeriveHkdfSha256(sourceKey, keyResult, destination, options);
                    break;
                case KeyDerivationAlgorithm.Pbkdf2Sha256:
                    DerivePbkdf2Sha256(sourceKey, keyResult, destination, options);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(options), options.Algorithm, "Unsupported key derivation algorithm.");
            }
        }
        finally {
            ArrayPool<byte>.Shared.Return(rentedBytes, clearArray: true);
        }
    }

    private static void DeriveSha256(ReadOnlySpan<byte> sourceKey, Span<byte> destination) {
        var hash = SHA256.HashData(sourceKey);
        try {
            hash.AsSpan(0, destination.Length).CopyTo(destination);
        }
        finally {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static void DeriveHkdfSha256(ReadOnlySpan<byte> sourceKey, int keyResult, Span<byte> destination, KeyDerivationOptions options) {
        Span<byte> defaultSalt = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(defaultSalt, keyResult);
        var salt = options.Salt.IsEmpty ? defaultSalt : options.Salt.Span;

        byte[] saltBytes = salt.ToArray();
        byte[] sourceBytes = sourceKey.ToArray();
        byte[]? pseudorandomKey = null;
        byte[] expandInput = new byte[options.Info.Length + 1];
        byte[]? expandedBlock = null;

        try {
            using (var extractHmac = new HMACSHA256(saltBytes)) {
                pseudorandomKey = extractHmac.ComputeHash(sourceBytes);
            }

            options.Info.Span.CopyTo(expandInput);
            expandInput[^1] = 0x01;
            using (var expandHmac = new HMACSHA256(pseudorandomKey)) {
                expandedBlock = expandHmac.ComputeHash(expandInput);
            }

            expandedBlock.AsSpan(0, destination.Length).CopyTo(destination);
        }
        finally {
            CryptographicOperations.ZeroMemory(saltBytes);
            CryptographicOperations.ZeroMemory(sourceBytes);
            CryptographicOperations.ZeroMemory(expandInput);
            if (pseudorandomKey is not null) {
                CryptographicOperations.ZeroMemory(pseudorandomKey);
            }
            if (expandedBlock is not null) {
                CryptographicOperations.ZeroMemory(expandedBlock);
            }
        }
    }

    private static void DerivePbkdf2Sha256(ReadOnlySpan<byte> sourceKey, int keyResult, Span<byte> destination, KeyDerivationOptions options) {
        Span<byte> defaultSalt = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(defaultSalt, keyResult);
        var salt = options.Salt.IsEmpty ? defaultSalt : options.Salt.Span;
        int iterationCount = options.IterationCount > 0 ? options.IterationCount : KeyDerivationOptions.DefaultPbkdf2IterationCount;

        Rfc2898DeriveBytes.Pbkdf2(sourceKey, salt, destination, iterationCount, HashAlgorithmName.SHA256);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ValidateKeySize(int keySizeInBytes) {
        if (keySizeInBytes != KeySize128 && keySizeInBytes != KeySize192 && keySizeInBytes != KeySize256) {
            throw new ArgumentOutOfRangeException(nameof(keySizeInBytes), "Supported key sizes are 16, 24, and 32 bytes.");
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ValidateNamedKeySize(int actualSize, int expectedSize) {
        if (actualSize != expectedSize) {
            throw new ArgumentException($"Destination must be {expectedSize} bytes.", nameof(expectedSize));
        }
    }

    public void Dispose() {
        GC.SuppressFinalize(this);
    }

}
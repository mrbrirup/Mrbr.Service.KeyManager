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
//public sealed class KeyService(KeyServiceOptions options) : IKeyService, IDisposable {
public sealed class KeyService : IKeyService, IDisposable {
    public KeyServiceOptions KeyServiceOptions { get; init; }
    //public KeyServiceOptions KeyServiceOptions { get; init; } = options;

    public KeyService(KeyServiceOptions options) {
        this.KeyServiceOptions = options;
    }


    /// <summary>
    /// Record containing key configuration information.
    /// </summary>
    /// <param name="Id">Key ID (0-255)</param>
    /// <param name="Value">Source text for key generation</param>
    /// <param name="MaxCharPosition">Maximum position for Block key extraction</param>
    /// <param name="KeyIdMask">Obfuscation mask for key ID</param>
    /// <param name="Type">Key generation type (Block or Matrix)</param>
    /// <param name="BlockSettings">Block-specific settings (when Type is Block)</param>
    /// <param name="MatrixSettings">Matrix-specific settings (when Type is Matrix)</param>
    public sealed record KeyServiceRecord(
        int Id,
        string Value,
        int MaxCharPosition,
        int KeyIdMask,
        Configuration.KeyType Type,
        Configuration.KeyBlockSettings? BlockSettings,
        Configuration.KeyMatrixSettings? MatrixSettings
    );

    /// <summary>
    /// Maximum number of keys in collection (0-255)
    /// </summary>
    public const int MaxKeyCount = 256;
    /// <summary>
    /// Binary Shift Size for Key ID (8 bits for 256 keys)
    /// </summary>
    public const int keyPositionSize = 16;
    /// <summary>
    /// Binary Shift Size for Key Length    
    /// </summary>
    public const int keyLengthSize = 8;
    /// <summary>
    /// Binary Mask for Key ID (0-255)
    /// </summary>
    /// <remarks>
    /// Block format: 0-255:8  0-1023:10    0-128:8
    /// [keyId][keyPosition][keyLength]
    /// </remarks>
    public const int keyIdMask = 255;
    /// <summary>
    /// Minimum supported KeyIdMask value. Lowest 8 key-id bits must remain unset.
    /// </summary>
    public const int MinKeyIdMaskValue = 256;
    /// <summary>
    /// Maximum supported KeyIdMask value. Lowest 8 key-id bits must remain unset.
    /// </summary>
    public const int MaxKeyIdMaskValue = int.MaxValue & ~255;
    /// <summary>
    /// Binary Mask for Key Position
    /// </summary>
    public static readonly int keyPositionMask = 65_535;
    /// <summary>
    /// Binary Mask for Key Length
    /// </summary>
    public static readonly int keyLengthMask = 127;
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
    /// Bit shift used to encode Matrix startPosition in keyResult bits 8-30.
    /// Matrix keyResult format: [startPosition:23][keyId:8]
    /// </summary>
    public const int matrixStartPositionSize = 8;
    /// <summary>
    /// Bitmask to extract the 23-bit Matrix startPosition from keyResult after shifting.
    /// Covers start positions 0-8,388,607 (more than enough for any practical matrix).
    /// </summary>
    public const int matrixStartPositionMask = 0x7FFFFF;

    /// <summary>
    /// Key Generation Architecture Notes:
    /// 
    /// BLOCK KEYS (1D Contiguous Extraction with Wrap-Around):
    /// - keyResult format: [keyLength:10][keyPosition:10][keyId:8] = 28 bits
    /// - Extracts contiguous key material from source text with wrap-around
    /// - keyResult alone is sufficient to reproduce identical key material
    /// 
    /// MATRIX KEYS (3D Vector-Based Navigation):
    /// - keyResult format: [startPosition:23][keyId:8] = 31 bits
    /// - Vectors are derived deterministically via DeriveVectors(sourceText, startPosition)
    ///   so keyResult alone is sufficient to reproduce identical key bytes
    /// - GetKey(keyResult) returns ReadOnlyMemory<char>.Empty for Matrix keys;
    ///   use GetKeyBytes / GetKey128 / GetKey192 / GetKey256 to retrieve byte output
    /// </summary>

    /// <summary>
    /// Array of Keys. Large key source strings to pull keys from (0-255)
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
    /// Block format: 0-255:8  0-1023:10    0-128:8        
    ///  [keyId][keyPosition][keyLength]
    /// Note: For Matrix keys, this generates a random key but returns empty memory. 
    /// Use GenerateKeyBytes() methods for actual cryptographic material.
    /// </remarks>
    public ReadOnlyMemory<char> GenerateKey(out int keyResult) {
        var keyServiceRecord = GetKeyServiceRecord(GetRandomKeyId());

        if (keyServiceRecord.Type == Configuration.KeyType.Block) {
            // Block key generation with wrap-around support
            int keyLength = minMaskLength + (RandomNumberGenerator.GetInt32(randomMaskLength) << 1),
                keyPosition = RandomNumberGenerator.GetInt32(keyServiceRecord.Value.Length);

            var test = (keyPosition << keyPositionSize);
            //   0-255:8  0-1023:10    0-128:8
            //  [keyId][keyPosition][keyLength]
            var originalKeyResult = keyServiceRecord.Id +
                                    (keyPosition << keyPositionSize) +
                                    (keyLength << keyPositionAndLength);
            keyResult = ApplyKeyIdMask(originalKeyResult, keyServiceRecord.KeyIdMask);
            return GetBlockKeyMaterial(KeyServiceOptions.KeyMemory[keyServiceRecord.Id], keyPosition, keyLength);
        }
        else {
            // Matrix key generation — generate a start position, derive vectors deterministically,
            // and encode both keyId and startPosition into the returned keyResult int.
            var matrixGenerator = new Matrices.MatrixKeyGenerator(keyServiceRecord.MatrixSettings!);
            var matrixResult = matrixGenerator.GenerateKey(
                keyServiceRecord.Value,
                (byte)keyServiceRecord.Id,
                KeySize128 // minimum size; only startPosition is needed from this call
            );
            keyResult = ApplyKeyIdMask(
                keyServiceRecord.Id | (matrixResult.StartPosition << matrixStartPositionSize),
                keyServiceRecord.KeyIdMask
            );
            return ReadOnlyMemory<char>.Empty;
        }
    }

    public byte[] GenerateKey128(out int keyResult, KeyDerivationOptions options = default) => GenerateKeyBytes(KeySize128, out keyResult, options);
    public byte[] GenerateKey192(out int keyResult, KeyDerivationOptions options = default) => GenerateKeyBytes(KeySize192, out keyResult, options);
    public byte[] GenerateKey256(out int keyResult, KeyDerivationOptions options = default) => GenerateKeyBytes(KeySize256, out keyResult, options);

    public void GenerateKeyBytes(Span<byte> destination, out int keyResult, KeyDerivationOptions options = default) {
        ValidateKeySize(destination.Length);

        // Get a random key ID and check its type
        int randomKeyId = GetRandomKeyId();
        var keyServiceRecord = GetKeyServiceRecord(randomKeyId);

        if (keyServiceRecord.Type == Configuration.KeyType.Block) {
            // Block key generation (original path)
            var keyMaterial = GenerateKey(out keyResult);
            DeriveKeyBytes(keyMaterial, keyResult, destination, options);
        }
        else {
            // Matrix key generation using MatrixKeyGenerator
            var matrixGenerator = new Matrices.MatrixKeyGenerator(keyServiceRecord.MatrixSettings!);
            var matrixResult = matrixGenerator.GenerateKey(
                keyServiceRecord.Value,
                (byte)keyServiceRecord.Id,
                destination.Length
            );

            matrixResult.KeyBytes.CopyTo(destination);
            // Encode keyId (bits 0-7) and startPosition (bits 8-30) into keyResult
            keyResult = ApplyKeyIdMask(
                keyServiceRecord.Id | (matrixResult.StartPosition << matrixStartPositionSize),
                keyServiceRecord.KeyIdMask
            );
        }
    }

    public byte[] GenerateKeyBytes(int keySizeInBytes, out int keyResult, KeyDerivationOptions options = default) {
        ValidateKeySize(keySizeInBytes);

        // Get a random key ID and check its type
        int randomKeyId = GetRandomKeyId();
        var keyServiceRecord = GetKeyServiceRecord(randomKeyId);

        if (keyServiceRecord.Type == Configuration.KeyType.Block) {
            // Block key generation (original path)
            var keyMaterial = GenerateKey(out keyResult);
            return DeriveKeyBytes(keyMaterial, keyResult, keySizeInBytes, options);
        }
        else {
            // Matrix key generation using MatrixKeyGenerator
            var matrixGenerator = new Matrices.MatrixKeyGenerator(keyServiceRecord.MatrixSettings!);
            var matrixResult = matrixGenerator.GenerateKey(
                keyServiceRecord.Value,
                (byte)keyServiceRecord.Id,
                keySizeInBytes
            );

            // Encode keyId (bits 0-7) and startPosition (bits 8-30) into keyResult
            keyResult = ApplyKeyIdMask(
                keyServiceRecord.Id | (matrixResult.StartPosition << matrixStartPositionSize),
                keyServiceRecord.KeyIdMask
            );
            return matrixResult.KeyBytes;
        }
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

        if (keyServiceRecord.Type == Configuration.KeyType.Block) {
            int keyLength = minMaskLength + (RandomNumberGenerator.GetInt32(randomMaskLength) << 1),
                keyPosition = RandomNumberGenerator.GetInt32(keyServiceRecord.Value.Length);
            //   0-255:8  0-1023:20    0-128:8
            //  [keyId][keyPosition][keyLength]
            var originalKeyResult = keyServiceRecord.Id +
                                    (keyPosition << keyPositionSize) +
                                    (keyLength << keyPositionAndLength);
            int maskedKeyResult = ApplyKeyIdMask(originalKeyResult, keyServiceRecord.KeyIdMask);
            var keyMaterial = GetBlockKeyMaterial(KeyServiceOptions.KeyMemory[keyServiceRecord.Id], keyPosition, keyLength);
            return Task.FromResult((keyMaterial, maskedKeyResult));
        }
        else {
            // Matrix key generation — encode startPosition for later reproduction
            var matrixGenerator = new Matrices.MatrixKeyGenerator(keyServiceRecord.MatrixSettings!);
            var matrixResult = matrixGenerator.GenerateKey(
                keyServiceRecord.Value,
                (byte)keyServiceRecord.Id,
                KeySize128 // minimum size; only startPosition is needed
            );
            int maskedKeyResult = ApplyKeyIdMask(
                keyServiceRecord.Id | (matrixResult.StartPosition << matrixStartPositionSize),
                keyServiceRecord.KeyIdMask
            );
            return Task.FromResult((ReadOnlyMemory<char>.Empty, maskedKeyResult));
        }
    }

    /// <summary>
    /// Get the Key text from the Source Keys using the Key Id.
    /// </summary>
    /// <remarks>
    /// Returns char material for Block keys only.
    /// Matrix keys do not produce char-based output; call GetKeyBytes / GetKey128 / GetKey192 / GetKey256 instead.
    /// </remarks>
    public ReadOnlyMemory<char> GetKey(int keyResult) {
        int keyId = keyResult & keyIdMask;
        var keyServiceRecord = GetKeyServiceRecord(keyId);

        if (keyServiceRecord.Type == Configuration.KeyType.Matrix) {
            return ReadOnlyMemory<char>.Empty;
        }

        var unmaskedKeyResult = UnmaskKeyResult(keyResult, keyServiceRecord);



        int keyPosition = (unmaskedKeyResult >> keyPositionSize) & keyPositionMask,
            keyLength = (unmaskedKeyResult >> keyPositionAndLength) & keyLengthMask;

        return GetBlockKeyMaterial(KeyServiceOptions.KeyMemory[keyId], keyPosition, keyLength);
    }

    public byte[] GetKey128(int keyResult, KeyDerivationOptions options = default) => GetKeyBytes(keyResult, KeySize128, options);
    public byte[] GetKey192(int keyResult, KeyDerivationOptions options = default) => GetKeyBytes(keyResult, KeySize192, options);
    public byte[] GetKey256(int keyResult, KeyDerivationOptions options = default) => GetKeyBytes(keyResult, KeySize256, options);

    public void GetKeyBytes(int keyResult, Span<byte> destination, KeyDerivationOptions options = default) {
        ValidateKeySize(destination.Length);
        int keyId = keyResult & keyIdMask;
        var keyServiceRecord = GetKeyServiceRecord(keyId);

        if (keyServiceRecord.Type == Configuration.KeyType.Matrix) {
            var unmasked = ApplyKeyIdMask(keyResult, keyServiceRecord.KeyIdMask);
            int startPosition = (unmasked >> matrixStartPositionSize) & matrixStartPositionMask;
            var matrixGenerator = new Matrices.MatrixKeyGenerator(keyServiceRecord.MatrixSettings!);
            var matrixResult = matrixGenerator.RegenerateKey(keyServiceRecord.Value, (byte)keyId, startPosition, destination.Length);
            matrixResult.KeyBytes.CopyTo(destination);
        }
        else {
            var keyMaterial = GetKey(keyResult);
            DeriveKeyBytes(keyMaterial, keyResult, destination, options);
        }
    }

    public byte[] GetKeyBytes(int keyResult, int keySizeInBytes, KeyDerivationOptions options = default) {
        ValidateKeySize(keySizeInBytes);
        int keyId = keyResult & keyIdMask;
        var keyServiceRecord = GetKeyServiceRecord(keyId);

        if (keyServiceRecord.Type == Configuration.KeyType.Matrix) {
            var unmasked = ApplyKeyIdMask(keyResult, keyServiceRecord.KeyIdMask);
            int startPosition = (unmasked >> matrixStartPositionSize) & matrixStartPositionMask;
            var matrixGenerator = new Matrices.MatrixKeyGenerator(keyServiceRecord.MatrixSettings!);
            return matrixGenerator.RegenerateKey(keyServiceRecord.Value, (byte)keyId, startPosition, keySizeInBytes).KeyBytes;
        }
        else {
            var keyMaterial = GetKey(keyResult);
            return DeriveKeyBytes(keyMaterial, keyResult, keySizeInBytes, options);
        }
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

        if (keyServiceRecord.Type == Configuration.KeyType.Matrix) {
            return Task.FromResult(ReadOnlyMemory<char>.Empty);
        }

        var unmaskedKeyResult = UnmaskKeyResult(keyResult, keyServiceRecord);

        int keyPosition = (unmaskedKeyResult >> keyPositionSize) & keyPositionMask,
            keyLength = (unmaskedKeyResult >> keyPositionAndLength) & keyLengthMask;

        return Task.FromResult(GetBlockKeyMaterial(KeyServiceOptions.KeyMemory[keyId], keyPosition, keyLength));
    }

    /// <summary>
    /// Does the Key Service contain the Key Id (0-255)
    /// </summary>
    /// <param name="keyId">Key identifier (0-255)</param>
    /// <returns>True if key exists</returns>
    public bool ContainsKey(int keyId) => keyId >= 0 && keyId < KeyService.MaxKeyCount && Keys[keyId] != null;
    /// <summary>
    /// Delete the Key Id from the Key Manager (0-255)
    /// </summary>
    /// <param name="keyId">Key identifier (0-255)</param>
    /// <returns>True if key was deleted</returns>
    public bool DeleteKey(int keyId) => KeyServiceOptions.DeleteKey(keyId);

    /// <summary>
    /// Delete all Keys from the Key Manager (all 256 slots)
    /// </summary>
    /// <returns>True if any keys were deleted</returns>
    public bool DeleteAllKeys() => KeyServiceOptions.DeleteAllKeys();

    /// <summary>
    /// Get a Random Key Id (0-255)
    /// </summary>
    /// <returns>Random key ID between 0 and 255</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int GetRandomKeyId() => RandomNumberGenerator.GetInt32(KeyCount);
    /// <summary>
    /// Get the Key Service Record for a given key ID (0-255)
    /// </summary>
    /// <param name="keyId">Key identifier (0-255)</param>
    /// <returns>KeyServiceRecord containing key configuration</returns>
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
        //var effectiveMask = keyMaskId & ~keyIdMask;
        var effectiveMask = keyMaskId;// & ~keyIdMask;
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
            //throw new ArgumentOutOfRangeException(nameof(maskedKeyResult), "Decoded key length is outside supported range.");
        }

        if (keyPosition < 0 || keyPosition >= keyServiceRecord.Value.Length) {
            throw new ArgumentOutOfRangeException(nameof(maskedKeyResult), "Decoded key position is outside configured key bounds.");
        }

        if (keyLength > keyServiceRecord.Value.Length) {
            throw new ArgumentOutOfRangeException(nameof(maskedKeyResult), "Decoded key length cannot exceed configured source length.");
        }

        return unmaskedKeyResult;
    }

    private static ReadOnlyMemory<char> GetBlockKeyMaterial(ReadOnlyMemory<char> source, int keyPosition, int keyLength) {
        var sourceSpan = source.Span;
        int sourceLength = sourceSpan.Length;

        if (keyPosition + keyLength <= sourceLength) {
            return source.Slice(keyPosition, keyLength);
        }

        int firstSegmentLength = sourceLength - keyPosition;
        int secondSegmentLength = keyLength - firstSegmentLength;
        char[] wrapped = GC.AllocateUninitializedArray<char>(keyLength);
        sourceSpan.Slice(keyPosition, firstSegmentLength).CopyTo(wrapped.AsSpan(0, firstSegmentLength));
        sourceSpan.Slice(0, secondSegmentLength).CopyTo(wrapped.AsSpan(firstSegmentLength, secondSegmentLength));
        return wrapped;
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
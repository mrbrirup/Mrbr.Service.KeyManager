using Mrbr.Service.KeyManager.Compression;
using Mrbr.Service.KeyManager.Configuration;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Mrbr.Service.KeyManager.Services;

/// <summary>
/// Provides cryptographic key generation and retrieval services supporting two distinct key architectures:
/// <list type="bullet">
///   <item>
///     <description>
///       <b>Block</b> — extracts contiguous character material from a large source string with wrap-around.
///       The encoded <c>keyResult</c> token carries the key ID, start position, and length.
///     </description>
///   </item>
///   <item>
///     <description>
///       <b>Matrix</b> — produces key bytes through a 3-D vector-based traversal of the source text.
///       The encoded <c>keyResult</c> token carries the key ID and start position; vectors are
///       re-derived deterministically on retrieval so no additional state is required.
///     </description>
///   </item>
/// </list>
/// In both cases a single <c>keyResult</c> value is sufficient to reproduce identical key material.
/// The token may be optionally obfuscated by a per-key XOR mask (<see cref="KeyServiceRecord.KeyIdMask"/>).
/// </summary>
/// <param name="options">
/// The <see cref="KeyServiceOptions"/> that supplies key source data, key-type settings,
/// and per-slot configuration for all registered keys.
/// </param>
public sealed class KeyService(KeyServiceOptions options) : IKeyService, IDisposable {
    /// <summary>
    /// Gets the key service configuration options used to initialise this instance.
    /// </summary>
    public KeyServiceOptions KeyServiceOptions { get; init; } = options;
    //public KeyServiceOptions KeyServiceOptions { get; init; } = options;



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
    /// <summary>
    /// Key size constant representing a 128-bit (16-byte) AES key.
    /// </summary>
    public const int KeySize128 = 16;
    /// <summary>
    /// Key size constant representing a 192-bit (24-byte) AES key.
    /// </summary>
    public const int KeySize192 = 24;
    /// <summary>
    /// Key size constant representing a 256-bit (32-byte) AES key.
    /// </summary>
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
    /// - GetKey(keyResult) returns ReadOnlyMemory&lt;char&gt;.Empty for Matrix keys;
    ///   use GetKeyBytes / GetKey128 / GetKey192 / GetKey256 to retrieve byte output
    /// </summary>

    /// <summary>
    /// Array of Keys. Large key source strings to pull keys from (0-255)
    /// </summary>
    /// <remarks>
    /// KeyId: Key
    /// </remarks>
    private static KeyServiceRecord?[] Keys => KeyServiceOptions.Keys;
    /// <summary>
    /// Gets the number of key slots currently registered in the key service.
    /// </summary>
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
    public ReadOnlyMemory<char> GenerateKey(out ulong keyResult) {
        var keyServiceRecord = GetKeyServiceRecord(GetRandomKeyId());

        if (keyServiceRecord.Type == Configuration.KeyType.Block) {
            // Block key generation with wrap-around support
            ulong keyLength = (ulong)minMaskLength + (ulong)(RandomNumberGenerator.GetInt32(randomMaskLength) << 1),
                keyPosition = (ulong)RandomNumberGenerator.GetInt32(keyServiceRecord.Value.Length);

            var test = (keyPosition << keyPositionSize);
            //   0-255:8  0-1023:10    0-128:8
            //  [keyId][keyPosition][keyLength]
            var originalKeyResult = (ulong)keyServiceRecord.Id +
                                    (keyPosition << keyPositionSize) +
                                    (keyLength << keyPositionAndLength);
            keyResult = ApplyKeyIdMask((ulong)originalKeyResult, (ulong)keyServiceRecord.KeyIdMask);
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
                (ulong)keyServiceRecord.Id | (matrixResult.StartPosition << matrixStartPositionSize),
                (ulong)keyServiceRecord.KeyIdMask
            );
            return ReadOnlyMemory<char>.Empty;
        }
    }

    /// <summary>
    /// Generates a new 128-bit (16-byte) cryptographic key and returns it as a byte array.
    /// </summary>
    /// <param name="keyResult">
    /// When this method returns, contains the encoded key token that can be used to reproduce
    /// the same key bytes via <see cref="GetKey128(ulong, KeyDerivationOptions)"/>.
    /// </param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm (SHA-256, HKDF-SHA-256, or PBKDF2-SHA-256)
    /// and any associated parameters such as salt and iteration count.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <returns>A 16-byte array containing the derived cryptographic key.</returns>
    public byte[] GenerateKey128(out ulong keyResult, KeyDerivationOptions options = default) => GenerateKeyBytes(KeySize128, out keyResult, options);

    /// <summary>
    /// Generates a new 192-bit (24-byte) cryptographic key and returns it as a byte array.
    /// </summary>
    /// <param name="keyResult">
    /// When this method returns, contains the encoded key token that can be used to reproduce
    /// the same key bytes via <see cref="GetKey192(ulong, KeyDerivationOptions)"/>.
    /// </param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm (SHA-256, HKDF-SHA-256, or PBKDF2-SHA-256)
    /// and any associated parameters such as salt and iteration count.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <returns>A 24-byte array containing the derived cryptographic key.</returns>
    public byte[] GenerateKey192(out ulong keyResult, KeyDerivationOptions options = default) => GenerateKeyBytes(KeySize192, out keyResult, options);

    /// <summary>
    /// Generates a new 256-bit (32-byte) cryptographic key and returns it as a byte array.
    /// </summary>
    /// <param name="keyResult">
    /// When this method returns, contains the encoded key token that can be used to reproduce
    /// the same key bytes via <see cref="GetKey256(ulong, KeyDerivationOptions)"/>.
    /// </param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm (SHA-256, HKDF-SHA-256, or PBKDF2-SHA-256)
    /// and any associated parameters such as salt and iteration count.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <returns>A 32-byte array containing the derived cryptographic key.</returns>
    public byte[] GenerateKey256(out ulong keyResult, KeyDerivationOptions options = default) => GenerateKeyBytes(KeySize256, out keyResult, options);

    /// <summary>
    /// Generates a new cryptographic key and writes the derived bytes directly into the provided destination span.
    /// </summary>
    /// <param name="destination">
    /// The span to receive the generated key bytes. Its length must be exactly 16, 24, or 32 bytes
    /// (<see cref="KeySize128"/>, <see cref="KeySize192"/>, or <see cref="KeySize256"/>).
    /// </param>
    /// <param name="keyResult">
    /// When this method returns, contains the encoded key token that can be used to reproduce
    /// the same key bytes via <see cref="GetKeyBytes(ulong, Span{byte}, KeyDerivationOptions)"/>.
    /// </param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm and associated parameters.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="destination"/>.Length is not 16, 24, or 32.
    /// </exception>
    public void GenerateKeyBytes(Span<byte> destination, out ulong keyResult, KeyDerivationOptions options = default) {
        ValidateKeySize((ulong)destination.Length);

        // Get a random key ID and check its type
        var randomKeyId = GetRandomKeyId();
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
                (ulong)keyServiceRecord.Id | (matrixResult.StartPosition << matrixStartPositionSize),
                (ulong)keyServiceRecord.KeyIdMask
            );
        }
    }

    /// <summary>
    /// Generates a new cryptographic key of the specified size and returns it as a byte array.
    /// </summary>
    /// <param name="keySizeInBytes">
    /// The desired key size in bytes. Must be exactly 16, 24, or 32
    /// (<see cref="KeySize128"/>, <see cref="KeySize192"/>, or <see cref="KeySize256"/>).
    /// </param>
    /// <param name="keyResult">
    /// When this method returns, contains the encoded key token that can be used to reproduce
    /// the same key bytes via <see cref="GetKeyBytes(ulong, ulong, KeyDerivationOptions)"/>.
    /// </param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm and associated parameters.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <returns>A byte array of length <paramref name="keySizeInBytes"/> containing the derived cryptographic key.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="keySizeInBytes"/> is not 16, 24, or 32.
    /// </exception>
    public byte[] GenerateKeyBytes(int keySizeInBytes, out ulong keyResult, KeyDerivationOptions options = default) {
        ValidateKeySize((ulong)keySizeInBytes);

        // Get a random key ID and check its type
        var randomKeyId = GetRandomKeyId();
        var keyServiceRecord = GetKeyServiceRecord(randomKeyId);

        if (keyServiceRecord.Type == Configuration.KeyType.Block) {
            // Block key generation (original path)
            var keyMaterial = GenerateKey(out keyResult);
            return DeriveKeyBytes(keyMaterial, keyResult, (ulong)keySizeInBytes, options);
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
                (ulong)keyServiceRecord.Id | ((ulong)matrixResult.StartPosition << matrixStartPositionSize),
                (ulong)keyServiceRecord.KeyIdMask
            );
            return matrixResult.KeyBytes;
        }
    }

    /// <summary>
    /// Generates a new 128-bit (16-byte) cryptographic key and writes the derived bytes into the provided destination span.
    /// </summary>
    /// <param name="destination">
    /// A span of exactly <see cref="KeySize128"/> (16) bytes to receive the generated key.
    /// </param>
    /// <param name="keyResult">
    /// When this method returns, contains the encoded key token that can be used to reproduce
    /// the same key bytes via <see cref="GetKey128(ulong, Span{byte}, KeyDerivationOptions)"/>.
    /// </param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm and associated parameters.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="destination"/>.Length is not <see cref="KeySize128"/>.
    /// </exception>
    public void GenerateKey128(Span<byte> destination, out ulong keyResult, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize128);
        GenerateKeyBytes(destination, out keyResult, options);
    }

    /// <summary>
    /// Generates a new 192-bit (24-byte) cryptographic key and writes the derived bytes into the provided destination span.
    /// </summary>
    /// <param name="destination">
    /// A span of exactly <see cref="KeySize192"/> (24) bytes to receive the generated key.
    /// </param>
    /// <param name="keyResult">
    /// When this method returns, contains the encoded key token that can be used to reproduce
    /// the same key bytes via <see cref="GetKey192(ulong, Span{byte}, KeyDerivationOptions)"/>.
    /// </param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm and associated parameters.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="destination"/>.Length is not <see cref="KeySize192"/>.
    /// </exception>
    public void GenerateKey192(Span<byte> destination, out ulong keyResult, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize192);
        GenerateKeyBytes(destination, out keyResult, options);
    }

    /// <summary>
    /// Generates a new 256-bit (32-byte) cryptographic key and writes the derived bytes into the provided destination span.
    /// </summary>
    /// <param name="destination">
    /// A span of exactly <see cref="KeySize256"/> (32) bytes to receive the generated key.
    /// </param>
    /// <param name="keyResult">
    /// When this method returns, contains the encoded key token that can be used to reproduce
    /// the same key bytes via <see cref="GetKey256(ulong, Span{byte}, KeyDerivationOptions)"/>.
    /// </param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm and associated parameters.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="destination"/>.Length is not <see cref="KeySize256"/>.
    /// </exception>
    public void GenerateKey256(Span<byte> destination, out ulong keyResult, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize256);
        GenerateKeyBytes(destination, out keyResult, options);
    }

    /// <summary>
    /// Asynchronously generates a new key and returns both the key material and the encoded key token.
    /// </summary>
    /// <returns>
    /// A <see cref="Task{TResult}"/> whose result is a tuple containing:
    /// <list type="bullet">
    ///   <item>
    ///     <description>
    ///       <c>Key</c> — the raw character-based key material for Block keys, or
    ///       <see cref="ReadOnlyMemory{T}.Empty"/> for Matrix keys (use the byte-returning overloads for Matrix key material).
    ///     </description>
    ///   </item>
    ///   <item>
    ///     <description>
    ///       <c>Id</c> — the encoded, optionally obfuscated key token that can be passed to
    ///       <see cref="GetKeyAsync(ulong)"/> or <see cref="GetKeyBytes(ulong, ulong, KeyDerivationOptions)"/>
    ///       to reproduce the identical key material.
    ///     </description>
    ///   </item>
    /// </list>
    /// </returns>
    public Task<(ReadOnlyMemory<char> Key, ulong Id)> GenerateKeyAsync() {
        var keyServiceRecord = GetKeyServiceRecord(GetRandomKeyId());

        if (keyServiceRecord.Type == Configuration.KeyType.Block) {
            ulong keyLength = (ulong)minMaskLength + (ulong)(RandomNumberGenerator.GetInt32(randomMaskLength) << 1),
                keyPosition = (ulong)RandomNumberGenerator.GetInt32(keyServiceRecord.Value.Length);
            //   0-255:8  0-1023:20    0-128:8
            //  [keyId][keyPosition][keyLength]
            var originalKeyResult = BitPacker.BlockKeyPack((uint)keyServiceRecord.Id, (uint)keyPosition, (uint)keyLength);
            var maskedKeyResult = ApplyKeyIdMask(originalKeyResult, (ulong)keyServiceRecord.KeyIdMask);
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
            ulong maskedKeyResult = ApplyKeyIdMask(
                (ulong)keyServiceRecord.Id | ((ulong)matrixResult.StartPosition << matrixStartPositionSize),
                (ulong)keyServiceRecord.KeyIdMask
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
    public ReadOnlyMemory<char> GetKey(ulong keyResult) {
        var keyId = keyResult & keyIdMask;
        var keyServiceRecord = GetKeyServiceRecord(keyId);

        if (keyServiceRecord.Type == Configuration.KeyType.Matrix) {
            return ReadOnlyMemory<char>.Empty;
        }

        var unmaskedKeyResult = UnmaskKeyResult(keyResult, keyServiceRecord);

        BitPacker.BlockKeyUnpack(keyResult, out _, out var keyPosition, out var keyLength);


        return GetBlockKeyMaterial(KeyServiceOptions.KeyMemory[keyId], keyPosition, keyLength);
    }

    /// <summary>
    /// Retrieves and derives a 128-bit (16-byte) cryptographic key from the encoded key token.
    /// </summary>
    /// <param name="keyResult">The encoded key token previously returned by a <c>GenerateKey</c> method.</param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm and associated parameters.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <returns>A 16-byte array containing the derived cryptographic key.</returns>
    public byte[] GetKey128(ulong keyResult, KeyDerivationOptions options = default) => GetKeyBytes(keyResult, KeySize128, options);

    /// <summary>
    /// Retrieves and derives a 192-bit (24-byte) cryptographic key from the encoded key token.
    /// </summary>
    /// <param name="keyResult">The encoded key token previously returned by a <c>GenerateKey</c> method.</param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm and associated parameters.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <returns>A 24-byte array containing the derived cryptographic key.</returns>
    public byte[] GetKey192(ulong keyResult, KeyDerivationOptions options = default) => GetKeyBytes(keyResult, KeySize192, options);

    /// <summary>
    /// Retrieves and derives a 256-bit (32-byte) cryptographic key from the encoded key token.
    /// </summary>
    /// <param name="keyResult">The encoded key token previously returned by a <c>GenerateKey</c> method.</param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm and associated parameters.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <returns>A 32-byte array containing the derived cryptographic key.</returns>
    public byte[] GetKey256(ulong keyResult, KeyDerivationOptions options = default) => GetKeyBytes(keyResult, KeySize256, options);

    /// <summary>
    /// Retrieves and derives cryptographic key bytes from the encoded key token and writes them into the provided destination span.
    /// </summary>
    /// <param name="keyResult">The encoded key token previously returned by a <c>GenerateKey</c> method.</param>
    /// <param name="destination">
    /// The span to receive the derived key bytes. Its length must be exactly 16, 24, or 32 bytes
    /// (<see cref="KeySize128"/>, <see cref="KeySize192"/>, or <see cref="KeySize256"/>).
    /// </param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm and associated parameters.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="destination"/>.Length is not 16, 24, or 32.
    /// </exception>
    public void GetKeyBytes(ulong keyResult, Span<byte> destination, KeyDerivationOptions options = default) {
        ValidateKeySize((ulong)destination.Length);
        var keyId = keyResult & keyIdMask;
        var keyServiceRecord = GetKeyServiceRecord(keyId);

        if (keyServiceRecord.Type == Configuration.KeyType.Matrix) {
            var unmasked = ApplyKeyIdMask(keyResult, (ulong)keyServiceRecord.KeyIdMask);
            BitPacker.BlockKeyUnpack(unmasked, out _, out var startPosition, out _);
            var matrixGenerator = new Matrices.MatrixKeyGenerator(keyServiceRecord.MatrixSettings!);
            var matrixResult = matrixGenerator.RegenerateKey(keyServiceRecord.Value, (byte)keyId, startPosition, (ulong)destination.Length);
            matrixResult.KeyBytes.CopyTo(destination);
        }
        else {
            var keyMaterial = GetKey(keyResult);
            DeriveKeyBytes(keyMaterial, keyResult, destination, options);
        }
    }

    /// <summary>
    /// Retrieves and derives cryptographic key bytes of the specified size from the encoded key token.
    /// </summary>
    /// <param name="keyResult">The encoded key token previously returned by a <c>GenerateKey</c> method.</param>
    /// <param name="keySizeInBytes">
    /// The desired output key size in bytes. Must be exactly 16, 24, or 32
    /// (<see cref="KeySize128"/>, <see cref="KeySize192"/>, or <see cref="KeySize256"/>).
    /// </param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm and associated parameters.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <returns>A byte array of length <paramref name="keySizeInBytes"/> containing the derived cryptographic key.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="keySizeInBytes"/> is not 16, 24, or 32.
    /// </exception>
    public byte[] GetKeyBytes(ulong keyResult, ulong keySizeInBytes, KeyDerivationOptions options = default) {
        ValidateKeySize(keySizeInBytes);
        var keyId = keyResult & keyIdMask;
        var keyServiceRecord = GetKeyServiceRecord(keyId);

        if (keyServiceRecord.Type == Configuration.KeyType.Matrix) {
            var unmasked = ApplyKeyIdMask(keyResult, (ulong)keyServiceRecord.KeyIdMask);
            BitPacker.BlockKeyUnpack(unmasked, out _, out var startPosition, out _);
            var matrixGenerator = new Matrices.MatrixKeyGenerator(keyServiceRecord.MatrixSettings!);
            return matrixGenerator.RegenerateKey(keyServiceRecord.Value, (byte)keyId, startPosition, keySizeInBytes).KeyBytes;
        }
        else {
            var keyMaterial = GetKey(keyResult);
            return DeriveKeyBytes(keyMaterial, keyResult, keySizeInBytes, options);
        }
    }

    /// <summary>
    /// Retrieves and derives a 128-bit (16-byte) cryptographic key from the encoded key token
    /// and writes it into the provided destination span.
    /// </summary>
    /// <param name="keyResult">The encoded key token previously returned by a <c>GenerateKey</c> method.</param>
    /// <param name="destination">
    /// A span of exactly <see cref="KeySize128"/> (16) bytes to receive the derived key.
    /// </param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm and associated parameters.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="destination"/>.Length is not <see cref="KeySize128"/>.
    /// </exception>
    public void GetKey128(ulong keyResult, Span<byte> destination, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize128);
        GetKeyBytes(keyResult, destination, options);
    }

    /// <summary>
    /// Retrieves and derives a 192-bit (24-byte) cryptographic key from the encoded key token
    /// and writes it into the provided destination span.
    /// </summary>
    /// <param name="keyResult">The encoded key token previously returned by a <c>GenerateKey</c> method.</param>
    /// <param name="destination">
    /// A span of exactly <see cref="KeySize192"/> (24) bytes to receive the derived key.
    /// </param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm and associated parameters.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="destination"/>.Length is not <see cref="KeySize192"/>.
    /// </exception>
    public void GetKey192(ulong keyResult, Span<byte> destination, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize192);
        GetKeyBytes(keyResult, destination, options);
    }

    /// <summary>
    /// Retrieves and derives a 256-bit (32-byte) cryptographic key from the encoded key token
    /// and writes it into the provided destination span.
    /// </summary>
    /// <param name="keyResult">The encoded key token previously returned by a <c>GenerateKey</c> method.</param>
    /// <param name="destination">
    /// A span of exactly <see cref="KeySize256"/> (32) bytes to receive the derived key.
    /// </param>
    /// <param name="options">
    /// Key derivation options controlling the algorithm and associated parameters.
    /// Defaults to <see cref="KeyDerivationOptions.Default"/>.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="destination"/>.Length is not <see cref="KeySize256"/>.
    /// </exception>
    public void GetKey256(ulong keyResult, Span<byte> destination, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize256);
        GetKeyBytes(keyResult, destination, options);
    }

    /// <summary>
    /// Asynchronously retrieves raw character-based key material from the encoded key token.
    /// </summary>
    /// <param name="keyResult">The encoded key token previously returned by <see cref="GenerateKeyAsync"/>.</param>
    /// <returns>
    /// A <see cref="Task{TResult}"/> whose result is the raw character material for Block keys,
    /// or <see cref="ReadOnlyMemory{T}.Empty"/> for Matrix keys.
    /// For Matrix keys, use <see cref="GetKeyBytes(ulong, ulong, KeyDerivationOptions)"/> or a typed
    /// overload to obtain the actual cryptographic bytes.
    /// </returns>
    public Task<ReadOnlyMemory<char>> GetKeyAsync(ulong keyResult) {
        var keyId = keyResult & keyIdMask;
        var keyServiceRecord = GetKeyServiceRecord(keyId);

        if (keyServiceRecord.Type == Configuration.KeyType.Matrix) {
            return Task.FromResult(ReadOnlyMemory<char>.Empty);
        }

        var unmaskedKeyResult = UnmaskKeyResult(keyResult, keyServiceRecord);
        BitPacker.BlockKeyUnpack(unmaskedKeyResult, out _, out var keyPosition, out var keyLength);

        return Task.FromResult(GetBlockKeyMaterial(KeyServiceOptions.KeyMemory[keyId], keyPosition, keyLength));
    }

    /// <summary>
    /// Does the Key Service contain the Key Id (0-255)
    /// </summary>
    /// <param name="keyId">Key identifier (0-255)</param>
    /// <returns>True if key exists</returns>
    public bool ContainsKey(ulong keyId) => keyId < KeyService.MaxKeyCount && Keys[keyId] != null;
    /// <summary>
    /// Delete the Key Id from the Key Manager (0-255)
    /// </summary>
    /// <param name="keyId">Key identifier (0-255)</param>
    /// <returns>True if key was deleted</returns>
    public bool DeleteKey(ulong keyId) => KeyServiceOptions.DeleteKey(keyId);

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
    public ulong GetRandomKeyId() => (ulong)RandomNumberGenerator.GetInt32(KeyCount);
    /// <summary>
    /// Get the Key Service Record for a given key ID (0-255)
    /// </summary>
    /// <param name="keyId">Key identifier (0-255)</param>
    /// <returns>KeyServiceRecord containing key configuration</returns>
    /// <exception cref="KeyNotFoundException">
    /// Thrown when no key configuration exists for the given <paramref name="keyId"/>.
    /// </exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static KeyServiceRecord GetKeyServiceRecord(ulong keyId) {
        if (keyId >= 0 && keyId < KeyService.MaxKeyCount) {
            var record = Keys[keyId];
            if (record != null) {
                return record;
            }
        }

        throw new KeyNotFoundException($"No key configuration exists for key id '{keyId}'.");
    }

    /// <summary>
    /// Applies or removes the per-key XOR obfuscation mask to or from a key result token.
    /// Because XOR is its own inverse, this method is used for both masking and unmasking.
    /// </summary>
    /// <param name="keyResult">The key result value to transform.</param>
    /// <param name="keyMaskId">The XOR mask value from <see cref="KeyServiceRecord.KeyIdMask"/>.</param>
    /// <returns>The XOR of <paramref name="keyResult"/> and <paramref name="keyMaskId"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong ApplyKeyIdMask(ulong keyResult, ulong keyMaskId) => keyResult ^ keyMaskId;

    /// <summary>
    /// Removes the per-key XOR mask from a masked key result token and validates the decoded fields.
    /// </summary>
    /// <param name="maskedKeyResult">The obfuscated key token as stored or transmitted.</param>
    /// <param name="keyServiceRecord">The <see cref="KeyServiceRecord"/> for the key identified in the token.</param>
    /// <returns>The unmasked key result value with validated key ID, position, and length fields.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the decoded key ID does not match <paramref name="keyServiceRecord"/>.Id,
    /// indicating an invalid <see cref="KeyServiceRecord.KeyIdMask"/> configuration.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when the decoded key position or length falls outside the bounds of the configured source key.
    /// </exception>
    private static ulong UnmaskKeyResult(ulong maskedKeyResult, KeyServiceRecord keyServiceRecord) {
        var unmaskedKeyResult = ApplyKeyIdMask(maskedKeyResult, (ulong)keyServiceRecord.KeyIdMask);
        BitPacker.BlockKeyUnpack(unmaskedKeyResult, out var decodedKeyId, out var keyPosition, out var keyLength);
        //int decodedKeyId = unmaskedKeyResult & keyIdMask,
        //    keyPosition = (unmaskedKeyResult >> keyPositionSize) & keyPositionMask,
        //    keyLength = (unmaskedKeyResult >> keyPositionAndLength) & keyLengthMask;

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

    /// <summary>
    /// Extracts a contiguous slice of character material from a Block key source, wrapping around to the
    /// beginning of the source when the requested range extends past the end.
    /// </summary>
    /// <param name="source">The full source key memory for the selected Block key slot.</param>
    /// <param name="keyPosition">The zero-based start position within <paramref name="source"/>.</param>
    /// <param name="keyLength">The number of characters to extract.</param>
    /// <returns>
    /// A <see cref="ReadOnlyMemory{T}"/> of length <paramref name="keyLength"/> containing the extracted characters.
    /// If the range fits entirely within <paramref name="source"/> a zero-copy slice is returned;
    /// otherwise a new array is allocated that concatenates the tail and head segments.
    /// </returns>
    private static ReadOnlyMemory<char> GetBlockKeyMaterial(ReadOnlyMemory<char> source, ulong keyPosition, ulong keyLength) {
        var sourceSpan = source.Span;
        var sourceLength = sourceSpan.Length;
        int iKeyPosition = (int)keyPosition, iKeyLength = (int)keyLength;
        if (iKeyPosition + iKeyLength <= sourceLength) {
            return source.Slice(iKeyPosition, iKeyLength);
        }

        int firstSegmentLength = sourceLength - iKeyPosition;
        int secondSegmentLength = iKeyLength - firstSegmentLength;
        char[] wrapped = GC.AllocateUninitializedArray<char>(iKeyLength);
        sourceSpan.Slice(iKeyPosition, firstSegmentLength).CopyTo(wrapped.AsSpan(0, firstSegmentLength));
        sourceSpan.Slice(0, secondSegmentLength).CopyTo(wrapped.AsSpan(firstSegmentLength, secondSegmentLength));
        return wrapped;
    }

    /// <summary>
    /// Allocates a new byte array and delegates to the span-based overload to fill it with derived key bytes.
    /// </summary>
    /// <param name="keyMaterial">The raw character-based key material from the source key slot.</param>
    /// <param name="keyResult">The encoded key token, used as derivation context (e.g., HKDF/PBKDF2 salt input).</param>
    /// <param name="keySizeInBytes">The number of bytes to derive. Must be 16, 24, or 32.</param>
    /// <param name="options">Key derivation options controlling the algorithm and parameters.</param>
    /// <returns>A newly allocated byte array of length <paramref name="keySizeInBytes"/> containing the derived key.</returns>
    private static byte[] DeriveKeyBytes(ReadOnlyMemory<char> keyMaterial, ulong keyResult, ulong keySizeInBytes, KeyDerivationOptions options) {
        var derivedKey = GC.AllocateUninitializedArray<byte>((int)keySizeInBytes);
        DeriveKeyBytes(keyMaterial, keyResult, derivedKey, options);
        return derivedKey;
    }

    /// <summary>
    /// Encodes <paramref name="keyMaterial"/> as UTF-8, then applies the configured key derivation
    /// algorithm to fill <paramref name="destination"/> with cryptographic key bytes.
    /// </summary>
    /// <param name="keyMaterial">The raw character-based key material from the source key slot.</param>
    /// <param name="keyResult">The encoded key token, used as derivation context (e.g., HKDF/PBKDF2 salt input).</param>
    /// <param name="destination">
    /// The span to receive the derived bytes. Its length must be exactly 16, 24, or 32.
    /// </param>
    /// <param name="options">Key derivation options controlling the algorithm and parameters.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="destination"/>.Length is not 16, 24, or 32,
    /// or when <paramref name="options"/>.<see cref="KeyDerivationOptions.Algorithm"/> is not supported.
    /// </exception>
    /// <remarks>
    /// The rented UTF-8 byte buffer is securely zeroed before being returned to the shared pool.
    /// </remarks>
    private static void DeriveKeyBytes(ReadOnlyMemory<char> keyMaterial, ulong keyResult, Span<byte> destination, KeyDerivationOptions options) {
        ValidateKeySize((ulong)destination.Length);

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
                    DeriveHkdfSha256(sourceKey, (int)keyResult, destination, options);
                    break;
                case KeyDerivationAlgorithm.Pbkdf2Sha256:
                    DerivePbkdf2Sha256(sourceKey, (int)keyResult, destination, options);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(options), options.Algorithm, "Unsupported key derivation algorithm.");
            }
        }
        finally {
            ArrayPool<byte>.Shared.Return(rentedBytes, clearArray: true);
        }
    }

    /// <summary>
    /// Derives key bytes by computing a SHA-256 hash of the source key and copying the leading bytes
    /// into <paramref name="destination"/>.
    /// </summary>
    /// <param name="sourceKey">The UTF-8-encoded key material to hash.</param>
    /// <param name="destination">
    /// The span to receive the derived bytes. Must be at most 32 bytes (the SHA-256 output length).
    /// </param>
    /// <remarks>
    /// The intermediate hash buffer is securely zeroed after the copy.
    /// </remarks>
    private static void DeriveSha256(ReadOnlySpan<byte> sourceKey, Span<byte> destination) {
        var hash = SHA256.HashData(sourceKey);
        try {
            hash.AsSpan(0, destination.Length).CopyTo(destination);
        }
        finally {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    /// <summary>
    /// Derives key bytes using a single-block HKDF-SHA-256 expand step (RFC 5869).
    /// The extract step uses <paramref name="keyResult"/> encoded as a little-endian salt
    /// unless a custom salt is provided via <paramref name="options"/>.
    /// </summary>
    /// <param name="sourceKey">The UTF-8-encoded key material used as IKM (input key material).</param>
    /// <param name="keyResult">
    /// The encoded key token. Used as the default salt for the extract step when
    /// <see cref="KeyDerivationOptions.Salt"/> is empty.
    /// </param>
    /// <param name="destination">
    /// The span to receive the derived bytes. Must be at most 32 bytes (one HMAC-SHA-256 block).
    /// </param>
    /// <param name="options">
    /// Key derivation options providing an optional custom salt and info context.
    /// </param>
    /// <remarks>
    /// All intermediate key material (salt bytes, source bytes, pseudorandom key, expanded block)
    /// is securely zeroed before the method returns.
    /// </remarks>
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

    /// <summary>
    /// Derives key bytes using PBKDF2-SHA-256 (RFC 2898).
    /// The <paramref name="keyResult"/> encoded as a little-endian integer is used as the default salt
    /// when no custom salt is provided via <paramref name="options"/>.
    /// </summary>
    /// <param name="sourceKey">The UTF-8-encoded key material used as the PBKDF2 password.</param>
    /// <param name="keyResult">
    /// The encoded key token. Used as the default salt when <see cref="KeyDerivationOptions.Salt"/> is empty.
    /// </param>
    /// <param name="destination">The span to receive the derived bytes (16, 24, or 32 bytes).</param>
    /// <param name="options">
    /// Key derivation options providing an optional custom salt and iteration count.
    /// When <see cref="KeyDerivationOptions.IterationCount"/> is zero or negative,
    /// <see cref="KeyDerivationOptions.DefaultPbkdf2IterationCount"/> is used.
    /// </param>
    private static void DerivePbkdf2Sha256(ReadOnlySpan<byte> sourceKey, int keyResult, Span<byte> destination, KeyDerivationOptions options) {
        Span<byte> defaultSalt = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(defaultSalt, keyResult);
        var salt = options.Salt.IsEmpty ? defaultSalt : options.Salt.Span;
        int iterationCount = options.IterationCount > 0 ? options.IterationCount : KeyDerivationOptions.DefaultPbkdf2IterationCount;

        Rfc2898DeriveBytes.Pbkdf2(sourceKey, salt, destination, iterationCount, HashAlgorithmName.SHA256);
    }

    /// <summary>
    /// Validates that <paramref name="keySizeInBytes"/> is one of the three supported key sizes
    /// (16, 24, or 32 bytes).
    /// </summary>
    /// <param name="keySizeInBytes">The key size to validate, in bytes.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="keySizeInBytes"/> is not <see cref="KeySize128"/>,
    /// <see cref="KeySize192"/>, or <see cref="KeySize256"/>.
    /// </exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ValidateKeySize(ulong keySizeInBytes) {
        if (keySizeInBytes != KeySize128 && keySizeInBytes != KeySize192 && keySizeInBytes != KeySize256) {
            throw new ArgumentOutOfRangeException(nameof(keySizeInBytes), "Supported key sizes are 16, 24, and 32 bytes.");
        }
    }

    /// <summary>
    /// Validates that the actual destination size matches the expected size for a named key operation.
    /// </summary>
    /// <param name="actualSize">The length of the caller-supplied destination span or array.</param>
    /// <param name="expectedSize">
    /// The required length — one of <see cref="KeySize128"/>, <see cref="KeySize192"/>, or <see cref="KeySize256"/>.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="actualSize"/> does not equal <paramref name="expectedSize"/>.
    /// </exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ValidateNamedKeySize(int actualSize, int expectedSize) {
        if (actualSize != expectedSize) {
            throw new ArgumentException($"Destination must be {expectedSize} bytes.", nameof(expectedSize));
        }
    }

    /// <summary>
    /// Releases all resources used by the <see cref="KeyService"/> instance and suppresses finalisation.
    /// </summary>
    public void Dispose() {
        GC.SuppressFinalize(this);
    }

}
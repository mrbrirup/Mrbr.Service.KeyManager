namespace Mrbr.Service.KeyManager.Services;
/// <summary>
/// Key Service Interface
/// Manages key generation and retrieval for 0-255 keys.
/// Supports both Block (1D contiguous) and Matrix (3D vector-based) key types.
/// </summary>
public interface IKeyService {
    /// <summary>
    /// Generate a New Key for the Key Manager from one of 256 available keys (0-255).
    /// For Block keys: Returns key material slice. For Matrix keys: Returns empty (use GenerateKeyBytes for actual output).
    /// </summary>
    /// <param name="keyId">Output key identifier</param>
    /// <returns>Key material (Block keys) or empty (Matrix keys)</returns>
    ReadOnlyMemory<char> GenerateKey(out ulong keyId);
    /// <summary>
    /// Generate a fixed-length 16-byte key from the Key Manager (selects from 0-255 keys).
    /// </summary>
    byte[] GenerateKey128(out ulong keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Generate a fixed-length 24-byte key from the Key Manager (selects from 0-255 keys).
    /// </summary>
    byte[] GenerateKey192(out ulong keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Generate a fixed-length 32-byte key from the Key Manager (selects from 0-255 keys).
    /// </summary>
    byte[] GenerateKey256(out ulong keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Generate a fixed-length key from the Key Manager into a caller-provided destination span (selects from 0-255 keys).
    /// Destination length must be 16, 24, or 32 bytes.
    /// </summary>
    void GenerateKeyBytes(Span<byte> destination, out ulong keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Generate a fixed-length key from the Key Manager (selects from 0-255 keys).
    /// keySizeInBytes must be 16, 24, or 32.
    /// </summary>
    byte[] GenerateKeyBytes(int keySizeInBytes, out ulong keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Generate a fixed-length 16-byte key from the Key Manager into a caller-provided destination span (selects from 0-255 keys).
    /// </summary>
    void GenerateKey128(Span<byte> destination, out ulong keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Generate a fixed-length 24-byte key from the Key Manager into a caller-provided destination span (selects from 0-255 keys).
    /// </summary>
    void GenerateKey192(Span<byte> destination, out ulong keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Generate a fixed-length 32-byte key from the Key Manager into a caller-provided destination span (selects from 0-255 keys).
    /// </summary>
    void GenerateKey256(Span<byte> destination, out ulong keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Get the Key text from the Source Keys using the Key Id (0-255).
    /// </summary>
    /// <param name="keyId">Key identifier (0-255)</param>
    /// <returns>Key material</returns>
    ReadOnlyMemory<char> GetKey(ulong keyId);
    /// <summary>
    /// Get a fixed-length 16-byte key from the Key Manager using a specific key ID (0-255).
    /// </summary>
    byte[] GetKey128(ulong keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Get a fixed-length 24-byte key from the Key Manager using a specific key ID (0-255).
    /// </summary>
    byte[] GetKey192(ulong keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Get a fixed-length 32-byte key from the Key Manager using a specific key ID (0-255).
    /// </summary>
    byte[] GetKey256(ulong keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Get a fixed-length key from the Key Manager into a caller-provided destination span using a specific key ID (0-255).
    /// Destination length must be 16, 24, or 32 bytes.
    /// </summary>
    void GetKeyBytes(ulong keyId, Span<byte> destination, KeyDerivationOptions options = default);
    /// <summary>
    /// Get a fixed-length key from the Key Manager using a specific key ID (0-255).
    /// keySizeInBytes must be 16, 24, or 32.
    /// </summary>
    byte[] GetKeyBytes(ulong keyId, ulong keySizeInBytes, KeyDerivationOptions options = default);
    /// <summary>
    /// Get a fixed-length 16-byte key from the Key Manager into a caller-provided destination span using a specific key ID (0-255).
    /// </summary>
    void GetKey128(ulong keyId, Span<byte> destination, KeyDerivationOptions options = default);
    /// <summary>
    /// Get a fixed-length 24-byte key from the Key Manager into a caller-provided destination span using a specific key ID (0-255).
    /// </summary>
    void GetKey192(ulong keyId, Span<byte> destination, KeyDerivationOptions options = default);
    /// <summary>
    /// Get a fixed-length 32-byte key from the Key Manager into a caller-provided destination span using a specific key ID (0-255).
    /// </summary>
    void GetKey256(ulong keyId, Span<byte> destination, KeyDerivationOptions options = default);
    /// <summary>
    /// Check if the Key Id exists in the Key Manager (0-255).
    /// </summary>
    /// <param name="keyId">Key identifier (0-255)</param>
    /// <returns>True if key exists</returns>
    bool ContainsKey(ulong keyId);
    /// <summary>
    /// Delete the Key Id from the Key Manager (0-255).
    /// </summary>
    /// <param name="keyId">Key identifier (0-255)</param>
    /// <returns>True if key was deleted</returns>
    bool DeleteKey(ulong keyId);
    /// <summary>
    /// Delete all Keys from the Key Manager (all 256 slots).
    /// </summary>
    /// <returns>True if any keys were deleted</returns>    
    bool DeleteAllKeys();
    /// <summary>
    /// Get a random Key Id from the available keys (0-255).
    /// </summary>
    /// <returns>Random key ID</returns>
    ulong GetRandomKeyId();

    Task<(ReadOnlyMemory<char> Key, ulong Id)> GenerateKeyAsync();
    Task<ReadOnlyMemory<char>> GetKeyAsync(ulong keyId);
}
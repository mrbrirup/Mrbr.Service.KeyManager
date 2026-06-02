namespace Mrbr.Service.KeyManager.Services;
/// <summary>
/// Key Service Interface
/// </summary>
public interface IKeyService {
    /// <summary>
    /// Generate a New Key for the Key Manager
    /// </summary>
    /// <param name="keyId"></param>
    /// <returns></returns>
    ReadOnlyMemory<char> GenerateKey(out int keyId);
    /// <summary>
    /// Generate a fixed-length 16-byte key from the Key Manager.
    /// </summary>
    byte[] GenerateKey128(out int keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Generate a fixed-length 24-byte key from the Key Manager.
    /// </summary>
    byte[] GenerateKey192(out int keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Generate a fixed-length 32-byte key from the Key Manager.
    /// </summary>
    byte[] GenerateKey256(out int keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Generate a fixed-length key from the Key Manager into a caller-provided destination span.
    /// Destination length must be 16, 24, or 32 bytes.
    /// </summary>
    void GenerateKeyBytes(Span<byte> destination, out int keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Generate a fixed-length key from the Key Manager.
    /// keySizeInBytes must be 16, 24, or 32.
    /// </summary>
    byte[] GenerateKeyBytes(int keySizeInBytes, out int keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Generate a fixed-length 16-byte key from the Key Manager into a caller-provided destination span.
    /// </summary>
    void GenerateKey128(Span<byte> destination, out int keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Generate a fixed-length 24-byte key from the Key Manager into a caller-provided destination span.
    /// </summary>
    void GenerateKey192(Span<byte> destination, out int keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Generate a fixed-length 32-byte key from the Key Manager into a caller-provided destination span.
    /// </summary>
    void GenerateKey256(Span<byte> destination, out int keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Get the Key text from the Source Keys using the Key Id
    /// </summary>
    /// <param name="keyId"></param>
    /// <returns></returns>
    ReadOnlyMemory<char> GetKey(int keyId);
    /// <summary>
    /// Get a fixed-length 16-byte key from the Key Manager.
    /// </summary>
    byte[] GetKey128(int keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Get a fixed-length 24-byte key from the Key Manager.
    /// </summary>
    byte[] GetKey192(int keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Get a fixed-length 32-byte key from the Key Manager.
    /// </summary>
    byte[] GetKey256(int keyId, KeyDerivationOptions options = default);
    /// <summary>
    /// Get a fixed-length key from the Key Manager into a caller-provided destination span.
    /// Destination length must be 16, 24, or 32 bytes.
    /// </summary>
    void GetKeyBytes(int keyId, Span<byte> destination, KeyDerivationOptions options = default);
    /// <summary>
    /// Get a fixed-length key from the Key Manager.
    /// keySizeInBytes must be 16, 24, or 32.
    /// </summary>
    byte[] GetKeyBytes(int keyId, int keySizeInBytes, KeyDerivationOptions options = default);
    /// <summary>
    /// Get a fixed-length 16-byte key from the Key Manager into a caller-provided destination span.
    /// </summary>
    void GetKey128(int keyId, Span<byte> destination, KeyDerivationOptions options = default);
    /// <summary>
    /// Get a fixed-length 24-byte key from the Key Manager into a caller-provided destination span.
    /// </summary>
    void GetKey192(int keyId, Span<byte> destination, KeyDerivationOptions options = default);
    /// <summary>
    /// Get a fixed-length 32-byte key from the Key Manager into a caller-provided destination span.
    /// </summary>
    void GetKey256(int keyId, Span<byte> destination, KeyDerivationOptions options = default);
    /// <summary>
    /// Check if the Key Id exists in the Key Manager    
    /// </summary>
    /// <param name="keyId"></param>
    /// <returns></returns>
    bool ContainsKey(int keyId);
    /// <summary>
    /// Delete the Key Id from the Key Manager
    /// </summary>
    /// <param name="keyId"></param>
    /// <returns></returns>
    bool DeleteKey(int keyId);
    /// <summary>
    /// Delete all Keys from the Key Manager
    /// </summary>
    /// <returns></returns>    
    bool DeleteAllKeys();
    int GetRandomKeyId();

    Task<(ReadOnlyMemory<char> Key, int Id)> GenerateKeyAsync();
    Task<ReadOnlyMemory<char>> GetKeyAsync(int keyId);
}
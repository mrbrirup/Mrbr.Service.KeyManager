namespace Mrbr.Service.KeyManager.Services;

/// <summary>
/// Supported algorithms for deriving fixed-length key bytes from KeyService key material.
/// </summary>
public enum KeyDerivationAlgorithm {
    Sha256,
    HkdfSha256,
    Pbkdf2Sha256
}

/// <summary>
/// Options for deriving fixed-length key bytes from KeyService key material.
/// </summary>
public readonly record struct KeyDerivationOptions {
    public const int DefaultPbkdf2IterationCount = 100_000;

    public KeyDerivationAlgorithm Algorithm { get; init; }
    public ReadOnlyMemory<byte> Salt { get; init; }
    public ReadOnlyMemory<byte> Info { get; init; }
    public int IterationCount { get; init; }
}

namespace Mrbr.Service.KeyManager.Configuration;

/// <summary>
/// Defines the type of key generation strategy.
/// </summary>
public enum KeyType {
    /// <summary>
    /// 1D contiguous extraction from source text.
    /// Uses position and length encoding: [keyId:8bits][keyPosition:10bits][keyLength:10bits]
    /// </summary>
    Block = 0,

    /// <summary>
    /// 3D vector-based navigation through matrix space.
    /// Uses handle encoding: [KeySourceId:8bits][Format:8bits][StartPosition:N bits][WalkSeed:remaining bits].
    /// </summary>
    Matrix = 1
}

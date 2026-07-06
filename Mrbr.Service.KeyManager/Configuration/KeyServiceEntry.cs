#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
namespace Mrbr.Service.KeyManager.Configuration;

/// <summary>
/// Configuration entry for a single key source in the KeyManager.
/// Supports source IDs from 0 to 255.
/// </summary>
public sealed class KeyServiceEntry {
    public KeyServiceEntry() { }

    public KeyServiceEntry(int keySourceId, string value, string keyHandleMask = "0", KeyType keyType = KeyType.Block) {
        KeySourceId = keySourceId;
        Value = value;
        KeyHandleMask = keyHandleMask;
        Type = keyType;
    }

    /// <summary>
    /// The key source ID (0-255). This value is stored unmasked in the low byte of every key handle.
    /// </summary>
    public int KeySourceId { get; set; }

    /// <summary>
    /// Compatibility alias for older configuration that used Key for the source ID.
    /// </summary>
    public int Key {
        get => KeySourceId;
        set => KeySourceId = value;
    }

    /// <summary>
    /// The source text/data for key generation.
    /// </summary>
    public string Value { get; set; }

    /// <summary>
    /// Mask applied to the replay payload in a key handle.
    /// The lowest 8 bits must remain clear so KeySourceId can be read without unmasking.
    /// </summary>
    public string KeyHandleMask { get; set; } = "0";

    /// <summary>
    /// Compatibility alias for older configuration that used KeyIdMask.
    /// </summary>
    public string KeyIdMask {
        get => KeyHandleMask;
        set => KeyHandleMask = value;
    }

    /// <summary>
    /// The type of key generation strategy (Block or Matrix).
    /// </summary>
    public KeyType Type { get; set; } = KeyType.Block;

    /// <summary>
    /// Block-specific settings. Required when Type is Block.
    /// </summary>
    public KeyBlockSettings? BlockSettings { get; set; }

    /// <summary>
    /// Matrix-specific settings. Required when Type is Matrix.
    /// </summary>
    public KeyMatrixSettings? MatrixSettings { get; set; }

    /// <summary>
    /// Validates that the entry has the correct settings for its type.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when validation fails</exception>
    public void Validate() {
        if (KeySourceId < 0 || KeySourceId > 255) {
            throw new InvalidOperationException($"KeySourceId must be between 0 and 255, but got {KeySourceId}.");
        }

        if (string.IsNullOrEmpty(Value)) {
            throw new InvalidOperationException($"Value (source text) cannot be null or empty for key source {KeySourceId}.");
        }

        switch (Type) {
            case KeyType.Block:
                if (BlockSettings != null) {
                    BlockSettings.Validate(Value.Length);
                }
                if (MatrixSettings != null) {
                    throw new InvalidOperationException($"Key source {KeySourceId} has type Block but also has MatrixSettings defined. Only one settings type is allowed.");
                }
                break;

            case KeyType.Matrix:
                if (MatrixSettings == null) {
                    throw new InvalidOperationException($"MatrixSettings are required for key source {KeySourceId} with type Matrix.");
                }
                if (BlockSettings != null) {
                    throw new InvalidOperationException($"Key source {KeySourceId} has type Matrix but also has BlockSettings defined. Only one settings type is allowed.");
                }
                break;

            default:
                throw new InvalidOperationException($"Unknown KeyType {Type} for key source {KeySourceId}.");
        }
    }
}
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

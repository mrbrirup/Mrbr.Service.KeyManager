#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
namespace Mrbr.Service.KeyManager.Configuration;

/// <summary>
/// Configuration entry for a single key in the KeyManager.
/// Supports key IDs from 0 to 255.
/// </summary>
public sealed class KeyServiceEntry {
    public KeyServiceEntry() { }

    public KeyServiceEntry(int key, string value, string keyIdMask = "0", KeyType keyType = KeyType.Block) {
        Key = key;
        Value = value;
        KeyIdMask = keyIdMask;
        Type = keyType;
    }

    /// <summary>
    /// The key ID (0-255).
    /// </summary>
    public int Key { get; set; }

    /// <summary>
    /// The source text/data for key generation.
    /// </summary>
    public string Value { get; set; }

    /// <summary>
    /// Mask applied to the key ID for additional obfuscation.
    /// Must not set the lowest 8 bits (minimum value: 256).
    /// </summary>
    public string KeyIdMask { get; set; } = "0";

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
        if (Key < 0 || Key > 255) {
            throw new InvalidOperationException($"Key ID must be between 0 and 255, but got {Key}.");
        }

        if (string.IsNullOrEmpty(Value)) {
            throw new InvalidOperationException($"Value (source text) cannot be null or empty for key {Key}.");
        }

        switch (Type) {
            case KeyType.Block:
                if (BlockSettings == null) {
                    throw new InvalidOperationException($"BlockSettings are required for key {Key} with type Block.");
                }
                BlockSettings.Validate(Value.Length);
                if (MatrixSettings != null) {
                    throw new InvalidOperationException($"Key {Key} has type Block but also has MatrixSettings defined. Only one settings type is allowed.");
                }
                break;

            case KeyType.Matrix:
                if (MatrixSettings == null) {
                    throw new InvalidOperationException($"MatrixSettings are required for key {Key} with type Matrix.");
                }
                if (BlockSettings != null) {
                    throw new InvalidOperationException($"Key {Key} has type Matrix but also has BlockSettings defined. Only one settings type is allowed.");
                }
                break;

            default:
                throw new InvalidOperationException($"Unknown KeyType {Type} for key {Key}.");
        }
    }
}
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.



public class Rootobject {
    public Keyserviceentry[] KeyServiceEntries { get; set; }
}

public class Keyserviceentry {
    public int KeyIndex { get; set; }
    public Keymatrixsettings KeyMatrixSettings { get; set; } = default!;
}

public class Keymatrixsettings {
    public Keymatrixsetting KeyMatrixSetting { get; set; } = default!;
}

public class Keymatrixsetting {
    public int Width { get; set; }
    public int Height { get; set; }
    public int Depth { get; set; }
    public long VectorMask { get; set; }
    public long KeyMask { get; set; }
}

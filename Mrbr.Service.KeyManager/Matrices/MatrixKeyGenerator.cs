using Microsoft.Extensions.Options;
using Mrbr.Service.KeyManager.Configuration;
using System.Buffers.Binary;
using System.Text;

namespace Mrbr.Service.KeyManager.Matrices;

/// <summary>
/// Convenience wrapper for Matrix key generation. The hot path uses <see cref="MatrixKeyWalker"/> directly.
/// </summary>
public class MatrixKeyGenerator {
    private readonly KeyMatrixSettings _settings;

    public MatrixKeyGenerator(IOptions<KeyMatrixSettings> options) : this(options.Value) { }

    public MatrixKeyGenerator(KeyMatrixSettings settings) {
        ArgumentNullException.ThrowIfNull(settings);
        _settings = settings;
    }

    public MatrixKeyResult GenerateKey(string sourceText, byte keyId, int maxTargetBytes) {
        ValidateTargetBytes(maxTargetBytes);

        byte[] sourceBytes = Encoding.UTF8.GetBytes(sourceText);
        var walker = new MatrixKeyWalker(_settings, sourceBytes);
        byte[] keyBytes = GC.AllocateUninitializedArray<byte>(maxTargetBytes);
        walker.Generate(keyBytes, out uint startPosition, out ulong seed);

        return new MatrixKeyResult {
            KeyId = keyId,
            StartPosition = startPosition,
            Seed = seed,
            KeyBytes = keyBytes
        };
    }

    public MatrixKeyResult RegenerateKey(string sourceText, byte keyId, ulong startPosition, ulong seed, int maxTargetBytes) {
        ValidateTargetBytes(maxTargetBytes);
        if (startPosition > uint.MaxValue) {
            throw new ArgumentOutOfRangeException(nameof(startPosition), "Matrix start position cannot exceed UInt32.MaxValue.");
        }

        byte[] sourceBytes = Encoding.UTF8.GetBytes(sourceText);
        var walker = new MatrixKeyWalker(_settings, sourceBytes);
        byte[] keyBytes = GC.AllocateUninitializedArray<byte>(maxTargetBytes);
        walker.Replay((uint)startPosition, seed, keyBytes);

        return new MatrixKeyResult {
            KeyId = keyId,
            StartPosition = startPosition,
            Seed = seed,
            KeyBytes = keyBytes
        };
    }

    private static void ValidateTargetBytes(int maxTargetBytes) {
        if (maxTargetBytes <= 0) {
            throw new ArgumentOutOfRangeException(nameof(maxTargetBytes), "Target byte count must be greater than zero.");
        }
    }
}

/// <summary>
/// Result of Matrix key generation containing replay metadata used by convenience APIs.
/// </summary>
public class MatrixKeyResult {
    public byte KeyId { get; init; }

    public ulong StartPosition { get; init; }

    public ulong Seed { get; init; }

    public byte[] KeyBytes { get; init; } = Array.Empty<byte>();

    public byte[] EncodeToBytes() {
        byte[] result = new byte[17];
        result[0] = KeyId;
        BinaryPrimitives.WriteUInt64LittleEndian(result.AsSpan(1, sizeof(ulong)), StartPosition);
        BinaryPrimitives.WriteUInt64LittleEndian(result.AsSpan(9, sizeof(ulong)), Seed);
        return result;
    }

    public static MatrixKeyResult DecodeFromBytes(byte[] encoded) {
        ArgumentNullException.ThrowIfNull(encoded);

        if (encoded.Length < 17) {
            throw new ArgumentException("Encoded data must be at least 17 bytes.", nameof(encoded));
        }

        return new MatrixKeyResult {
            KeyId = encoded[0],
            StartPosition = BinaryPrimitives.ReadUInt64LittleEndian(encoded.AsSpan(1, sizeof(ulong))),
            Seed = BinaryPrimitives.ReadUInt64LittleEndian(encoded.AsSpan(9, sizeof(ulong)))
        };
    }
}

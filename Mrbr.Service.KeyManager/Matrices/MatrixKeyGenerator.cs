using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;

namespace Mrbr.Service.KeyManager.Matrices;

/// <summary>
/// Generates keys by walking a 3D matrix using vectors derived deterministically
/// from the start position and source text — enabling full key reproduction from
/// a single compact token (keyId + startPosition).
/// </summary>
public class MatrixKeyGenerator {
    private readonly Configuration.KeyMatrixSettings _settings;
    private readonly OptimizedKeyWalker _walker;
    private readonly MatrixBuilder _builder;
    private readonly int _widthMask;
    private readonly int _heightMask;
    private readonly int _depthMask;

    /// <summary>
    /// Initializes a new instance of MatrixKeyGenerator.
    /// </summary>
    /// <param name="options">Matrix configuration settings</param>
    public MatrixKeyGenerator(IOptions<Configuration.KeyMatrixSettings> options) {
        _settings = options.Value;
        _walker = new OptimizedKeyWalker(options);
        _builder = new MatrixBuilder(options);

        _widthMask = _settings.Width - 1;
        _heightMask = _settings.Height - 1;
        _depthMask = _settings.Depth - 1;
    }

    /// <summary>
    /// Initializes a new instance of MatrixKeyGenerator with settings directly.
    /// </summary>
    /// <param name="settings">Matrix configuration settings</param>
    public MatrixKeyGenerator(Configuration.KeyMatrixSettings settings) {
        _settings = settings;
        _walker = new OptimizedKeyWalker(Microsoft.Extensions.Options.Options.Create(settings));
        _builder = new MatrixBuilder(settings);

        _widthMask = _settings.Width - 1;
        _heightMask = _settings.Height - 1;
        _depthMask = _settings.Depth - 1;
    }

    /// <summary>
    /// Generates a matrix key using a random start position. Vectors are derived
    /// deterministically from the start position and source text, so the returned
    /// startPosition alone (combined with the source text) is sufficient to reproduce
    /// identical key bytes via <see cref="RegenerateKey(string,byte,int,int)"/>.
    /// </summary>
    /// <param name="sourceText">Source text to use as matrix data</param>
    /// <param name="keyId">The key ID (0-255)</param>
    /// <param name="maxTargetBytes">Target key size in bytes (16, 24, or 32)</param>
    /// <returns>Result containing generated key bytes, start position, and derived vectors</returns>
    public unsafe MatrixKeyResult GenerateKey(string sourceText, byte keyId, int maxTargetBytes) {
        byte[] flatMatrix = _builder.BuildFlatMatrix(sourceText);

        int startX = RandomNumberGenerator.GetInt32(_settings.Width);
        int startY = RandomNumberGenerator.GetInt32(_settings.Height);
        int startZ = RandomNumberGenerator.GetInt32(_settings.Depth);

        int startPosition = startX + (startY * _settings.Width) + (startZ * _settings.Width * _settings.Height);

        // Derive vectors deterministically — same sourceText + startPosition always gives same vectors
        byte[] vectors = DeriveVectors(sourceText, startPosition);

        byte[] keyBytes = new byte[maxTargetBytes];

        fixed (byte* pVectors = vectors)
        fixed (byte* pResult = keyBytes) {
            int bytesWritten = _walker.WalkMatrixUnsafe(
                flatMatrix, startX, startY, startZ,
                pVectors, pResult, maxTargetBytes
            );

            if (bytesWritten < maxTargetBytes) {
                for (int i = bytesWritten; i < maxTargetBytes; i++) {
                    keyBytes[i] = flatMatrix[i % flatMatrix.Length];
                }
            }
        }

        return new MatrixKeyResult {
            KeyId = keyId,
            StartPosition = startPosition,
            Vectors = vectors,
            KeyBytes = keyBytes
        };
    }

    /// <summary>
    /// Reproduces a key using only the start position. Vectors are re-derived
    /// deterministically from sourceText and startPosition — no stored vectors needed.
    /// This is the primary reproduction path used by KeyService.GetKeyBytes.
    /// </summary>
    /// <param name="sourceText">Source text to use as matrix data</param>
    /// <param name="keyId">The key ID (0-255)</param>
    /// <param name="startPosition">Encoded start position (from MatrixKeyResult or decoded keyResult)</param>
    /// <param name="maxTargetBytes">Target key size in bytes</param>
    /// <returns>Result containing the reproduced key bytes</returns>
    public unsafe MatrixKeyResult RegenerateKey(string sourceText, byte keyId, int startPosition, int maxTargetBytes) {
        byte[] flatMatrix = _builder.BuildFlatMatrix(sourceText);

        byte[] vectors = DeriveVectors(sourceText, startPosition);

        int startX = startPosition & _widthMask;
        int remainder = startPosition >> GetBitCount(_widthMask);
        int startY = remainder & _heightMask;
        int startZ = remainder >> GetBitCount(_heightMask);

        byte[] keyBytes = new byte[maxTargetBytes];

        fixed (byte* pVectors = vectors)
        fixed (byte* pResult = keyBytes) {
            int bytesWritten = _walker.WalkMatrixUnsafe(
                flatMatrix, startX, startY, startZ,
                pVectors, pResult, maxTargetBytes
            );

            if (bytesWritten < maxTargetBytes) {
                for (int i = bytesWritten; i < maxTargetBytes; i++) {
                    keyBytes[i] = flatMatrix[i % flatMatrix.Length];
                }
            }
        }

        return new MatrixKeyResult {
            KeyId = keyId,
            StartPosition = startPosition,
            Vectors = vectors,
            KeyBytes = keyBytes
        };
    }

    /// <summary>
    /// Recreates a key using an explicit pre-supplied vector array.
    /// Used for testing specific vector patterns; for normal reproduction
    /// prefer <see cref="RegenerateKey(string,byte,int,int)"/>.
    /// </summary>
    /// <param name="sourceText">Source text to use as matrix data</param>
    /// <param name="keyId">The key ID (0-255)</param>
    /// <param name="startPosition">Encoded start position</param>
    /// <param name="vectors">16-byte vector array</param>
    /// <param name="maxTargetBytes">Target key size in bytes</param>
    /// <returns>Result containing the regenerated key bytes</returns>
    public unsafe MatrixKeyResult RegenerateKey(string sourceText, byte keyId, int startPosition, byte[] vectors, int maxTargetBytes) {
        if (vectors.Length != 16) {
            throw new ArgumentException("Vectors must be exactly 16 bytes.", nameof(vectors));
        }

        byte[] flatMatrix = _builder.BuildFlatMatrix(sourceText);

        int startX = startPosition & _widthMask;
        int remainder = startPosition >> GetBitCount(_widthMask);
        int startY = remainder & _heightMask;
        int startZ = remainder >> GetBitCount(_heightMask);

        byte[] keyBytes = new byte[maxTargetBytes];

        fixed (byte* pVectors = vectors)
        fixed (byte* pResult = keyBytes) {
            int bytesWritten = _walker.WalkMatrixUnsafe(
                flatMatrix, startX, startY, startZ,
                pVectors, pResult, maxTargetBytes
            );

            if (bytesWritten < maxTargetBytes) {
                for (int i = bytesWritten; i < maxTargetBytes; i++) {
                    keyBytes[i] = flatMatrix[i % flatMatrix.Length];
                }
            }
        }

        return new MatrixKeyResult {
            KeyId = keyId,
            StartPosition = startPosition,
            Vectors = vectors,
            KeyBytes = keyBytes
        };
    }

    /// <summary>
    /// Derives 16 deterministic vector bytes from the source text and start position
    /// using HMAC-SHA256. The same inputs always produce the same 16 bytes, ensuring
    /// full key reproduction without storing vectors.
    /// </summary>
    /// <param name="sourceText">Source text used as the HMAC key material</param>
    /// <param name="startPosition">Start position used as HMAC data</param>
    /// <returns>16 deterministic vector bytes (each clamped to 0-30, stop marker avoided)</returns>
    public static byte[] DeriveVectors(string sourceText, int startPosition) {
        // Hash the source text once as the stable HMAC key
        byte[] sourceHash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sourceText));

        // HMAC-SHA256 keyed by source hash, data is the 4-byte start position
        Span<byte> positionBytes = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(positionBytes, startPosition);

        byte[] hmac = HMACSHA256.HashData(sourceHash, positionBytes);

        // Take first 16 bytes, clamp each to 0-30 (avoid stop marker 31)
        byte[] vectors = new byte[16];
        for (int i = 0; i < 16; i++) {
            vectors[i] = (byte)(hmac[i] % 31);
        }

        return vectors;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int GetBitCount(int mask) {
        int count = 0;
        while (mask > 0) {
            count++;
            mask >>= 1;
        }
        return count;
    }
}


/// <summary>
/// Result of matrix key generation containing all necessary information to recreate the key.
/// </summary>
public class MatrixKeyResult {
    /// <summary>
    /// The key ID (0-255).
    /// </summary>
    public byte KeyId { get; init; }

    /// <summary>
    /// Encoded start position in the matrix (10 bits: x + y*width + z*width*height).
    /// </summary>
    public int StartPosition { get; init; }

    /// <summary>
    /// 16-byte vector array defining the walk path.
    /// </summary>
    public byte[] Vectors { get; init; } = Array.Empty<byte>();

    /// <summary>
    /// The generated key bytes.
    /// </summary>
    public byte[] KeyBytes { get; init; } = Array.Empty<byte>();

    /// <summary>
    /// Encodes the complete matrix key information into a byte array.
    /// Format: [keyId:1byte][startPosition:2bytes][vectors:16bytes] = 19 bytes total
    /// </summary>
    public byte[] EncodeToBytes() {
        byte[] result = new byte[19];
        result[0] = KeyId;
        result[1] = (byte)(StartPosition & 0xFF);
        result[2] = (byte)((StartPosition >> 8) & 0xFF);
        Array.Copy(Vectors, 0, result, 3, 16);
        return result;
    }

    /// <summary>
    /// Decodes matrix key information from a byte array.
    /// </summary>
    public static MatrixKeyResult DecodeFromBytes(byte[] encoded) {
        if (encoded.Length < 19) {
            throw new ArgumentException("Encoded data must be at least 19 bytes.", nameof(encoded));
        }

        byte keyId = encoded[0];
        int startPosition = encoded[1] | (encoded[2] << 8);
        byte[] vectors = new byte[16];
        Array.Copy(encoded, 3, vectors, 0, 16);

        return new MatrixKeyResult {
            KeyId = keyId,
            StartPosition = startPosition,
            Vectors = vectors
        };
    }
}

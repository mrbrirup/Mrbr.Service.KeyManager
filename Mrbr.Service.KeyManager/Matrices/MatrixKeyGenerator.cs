using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;

namespace Mrbr.Service.KeyManager.Matrices;

/// <summary>
/// Generates keys by walking a 3D matrix using random vectors.
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
    /// Generates a matrix key by walking the 3D space with random vectors.
    /// </summary>
    /// <param name="sourceText">Source text to use as matrix data</param>
    /// <param name="keyId">The key ID (0-255)</param>
    /// <param name="maxTargetBytes">Target key size in bytes (typically 16, 24, or 32)</param>
    /// <returns>Result containing the generated key bytes, start position, and vectors</returns>
    public unsafe MatrixKeyResult GenerateKey(string sourceText, byte keyId, int maxTargetBytes) {
        // Build the flat matrix from source text
        byte[] flatMatrix = _builder.BuildFlatMatrix(sourceText);

        // Generate random start position within matrix bounds
        int startX = RandomNumberGenerator.GetInt32(_settings.Width);
        int startY = RandomNumberGenerator.GetInt32(_settings.Height);
        int startZ = RandomNumberGenerator.GetInt32(_settings.Depth);

        // Encode start position as single value: x + (y * width) + (z * width * height)
        int startPosition = startX + (startY * _settings.Width) + (startZ * _settings.Width * _settings.Height);

        // Generate 16 random vectors (each 0-31, with 0=no-op, 31=stop)
        byte[] vectors = GenerateRandomVectors(16);

        // Allocate result buffer
        byte[] keyBytes = new byte[maxTargetBytes];

        // Walk the matrix using the generated vectors
        fixed (byte* pVectors = vectors)
        fixed (byte* pResult = keyBytes) {
            int bytesWritten = _walker.WalkMatrixUnsafe(
                flatMatrix,
                startX, startY, startZ,
                pVectors,
                pResult,
                maxTargetBytes
            );

            // If we didn't get enough bytes, fill remainder with deterministic data
            if (bytesWritten < maxTargetBytes) {
                // Use remaining source material cyclically
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
    /// Recreates a key using a known start position and vectors.
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

        // Build the flat matrix
        byte[] flatMatrix = _builder.BuildFlatMatrix(sourceText);

        // Decode start position
        int startX = startPosition & _widthMask;
        int remainder = startPosition >> GetBitCount(_widthMask);
        int startY = remainder & _heightMask;
        int startZ = remainder >> GetBitCount(_heightMask);

        // Allocate result buffer
        byte[] keyBytes = new byte[maxTargetBytes];

        // Walk the matrix
        fixed (byte* pVectors = vectors)
        fixed (byte* pResult = keyBytes) {
            int bytesWritten = _walker.WalkMatrixUnsafe(
                flatMatrix,
                startX, startY, startZ,
                pVectors,
                pResult,
                maxTargetBytes
            );

            // Fill remainder if needed
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
    /// Generates 16 random vector bytes, each in range 0-31.
    /// Vector 0 = no-op, 1-26 = directional moves, 31 = stop marker.
    /// </summary>
    private static byte[] GenerateRandomVectors(int count) {
        byte[] vectors = new byte[count];

        for (int i = 0; i < count; i++) {
            // Generate random value 0-30 (avoid 31 stop marker for most vectors)
            // Last few vectors have higher chance of being movement vectors
            vectors[i] = (byte)RandomNumberGenerator.GetInt32(0, 27);
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

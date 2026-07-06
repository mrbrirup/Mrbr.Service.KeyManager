using System.ComponentModel.DataAnnotations;

namespace Mrbr.Service.KeyManager.Configuration;

/// <summary>
/// Configuration settings for Matrix key generation.
/// Dimensions must be powers of two so coordinate wrapping and offset packing can use bit operations.
/// </summary>
public class KeyMatrixSettings {
    public const string SectionName = "KeyMatrixSettings";
    public const int LegMagnitude = 8;
    public const int HandlePayloadBits = 48;
    public const int MinimumSeedBits = 16;

    /// <summary>
    /// Width of the matrix (X dimension). Must be a power of 2.
    /// </summary>
    [Range(8, 2048, ErrorMessage = "Width must be between 8 and 2048.")]
    public int Width { get; set; }

    /// <summary>
    /// Height of the matrix (Y dimension). Must be a power of 2.
    /// </summary>
    [Range(8, 2048, ErrorMessage = "Height must be between 8 and 2048.")]
    public int Height { get; set; }

    /// <summary>
    /// Depth of the matrix (Z dimension). Must be a power of 2.
    /// </summary>
    [Range(8, 2048, ErrorMessage = "Depth must be between 8 and 2048.")]
    public int Depth { get; set; }

    /// <summary>
    /// Validates dimensions and verifies that a Matrix key handle has room for start position and seed.
    /// </summary>
    public void Validate() {
        if (!IsPowerOfTwo(Width)) {
            throw new InvalidOperationException($"Width ({Width}) must be a power of 2.");
        }

        if (!IsPowerOfTwo(Height)) {
            throw new InvalidOperationException($"Height ({Height}) must be a power of 2.");
        }

        if (!IsPowerOfTwo(Depth)) {
            throw new InvalidOperationException($"Depth ({Depth}) must be a power of 2.");
        }

        int startBits = GetStartBitCount();
        int seedBits = HandlePayloadBits - startBits;
        if (seedBits < MinimumSeedBits) {
            throw new InvalidOperationException(
                $"Matrix dimensions require {startBits} start-position bits, leaving only {seedBits} seed bits in the KeyHandle. At least {MinimumSeedBits} seed bits are required.");
        }

        long totalCells = GetMatrixCellCount64();
        if (totalCells > int.MaxValue) {
            throw new InvalidOperationException(
                $"Matrix is too large. Total size is {totalCells} bytes, but must fit in a single in-memory byte array.");
        }

        if (totalCells < 128) {
            throw new InvalidOperationException(
                $"Matrix is too small. Total size is {totalCells} bytes, but must be at least 128 bytes.");
        }
    }

    /// <summary>
    /// Validates dimensions and verifies that configured source bytes can fill the matrix.
    /// </summary>
    public void Validate(int sourceByteLength) {
        Validate();

        int requiredBytes = GetMatrixLength();
        if (sourceByteLength < requiredBytes) {
            throw new InvalidOperationException(
                $"Matrix source is too small. Need at least {requiredBytes} bytes for a {Width}x{Height}x{Depth} matrix, but got {sourceByteLength} bytes.");
        }
    }

    public int GetMatrixLength() {
        long totalCells = GetMatrixCellCount64();
        if (totalCells > int.MaxValue) {
            throw new InvalidOperationException(
                $"Matrix is too large. Total size is {totalCells} bytes, but must fit in a single in-memory byte array.");
        }

        return (int)totalCells;
    }

    public int GetStartBitCount() => GetPowerOfTwoExponent(Width) + GetPowerOfTwoExponent(Height) + GetPowerOfTwoExponent(Depth);

    public int GetWidthBitCount() => GetPowerOfTwoExponent(Width);

    public int GetHeightBitCount() => GetPowerOfTwoExponent(Height);

    private static bool IsPowerOfTwo(int value) => value > 0 && (value & (value - 1)) == 0;

    private long GetMatrixCellCount64() => (long)Width * Height * Depth;

    private static int GetPowerOfTwoExponent(int value) {
        int bits = 0;
        while (value > 1) {
            bits++;
            value >>= 1;
        }

        return bits;
    }
}

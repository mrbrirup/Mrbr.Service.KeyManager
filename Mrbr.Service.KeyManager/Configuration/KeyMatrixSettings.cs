using System;
using System.Collections.Generic;
using System.Text;
using System.ComponentModel.DataAnnotations;

namespace Mrbr.Service.KeyManager.Configuration;

/// <summary>
/// Configuration settings for Matrix (3D vector-based) key generation.
/// All dimensions must be powers of 2.
/// </summary>
public class KeyMatrixSettings {
    public const string SectionName = "KeyMatrixSettings";

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
    /// 64-bit mask applied to vectors for obfuscation (covers up to 8 packed 8-bit or 5-bit numbers).
    /// </summary>
    public ulong VectorMask { get; set; }

    /// <summary>
    /// 64-bit mask applied across the output keys for obfuscation.
    /// </summary>
    public ulong KeyMask { get; set; }

    /// <summary>
    /// Validates that all dimensions are powers of 2.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when validation fails</exception>
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

        int totalCells = Width * Height * Depth;
        int totalBytes = totalCells * 8;

        if (totalBytes < 128) {
            throw new InvalidOperationException(
                $"Matrix is too small. Total size is {totalBytes} bytes, but must be at least 128 bytes.");
        }
    }

    private static bool IsPowerOfTwo(int value) {
        return value > 0 && (value & (value - 1)) == 0;
    }
}

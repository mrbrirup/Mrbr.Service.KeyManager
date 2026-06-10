using System.ComponentModel.DataAnnotations;

namespace Mrbr.Service.KeyManager.Configuration;

/// <summary>
/// Configuration settings for Block (1D contiguous) key generation.
/// </summary>
public class KeyBlockSettings {
    public const string SectionName = "KeyBlockSettings";

    /// <summary>
    /// Minimum length for generated keys.
    /// </summary>
    [Range(1, 1024, ErrorMessage = "MinLength must be between 1 and 1024 characters.")]
    public int MinLength { get; set; } = 64;

    /// <summary>
    /// Maximum length for generated keys.
    /// </summary>
    [Range(1, 1024, ErrorMessage = "MaxLength must be between 1 and 1024 characters.")]
    public int MaxLength { get; set; } = 128;

    /// <summary>
    /// Validates that the source text is large enough to support the configured key lengths.
    /// </summary>
    /// <param name="sourceTextLength">Length of the source text</param>
    /// <exception cref="InvalidOperationException">Thrown when validation fails</exception>
    public void Validate(int sourceTextLength) {
        if (MinLength > MaxLength) {
            throw new InvalidOperationException($"MinLength ({MinLength}) cannot be greater than MaxLength ({MaxLength}).");
        }

        if (MaxLength > sourceTextLength) {
            throw new InvalidOperationException($"MaxLength ({MaxLength}) cannot exceed source text length ({sourceTextLength}).");
        }

        if (sourceTextLength < MinLength + MaxLength) {
            throw new InvalidOperationException(
                $"Source text length ({sourceTextLength}) must be at least MinLength + MaxLength ({MinLength + MaxLength}) to ensure adequate key space.");
        }
    }
}

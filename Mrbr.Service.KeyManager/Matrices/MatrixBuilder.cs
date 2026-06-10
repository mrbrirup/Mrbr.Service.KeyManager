using Microsoft.Extensions.Options;
using System.Text;

namespace Mrbr.Service.KeyManager.Matrices;

/// <summary>
/// Builds a flat 3D byte matrix from source text for use with OptimizedKeyWalker.
/// </summary>
public class MatrixBuilder {
    private readonly Configuration.KeyMatrixSettings _settings;
    private readonly int _totalCells;
    private readonly int _totalBytes;

    /// <summary>
    /// Initializes a new instance of MatrixBuilder with the specified settings.
    /// </summary>
    /// <param name="options">Matrix configuration settings</param>
    public MatrixBuilder(IOptions<Configuration.KeyMatrixSettings> options) {
        _settings = options.Value;
        _totalCells = _settings.Width * _settings.Height * _settings.Depth;
        _totalBytes = _totalCells * 8; // 8 bytes per cell
    }

    /// <summary>
    /// Initializes a new instance of MatrixBuilder with settings directly.
    /// </summary>
    /// <param name="settings">Matrix configuration settings</param>
    public MatrixBuilder(Configuration.KeyMatrixSettings settings) {
        _settings = settings;
        _totalCells = _settings.Width * _settings.Height * _settings.Depth;
        _totalBytes = _totalCells * 8; // 8 bytes per cell
    }

    /// <summary>
    /// Builds a flat byte array representing a 3D matrix from the source text.
    /// The matrix follows the layout: [x + (y * width) + (z * width * height)] * 8 bytes per cell.
    /// </summary>
    /// <param name="sourceText">Source text to convert into matrix</param>
    /// <returns>Flat byte array representing the 3D matrix</returns>
    /// <exception cref="ArgumentException">Thrown when source text is too small</exception>
    public byte[] BuildFlatMatrix(string sourceText) {
        if (string.IsNullOrEmpty(sourceText)) {
            throw new ArgumentException("Source text cannot be null or empty.", nameof(sourceText));
        }

        // Convert source text to UTF-8 bytes
        byte[] sourceBytes = Encoding.UTF8.GetBytes(sourceText);

        if (sourceBytes.Length < _totalBytes) {
            throw new ArgumentException(
                $"Source text is too small. Need at least {_totalBytes} bytes for a {_settings.Width}×{_settings.Height}×{_settings.Depth} matrix (8 bytes per cell), but got {sourceBytes.Length} bytes.",
                nameof(sourceText));
        }

        // Create the flat matrix array
        byte[] flatMatrix = new byte[_totalBytes];

        // Copy source bytes into the matrix
        // If source is larger than needed, we only use what fits
        int bytesToCopy = Math.Min(sourceBytes.Length, _totalBytes);
        Array.Copy(sourceBytes, 0, flatMatrix, 0, bytesToCopy);

        // If source is shorter than matrix capacity, wrap/repeat the source
        if (sourceBytes.Length < _totalBytes) {
            int offset = sourceBytes.Length;
            while (offset < _totalBytes) {
                int remaining = _totalBytes - offset;
                int copySize = Math.Min(sourceBytes.Length, remaining);
                Array.Copy(sourceBytes, 0, flatMatrix, offset, copySize);
                offset += copySize;
            }
        }

        return flatMatrix;
    }

    /// <summary>
    /// Gets the total number of cells in the matrix.
    /// </summary>
    public int TotalCells => _totalCells;

    /// <summary>
    /// Gets the total number of bytes in the matrix (cells * 8).
    /// </summary>
    public int TotalBytes => _totalBytes;

    /// <summary>
    /// Validates that the matrix dimensions are powers of 2.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when dimensions are invalid</exception>
    public void ValidateDimensions() {
        if (!IsPowerOfTwo(_settings.Width)) {
            throw new InvalidOperationException($"Width ({_settings.Width}) must be a power of 2.");
        }
        if (!IsPowerOfTwo(_settings.Height)) {
            throw new InvalidOperationException($"Height ({_settings.Height}) must be a power of 2.");
        }
        if (!IsPowerOfTwo(_settings.Depth)) {
            throw new InvalidOperationException($"Depth ({_settings.Depth}) must be a power of 2.");
        }
    }

    private static bool IsPowerOfTwo(int value) {
        return value > 0 && (value & (value - 1)) == 0;
    }
}

using Microsoft.Extensions.Options;
using System.Text;

namespace Mrbr.Service.KeyManager.Matrices;

/// <summary>
/// Builds a flat one-byte-per-cell 3D matrix from source text.
/// </summary>
public class MatrixBuilder {
    private readonly Configuration.KeyMatrixSettings _settings;
    private readonly int _totalBytes;

    public MatrixBuilder(IOptions<Configuration.KeyMatrixSettings> options) : this(options.Value) { }

    public MatrixBuilder(Configuration.KeyMatrixSettings settings) {
        _settings = settings;
        _settings.Validate();
        _totalBytes = _settings.GetMatrixLength();
    }

    /// <summary>
    /// Builds a flat byte array using layout: x + (y * width) + (z * width * height).
    /// </summary>
    public byte[] BuildFlatMatrix(string sourceText) {
        if (string.IsNullOrEmpty(sourceText)) {
            throw new ArgumentException("Source text cannot be null or empty.", nameof(sourceText));
        }

        byte[] sourceBytes = Encoding.UTF8.GetBytes(sourceText);
        _settings.Validate(sourceBytes.Length);

        byte[] flatMatrix = GC.AllocateUninitializedArray<byte>(_totalBytes);
        Array.Copy(sourceBytes, 0, flatMatrix, 0, _totalBytes);
        return flatMatrix;
    }

    public int TotalCells => _totalBytes;

    public int TotalBytes => _totalBytes;

    public void ValidateDimensions() => _settings.Validate();
}

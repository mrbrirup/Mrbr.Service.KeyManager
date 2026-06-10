using Microsoft.Extensions.Options;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.Matrices;
using Mrbr.Service.KeyManager.Services;
using Xunit;
using Xunit.Abstractions;

namespace Mrbr.Service.KeyManager.Tests;

/// <summary>
/// Integration tests for Block and Matrix key generation.
/// </summary>
public class KeyGenerationTests {
    private readonly ITestOutputHelper _output;

    public KeyGenerationTests(ITestOutputHelper output) {
        _output = output;
    }

    [Fact]
    public void MatrixBuilder_BuildsFlatMatrix_Successfully() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 16,
            Height = 16,
            Depth = 8,
            VectorMask = 0,
            KeyMask = 0
        };

        var builder = new MatrixBuilder(settings);
        string sourceText = new string('A', 16 * 16 * 8 * 8); // Large enough for matrix

        // Act
        byte[] matrix = builder.BuildFlatMatrix(sourceText);

        // Assert
        Assert.Equal(16 * 16 * 8 * 8, matrix.Length);
        Assert.NotNull(matrix);
    }

    [Fact]
    public void MatrixBuilder_ValidatesDimensions_PowerOfTwo() {
        // Arrange
        var validSettings = new KeyMatrixSettings {
            Width = 16,
            Height = 16,
            Depth = 8,
            VectorMask = 0,
            KeyMask = 0
        };

        var invalidSettings = new KeyMatrixSettings {
            Width = 15,  // Not power of 2
            Height = 16,
            Depth = 8,
            VectorMask = 0,
            KeyMask = 0
        };

        var validBuilder = new MatrixBuilder(validSettings);
        var invalidBuilder = new MatrixBuilder(invalidSettings);

        // Act & Assert
        validBuilder.ValidateDimensions(); // Should not throw
        Assert.Throws<InvalidOperationException>(() => invalidBuilder.ValidateDimensions());
    }

    [Fact]
    public void MatrixKeyGenerator_GeneratesKey_Successfully() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 16,
            Height = 16,
            Depth = 8,
            VectorMask = 0,
            KeyMask = 0
        };

        var generator = new MatrixKeyGenerator(settings);
        string sourceText = new string('A', 16 * 16 * 8 * 8); // Large enough

        // Act
        var result = generator.GenerateKey(sourceText, keyId: 42, maxTargetBytes: 32);

        // Assert
        Assert.Equal(42, result.KeyId);
        Assert.Equal(32, result.KeyBytes.Length);
        Assert.Equal(16, result.Vectors.Length);
        Assert.InRange(result.StartPosition, 0, 16 * 16 * 8 - 1);
    }

    [Fact]
    public void MatrixKeyGenerator_RegeneratesKey_Consistently() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 16,
            Height = 16,
            Depth = 8,
            VectorMask = 0,
            KeyMask = 0
        };

        var generator = new MatrixKeyGenerator(settings);
        string sourceText = new string('A', 16 * 16 * 8 * 8);

        // Generate initial key
        var original = generator.GenerateKey(sourceText, keyId: 100, maxTargetBytes: 32);

        // Act - Regenerate using same parameters
        var regenerated = generator.RegenerateKey(
            sourceText, 
            keyId: 100, 
            original.StartPosition, 
            original.Vectors, 
            maxTargetBytes: 32
        );

        // Assert - Should produce identical output
        Assert.Equal(original.KeyId, regenerated.KeyId);
        Assert.Equal(original.StartPosition, regenerated.StartPosition);
        Assert.Equal(original.KeyBytes, regenerated.KeyBytes);
    }

    [Fact]
    public void MatrixKeyResult_EncodesAndDecodes_Correctly() {
        // Arrange
        var vectors = new byte[16];
        for (int i = 0; i < 16; i++) {
            vectors[i] = (byte)(i + 1);
        }

        var original = new MatrixKeyResult {
            KeyId = 123,
            StartPosition = 512,
            Vectors = vectors,
            KeyBytes = new byte[32]
        };

        // Act
        byte[] encoded = original.EncodeToBytes();
        var decoded = MatrixKeyResult.DecodeFromBytes(encoded);

        // Assert
        Assert.Equal(19, encoded.Length); // 1 + 2 + 16
        Assert.Equal(original.KeyId, decoded.KeyId);
        Assert.Equal(original.StartPosition, decoded.StartPosition);
        Assert.Equal(original.Vectors, decoded.Vectors);
    }

    [Fact]
    public void KeyBlockSettings_Validates_LengthConstraints() {
        // Arrange
        var validSettings = new KeyBlockSettings {
            MinLength = 64,
            MaxLength = 128
        };

        var invalidSettings = new KeyBlockSettings {
            MinLength = 128,
            MaxLength = 64  // Min > Max
        };

        // Act & Assert
        validSettings.Validate(200); // Should not throw
        Assert.Throws<InvalidOperationException>(() => invalidSettings.Validate(200));
    }

    [Fact]
    public void KeyServiceEntry_Validates_TypeSpecificSettings() {
        // Arrange - Block entry without Block settings
        var invalidBlockEntry = new KeyServiceEntry {
            Key = 10,
            Value = new string('A', 200),
            Type = KeyType.Block,
            BlockSettings = null,  // Missing required settings
            MatrixSettings = null
        };

        // Arrange - Valid Block entry
        var validBlockEntry = new KeyServiceEntry {
            Key = 10,
            Value = new string('A', 200),
            Type = KeyType.Block,
            BlockSettings = new KeyBlockSettings { MinLength = 64, MaxLength = 128 },
            MatrixSettings = null
        };

        // Arrange - Matrix entry without Matrix settings
        var invalidMatrixEntry = new KeyServiceEntry {
            Key = 20,
            Value = new string('A', 16 * 16 * 8 * 8),
            Type = KeyType.Matrix,
            BlockSettings = null,
            MatrixSettings = null  // Missing required settings
        };

        // Arrange - Valid Matrix entry
        var validMatrixEntry = new KeyServiceEntry {
            Key = 20,
            Value = new string('A', 16 * 16 * 8 * 8),
            Type = KeyType.Matrix,
            BlockSettings = null,
            MatrixSettings = new KeyMatrixSettings { Width = 16, Height = 16, Depth = 8 }
        };

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => invalidBlockEntry.Validate());
        validBlockEntry.Validate(); // Should not throw
        Assert.Throws<InvalidOperationException>(() => invalidMatrixEntry.Validate());
        validMatrixEntry.Validate(); // Should not throw
    }

    [Fact]
    public void KeyServiceEntry_Validates_MutuallyExclusiveSettings() {
        // Arrange - Entry with both Block and Matrix settings
        var invalidEntry = new KeyServiceEntry {
            Key = 30,
            Value = new string('A', 200),
            Type = KeyType.Block,
            BlockSettings = new KeyBlockSettings { MinLength = 64, MaxLength = 128 },
            MatrixSettings = new KeyMatrixSettings { Width = 16, Height = 16, Depth = 8 }  // Should not be present
        };

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => invalidEntry.Validate());
    }

    [Fact]
    public void KeyServiceEntry_Validates_KeyIdRange() {
        // Arrange - Invalid key IDs
        var negativeKeyEntry = new KeyServiceEntry {
            Key = -1,
            Value = new string('A', 200),
            Type = KeyType.Block,
            BlockSettings = new KeyBlockSettings { MinLength = 64, MaxLength = 128 }
        };

        var tooLargeKeyEntry = new KeyServiceEntry {
            Key = 256,  // Max is 255
            Value = new string('A', 200),
            Type = KeyType.Block,
            BlockSettings = new KeyBlockSettings { MinLength = 64, MaxLength = 128 }
        };

        var validKeyEntry = new KeyServiceEntry {
            Key = 255,  // Max valid
            Value = new string('A', 200),
            Type = KeyType.Block,
            BlockSettings = new KeyBlockSettings { MinLength = 64, MaxLength = 128 }
        };

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => negativeKeyEntry.Validate());
        Assert.Throws<InvalidOperationException>(() => tooLargeKeyEntry.Validate());
        validKeyEntry.Validate(); // Should not throw
    }

    [Fact]
    public void KeyService_Block_GenerateThenGet_WithReturnedKeyResult_ReturnsSameBytes() {
        // Arrange: single configured Block key ensures deterministic key selection.
        var config = new KeyServiceConfig {
            new() {
                Key = 0,
                Value = new string('B', 600),
                KeyIdMask = "0",
                Type = KeyType.Block,
                BlockSettings = new KeyBlockSettings { MinLength = 64, MaxLength = 128 }
            }
        };

        var options = new KeyServiceOptions(Options.Create(config));
        var service = new KeyService(options);

        // Act
        byte[] generated = service.GenerateKey256(out int keyResult);
        byte[] retrieved = service.GetKey256(keyResult);

        _output.WriteLine($"Block keyResult: {keyResult}");
        _output.WriteLine($"Block generated (hex): {Convert.ToHexString(generated)}");
        _output.WriteLine($"Block retrieved (hex): {Convert.ToHexString(retrieved)}");

        // Assert
        Assert.Equal(0, keyResult & KeyService.keyIdMask);
        Assert.Equal(generated, retrieved);
    }

    [Fact]
    public void MatrixKeyGenerator_Regenerate_WithMultipleVectors_ReturnsSameBytes() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 8,
            Height = 8,
            Depth = 8,
            VectorMask = 0,
            KeyMask = 0
        };

        var generator = new MatrixKeyGenerator(settings);
        string sourceText = BuildAsciiSourceText(8 * 8 * 8 * 8);

        var vectorSets = new[] {
            // Mixed face/edge/corner moves
            new byte[] { 1, 3, 5, 7, 11, 15, 19, 23, 2, 4, 6, 8, 12, 16, 20, 24 },
            // Includes no-op and stop marker in later steps
            new byte[] { 0, 0, 1, 2, 3, 4, 5, 6, 25, 26, 7, 8, 9, 10, 31, 0 },
            // Wrap-around-heavy movement from origin (-X/-Y/-Z repeatedly)
            new byte[] { 2, 4, 6, 2, 4, 6, 14, 18, 26, 12, 16, 24, 2, 4, 6, 31 }
        };

        const int startPosition = 0;
        const byte keyId = 201;

        foreach (var vectors in vectorSets) {
            // Act
            var first = generator.RegenerateKey(sourceText, keyId, startPosition, vectors, 32);
            var second = generator.RegenerateKey(sourceText, keyId, startPosition, vectors, 32);

            _output.WriteLine($"Matrix keyId={keyId}, startPosition={startPosition}, vectors={Convert.ToHexString(vectors)}");
            _output.WriteLine($"Matrix first (hex):  {Convert.ToHexString(first.KeyBytes)}");
            _output.WriteLine($"Matrix second (hex): {Convert.ToHexString(second.KeyBytes)}");

            // Assert
            Assert.Equal(keyId, first.KeyId);
            Assert.Equal(keyId, second.KeyId);
            Assert.Equal(startPosition, first.StartPosition);
            Assert.Equal(startPosition, second.StartPosition);
            Assert.Equal(first.KeyBytes, second.KeyBytes);
        }
    }

    [Fact]
    public void MatrixKeyGenerator_WrapAroundVectors_FromBoundary_RegeneratesSameOutput() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 8,
            Height = 8,
            Depth = 8,
            VectorMask = 0,
            KeyMask = 0
        };

        var generator = new MatrixKeyGenerator(settings);
        string sourceText = BuildAsciiSourceText(8 * 8 * 8 * 8);

        // Start at last x,y,z cell then move +X/+Y/+Z to force wrap to 0.
        int startPosition = 7 + (7 * 8) + (7 * 8 * 8);
        byte[] wrapVectors = [1, 3, 5, 1, 3, 5, 7, 11, 15, 19, 23, 25, 26, 1, 3, 5];

        // Act
        var first = generator.RegenerateKey(sourceText, keyId: 77, startPosition, wrapVectors, 32);
        var second = generator.RegenerateKey(sourceText, keyId: 77, startPosition, wrapVectors, 32);

        _output.WriteLine($"Matrix wrap keyId=77, startPosition={startPosition}, vectors={Convert.ToHexString(wrapVectors)}");
        _output.WriteLine($"Matrix wrap first (hex):  {Convert.ToHexString(first.KeyBytes)}");
        _output.WriteLine($"Matrix wrap second (hex): {Convert.ToHexString(second.KeyBytes)}");

        // Assert
        Assert.Equal(77, first.KeyId);
        Assert.Equal(first.KeyBytes, second.KeyBytes);
    }

    private static string BuildAsciiSourceText(int length) {
        return string.Create(length, length, static (span, targetLength) => {
            for (int i = 0; i < targetLength; i++) {
                span[i] = (char)('!' + (i % 90));
            }
        });
    }
}

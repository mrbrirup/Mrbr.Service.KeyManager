using Microsoft.Extensions.Options;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.Matrices;
using Mrbr.Service.KeyManager.Services;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
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
    public void MatrixKeyGenerator_RegeneratesKey_Deterministically_WithoutVectors() {
        // Arrange: vectors are derived from sourceText + startPosition, so no stored vectors needed.
        var settings = new KeyMatrixSettings {
            Width = 16,
            Height = 16,
            Depth = 8,
            VectorMask = 0,
            KeyMask = 0
        };

        var generator = new MatrixKeyGenerator(settings);
        string sourceText = new string('A', 16 * 16 * 8 * 8);

        var original = generator.GenerateKey(sourceText, keyId: 100, maxTargetBytes: 32);

        // Act - Reproduce using ONLY startPosition (no explicit vectors needed)
        var reproduced = generator.RegenerateKey(sourceText, keyId: 100, original.StartPosition, maxTargetBytes: 32);

        _output.WriteLine($"Matrix startPosition: {original.StartPosition}");
        _output.WriteLine($"Matrix original  (bytes): {Encoding.UTF8.GetString(original.KeyBytes)}");
        _output.WriteLine($"Matrix reproduced (bytes): {Encoding.UTF8.GetString(reproduced.KeyBytes)}");

        Assert.Equal(original.KeyId, reproduced.KeyId);
        Assert.Equal(original.StartPosition, reproduced.StartPosition);
        Assert.Equal(original.KeyBytes, reproduced.KeyBytes);
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
        ResetKeyServiceOptionsState();
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
    public void KeyService_Matrix_GenerateThenGet_WithReturnedKeyResult_ReturnsSameBytes() {
        // Mirrors the JWT sign/verify story:
        //   1. KeyId is created via GenerateKey256  -> SignResult
        //   2. keyResult is stored in the JWT header
        //   3. On verification GetKey256(keyResult) -> CheckResult
        //   4. SignResult == CheckResult => signature confirmed
        ResetKeyServiceOptionsState();
        string sourceText = BuildAsciiSourceText(16 * 16 * 8 * 8);
        var config = new KeyServiceConfig {
            new() {
                Key = 0,
                Value = sourceText,
                KeyIdMask = "0",
                Type = KeyType.Matrix,
                MatrixSettings = new KeyMatrixSettings { Width = 16, Height = 16, Depth = 8 }
            }
        };

        var options = new KeyServiceOptions(Options.Create(config));
        var service = new KeyService(options);

        // Act
        byte[] signResult = service.GenerateKey256(out int keyResult);
        byte[] checkResult = service.GetKey256(keyResult);

        _output.WriteLine($"Matrix keyResult:          {keyResult}");
        _output.WriteLine($"Matrix keyId (bits 0-7):   {keyResult & KeyService.keyIdMask}");
        _output.WriteLine($"Matrix startPosition:      {(keyResult >> KeyService.matrixStartPositionSize) & KeyService.matrixStartPositionMask}");
        _output.WriteLine($"Matrix SignResult  (bytes): {Encoding.UTF8.GetString(signResult)}");
        _output.WriteLine($"Matrix CheckResult (bytes): {Encoding.UTF8.GetString(checkResult)}");

        // Assert: signing and checking produce identical key bytes
        Assert.Equal(0, keyResult & KeyService.keyIdMask);
        Assert.Equal(signResult, checkResult);
    }

    [Theory]
    [RepeatData(100)]
    [Trait("Category", "Stress")]
    public void KeyService_Matrix_GenerateThenGet_Stress_ReturnsSameBytes(int iteration) {
        // Stress: verify sign/check symmetry across 100 random Matrix key generations.
        ResetKeyServiceOptionsState();
        string sourceText = BuildAsciiSourceText(8 * 8 * 8 * 8);
        var config = new KeyServiceConfig {
            new() {
                Key = 0,
                Value = sourceText,
                KeyIdMask = "0",
                Type = KeyType.Matrix,
                MatrixSettings = new KeyMatrixSettings { Width = 8, Height = 8, Depth = 8 }
            }
        };

        var options = new KeyServiceOptions(Options.Create(config));
        var service = new KeyService(options);

        int keySizeInBytes = RandomNumberGenerator.GetInt32(0, 3) switch {
            0 => 16,
            1 => 24,
            _ => 32
        };

        byte[] signResult = service.GenerateKeyBytes(keySizeInBytes, out int keyResult);
        byte[] checkResult = service.GetKeyBytes(keyResult, keySizeInBytes);

        _output.WriteLine($"Matrix iter={iteration}, keyResult={keyResult}, keySize={keySizeInBytes}");
        _output.WriteLine($"Matrix SignResult: {Encoding.UTF8.GetString(signResult)}");
        _output.WriteLine($"Matrix CheckResult: {Encoding.UTF8.GetString(checkResult)}");
        Assert.Equal(signResult, checkResult);
    }

    public void MatrixKeyGenerator_Regenerate_WithRandomizedVectorsPositionsAndLengths_ReturnsSameBytes(int iteration) {
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
        int maxStartPosition = (settings.Width * settings.Height * settings.Depth) - 1;

        byte keyId = (byte)RandomNumberGenerator.GetInt32(0, 256);
        int startPosition = RandomNumberGenerator.GetInt32(0, maxStartPosition + 1);
        int keyLength = RandomNumberGenerator.GetInt32(0, 3) switch {
            0 => 16,
            1 => 24,
            _ => 32
        };
        byte[] vectors = GenerateRandomVectors(16);

        // Act
        var first = generator.RegenerateKey(sourceText, keyId, startPosition, vectors, keyLength);
        var second = generator.RegenerateKey(sourceText, keyId, startPosition, vectors, keyLength);

        //if (iteration < 5) {
        _output.WriteLine($"Matrix iter={iteration}, keyId={keyId}, startPosition={startPosition}, keyLength={keyLength}, vectors={Convert.ToHexString(vectors)}");
        _output.WriteLine($"Matrix first (bytes):  {Encoding.UTF8.GetString(first.KeyBytes)}");
        _output.WriteLine($"Matrix second (bytes): {Encoding.UTF8.GetString(second.KeyBytes)}");
        //}

        // Assert
        Assert.Equal(keyId, first.KeyId);
        Assert.Equal(keyId, second.KeyId);
        Assert.Equal(startPosition, first.StartPosition);
        Assert.Equal(startPosition, second.StartPosition);
        Assert.Equal(first.KeyBytes, second.KeyBytes);
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
        _output.WriteLine($"Matrix wrap first (bytes):  {Encoding.UTF8.GetString(first.KeyBytes)}");
        _output.WriteLine($"Matrix wrap second (bytes): {Encoding.UTF8.GetString(second.KeyBytes)}");

        // Assert
        Assert.Equal(77, first.KeyId);
        Assert.Equal(first.KeyBytes, second.KeyBytes);
    }

    [Fact]
    public void KeyService_Block_GetKey_WrapAroundAtEnd_ReturnsExpectedMaterial() {
        // Arrange
        ResetKeyServiceOptionsState();
        string sourceText = BuildAsciiSourceText(220);
        var config = new KeyServiceConfig {
            new() {
                Key = 0,
                Value = sourceText,
                KeyIdMask = "0",
                Type = KeyType.Block,
                BlockSettings = new KeyBlockSettings { MinLength = 64, MaxLength = 128 }
            }
        };

        var options = new KeyServiceOptions(Options.Create(config));
        var service = new KeyService(options);

        const int keyId = 0;
        const int keyPosition = 200;
        const int keyLength = 64;
        int keyResult = keyId + (keyPosition << KeyService.keyPositionSize) + (keyLength << KeyService.keyPositionAndLength);

        // Act
        var key = service.GetKey(keyResult);
        string actual = new string(key.Span);

        string expected = BuildExpectedBlockMaterial(sourceText, keyPosition, keyLength);

        _output.WriteLine($"Block wrap keyResult: {keyResult}, keyPosition={keyPosition}, keyLength={keyLength}");
        _output.WriteLine($"Block wrap expected: {expected}");
        _output.WriteLine($"Block wrap actual:   {actual}");

        // Assert
        Assert.Equal(expected, actual);
    }

    [Theory]
    [RepeatData(100)]
    [Trait("Category", "Stress")]
    public void KeyService_Block_GetKey_WithRandomizedStartPositionsAndLengths_ReturnsExpectedMaterial(int iteration) {
        // Arrange
        ResetKeyServiceOptionsState();
        string sourceText = BuildAsciiSourceText(600);
        var config = new KeyServiceConfig {
            new() {
                Key = 0,
                Value = sourceText,
                KeyIdMask = "0",
                Type = KeyType.Block,
                BlockSettings = new KeyBlockSettings { MinLength = 64, MaxLength = 128 }
            }
        };

        var options = new KeyServiceOptions(Options.Create(config));
        var service = new KeyService(options);

        int keyPosition = RandomNumberGenerator.GetInt32(0, sourceText.Length);
        int keyLength = RandomNumberGenerator.GetInt32(64, 128);
        int keyResult = (keyPosition << KeyService.keyPositionSize) + (keyLength << KeyService.keyPositionAndLength);

        var key = service.GetKey(keyResult);
        string actual = new string(key.Span);
        string expected = BuildExpectedBlockMaterial(sourceText, keyPosition, keyLength);

        //if (iteration < 5) {
        _output.WriteLine($"Block iter={iteration}, keyPosition={keyPosition}, keyLength={keyLength}, keyResult={keyResult}");
        _output.WriteLine($"Block expected: {expected}");
        _output.WriteLine($"Block actual:   {actual}");
        //}

        Assert.Equal(expected, actual);
    }

    private static void ResetKeyServiceOptionsState() {
        var type = typeof(KeyServiceOptions);

        type.GetField("_keys", BindingFlags.NonPublic | BindingFlags.Static)?.SetValue(null, null);
        type.GetField("_keyMemory", BindingFlags.NonPublic | BindingFlags.Static)?.SetValue(null, null);
        type.GetField("_keyCount", BindingFlags.NonPublic | BindingFlags.Static)?.SetValue(null, 0);
        type.GetField("_initialised", BindingFlags.NonPublic | BindingFlags.Static)?.SetValue(null, false);
    }

    private static byte[] GenerateRandomVectors(int count) {
        byte[] vectors = new byte[count];
        for (int i = 0; i < count; i++) {
            vectors[i] = (byte)RandomNumberGenerator.GetInt32(0, 32);
        }

        return vectors;
    }

    private static string BuildExpectedBlockMaterial(string sourceText, int keyPosition, int keyLength) {
        if (keyPosition + keyLength <= sourceText.Length) {
            return sourceText.Substring(keyPosition, keyLength);
        }

        int firstSegmentLength = sourceText.Length - keyPosition;
        int secondSegmentLength = keyLength - firstSegmentLength;
        return sourceText.Substring(keyPosition, firstSegmentLength) + sourceText.Substring(0, secondSegmentLength);
    }

    private static string BuildAsciiSourceText(int length) {
        return string.Create(length, length, static (span, targetLength) => {
            for (int i = 0; i < targetLength; i++) {
                span[i] = (char)('!' + (i % 90));
            }
        });
    }
}

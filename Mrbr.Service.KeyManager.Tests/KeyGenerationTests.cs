using Microsoft.Extensions.Options;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.KeyHandles;
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
        Assert.Single(result.Vectors); // Directional walk now stores only first vector
        Assert.InRange(result.StartPosition, 0UL, 16UL * 16UL * 8UL - 1UL);
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

        // Act - Regenerate using same startPosition (vectors are derived dynamically)
        var regenerated = generator.RegenerateKey(
            sourceText,
            keyId: 100,
            original.StartPosition,
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
        // Arrange - Block entry without legacy Block settings
        var validBlockEntryWithoutSettings = new KeyServiceEntry {
            Key = 10,
            Value = new string('A', 200),
            Type = KeyType.Block,
            BlockSettings = null,
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
        validBlockEntryWithoutSettings.Validate(); // BlockSettings are optional for requested-length Block keys
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
                KeySourceId = 0,
                Value = new string('B', 600),
                KeyHandleMask = "0",
                Type = KeyType.Block,
            }
        };

        var options = new KeyServiceOptions(Options.Create(config));
        var service = new KeyService(options);

        // Act
        Span<byte> generated = stackalloc byte[KeyService.KeySize256];
        Span<byte> retrieved = stackalloc byte[KeyService.KeySize256];
        service.GenerateKey(generated, out ulong keyHandle);
        service.GetKey(keyHandle, retrieved);

        _output.WriteLine($"Block keyHandle: {keyHandle}");
        _output.WriteLine($"Block generated (hex): {Convert.ToHexString(generated)}");
        _output.WriteLine($"Block retrieved (hex): {Convert.ToHexString(retrieved)}");

        // Assert
        Assert.Equal(0, KeyHandleCodec.GetKeySourceId(keyHandle));
        Assert.True(generated.SequenceEqual(retrieved));
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
        byte[] signResult = service.GenerateKey256(out ulong keyResult);
        byte[] checkResult = service.GetKey256(keyResult);

        _output.WriteLine($"Matrix keyResult:          {keyResult}");
        _output.WriteLine($"Matrix keyId (bits 0-7):   {keyResult & KeyService.keyIdMask}");
        _output.WriteLine($"Matrix startPosition:      {(keyResult >> KeyService.matrixStartPositionSize) & KeyService.matrixStartPositionMask}");
        _output.WriteLine($"Matrix SignResult  (bytes): {Encoding.UTF8.GetString(signResult)}");
        _output.WriteLine($"Matrix CheckResult (bytes): {Encoding.UTF8.GetString(checkResult)}");

        // Assert: signing and checking produce identical key bytes
        Assert.Equal(0UL, keyResult & KeyService.keyIdMask);
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

        byte[] signResult = service.GenerateKeyBytes(keySizeInBytes, out ulong keyResult);
        byte[] checkResult = service.GetKeyBytes(keyResult, (ulong)keySizeInBytes);

        _output.WriteLine($"Matrix iter={iteration}, keyResult={keyResult}, keySize={keySizeInBytes}");
        _output.WriteLine($"Matrix SignResult: {Encoding.UTF8.GetString(signResult)}");
        _output.WriteLine($"Matrix CheckResult: {Encoding.UTF8.GetString(checkResult)}");
        Assert.Equal(signResult, checkResult);
    }

    [Fact]
    public void KeyService_Matrix_GenerateThenGet_WithVectorChainTracing() {
        // This test traces the directional vector chain to verify dynamic derivation
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
        byte[] signResult = service.GenerateKey256(out ulong keyResult);
        byte[] checkResult = service.GetKey256(keyResult);

        // Trace first vector and first few leg bytes
        ulong startPosition = (keyResult / (1UL << KeyService.matrixStartPositionSize)) & KeyService.matrixStartPositionMask;
        byte firstVector = MatrixKeyGenerator.DeriveFirstVector(sourceText, startPosition);

        int dx = DecodeVectorComponentPublic((byte)((firstVector >> 4) & 0x3));
        int dy = DecodeVectorComponentPublic((byte)((firstVector >> 2) & 0x3));
        int dz = DecodeVectorComponentPublic((byte)(firstVector & 0x3));

        _output.WriteLine($"=== Matrix Directional Walking Vector Chain ===");
        _output.WriteLine($"KeyResult:      {keyResult}");
        _output.WriteLine($"StartPosition:  {startPosition}");
        _output.WriteLine($"First Vector:   0x{firstVector:X2} [dx={dx}, dy={dy}, dz={dz}]");
        _output.WriteLine($"");
        _output.WriteLine($"Leg 1 bytes (0-7):   {string.Join(", ", signResult.Take(8).Select(b => b.ToString()))}");

        if (signResult.Length >= 16) {
            _output.WriteLine($"Leg 2 bytes (8-15):  {string.Join(", ", signResult.Skip(8).Take(8).Select(b => b.ToString()))}");
        }
        if (signResult.Length >= 24) {
            _output.WriteLine($"Leg 3 bytes (16-23): {string.Join(", ", signResult.Skip(16).Take(8).Select(b => b.ToString()))}");
        }
        if (signResult.Length >= 32) {
            _output.WriteLine($"Leg 4 bytes (24-31): {string.Join(", ", signResult.Skip(24).Take(8).Select(b => b.ToString()))}");
        }

        // Assert
        Assert.Equal(signResult, checkResult);
    }

    private static int DecodeVectorComponentPublic(byte component) {
        return component == 0 ? 0 : (component == 1 ? 1 : (component == 2 ? -1 : 0));
    }

    private void MatrixKeyGenerator_Regenerate_WithRandomizedVectorsPositionsAndLengths_ReturnsSameBytes(int iteration) {
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
        var first = generator.RegenerateKey(sourceText, keyId, (ulong)startPosition, vectors, keyLength);
        var second = generator.RegenerateKey(sourceText, keyId, (ulong)startPosition, vectors, keyLength);

        //if (iteration < 5) {
        _output.WriteLine($"Matrix iter={iteration}, keyId={keyId}, startPosition={startPosition}, keyLength={keyLength}, vectors={Convert.ToHexString(vectors)}");
        _output.WriteLine($"Matrix first (bytes):  {Encoding.UTF8.GetString(first.KeyBytes)}");
        _output.WriteLine($"Matrix second (bytes): {Encoding.UTF8.GetString(second.KeyBytes)}");
        //}

        // Assert
        Assert.Equal(keyId, first.KeyId);
        Assert.Equal(keyId, second.KeyId);
        Assert.Equal((ulong)startPosition, first.StartPosition);
        Assert.Equal((ulong)startPosition, second.StartPosition);
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
        var first = generator.RegenerateKey(sourceText, keyId: 77, (ulong)startPosition, wrapVectors, 32);
        var second = generator.RegenerateKey(sourceText, keyId: 77, (ulong)startPosition, wrapVectors, 32);

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
                KeySourceId = 0,
                Value = sourceText,
                KeyHandleMask = "0",
                Type = KeyType.Block,
            }
        };

        var options = new KeyServiceOptions(Options.Create(config));
        var service = new KeyService(options);

        const byte keySourceId = 0;
        const uint keyPosition = 200;
        const ushort keyLength = 64;
        ulong keyHandle = KeyHandleCodec.PackBlock(keySourceId, keyPosition, keyLength, keyHandleMask: 0);

        // Act
        Span<byte> key = stackalloc byte[keyLength];
        service.GetKey(keyHandle, key);
        string actual = Encoding.UTF8.GetString(key);

        string expected = BuildExpectedBlockMaterial(sourceText, (int)keyPosition, keyLength);

        _output.WriteLine($"Block wrap keyHandle: {keyHandle}, keyPosition={keyPosition}, keyLength={keyLength}");
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
                KeySourceId = 0,
                Value = sourceText,
                KeyHandleMask = "0",
                Type = KeyType.Block,
            }
        };

        var options = new KeyServiceOptions(Options.Create(config));
        var service = new KeyService(options);

        int keyPosition = RandomNumberGenerator.GetInt32(0, sourceText.Length);
        int keyLength = RandomNumberGenerator.GetInt32(64, 128);
        ulong keyHandle = KeyHandleCodec.PackBlock(0, (uint)keyPosition, (ushort)keyLength, keyHandleMask: 0);

        byte[] key = new byte[keyLength];
        service.GetKey(keyHandle, key);
        string actual = Encoding.UTF8.GetString(key);
        string expected = BuildExpectedBlockMaterial(sourceText, keyPosition, keyLength);

        //if (iteration < 5) {
        _output.WriteLine($"Block iter={iteration}, keyPosition={keyPosition}, keyLength={keyLength}, keyHandle={keyHandle}");
        _output.WriteLine($"Block expected: {expected}");
        _output.WriteLine($"Block actual:   {actual}");
        //}

        Assert.Equal(expected, actual);
    }

    private static void ResetKeyServiceOptionsState() {
        var type = typeof(KeyServiceOptions);

        type.GetField("_keys", BindingFlags.NonPublic | BindingFlags.Static)?.SetValue(null, null);
        type.GetField("_keyMemory", BindingFlags.NonPublic | BindingFlags.Static)?.SetValue(null, null);
        type.GetField("_keyBytes", BindingFlags.NonPublic | BindingFlags.Static)?.SetValue(null, null);
        type.GetField("_keySourceIds", BindingFlags.NonPublic | BindingFlags.Static)?.SetValue(null, null);
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

    // ==========================================
    // 6-BIT DIRECTIONAL VECTOR UNIT TESTS
    // ==========================================

    [Fact]
    public void OptimizedKeyWalker_Pack6BitVectors_RoundTrip() {
        // Arrange
        byte[] original = new byte[16];
        for (int i = 0; i < 16; i++) {
            original[i] = (byte)(i % 64); // Values 0-15 (modulo 64 to stay in 6-bit range)
        }

        byte[] packed = new byte[12];
        byte[] unpacked = new byte[16];

        // Act
        OptimizedKeyWalker.Pack6BitVectors(original, packed);

        unsafe {
            fixed (byte* pUnpacked = unpacked) {
                OptimizedKeyWalker.Unpack6BitVectors(packed, pUnpacked);
            }
        }

        // Assert
        Assert.Equal(12, packed.Length);
        Assert.Equal(original, unpacked);

        _output.WriteLine("Pack6BitVectors round-trip test passed");
        _output.WriteLine($"Original:  {string.Join(",", original)}");
        _output.WriteLine($"Unpacked:  {string.Join(",", unpacked)}");
    }

    [Theory]
    [InlineData(0, 0)]   // 00 -> 0 (no move)
    [InlineData(1, 1)]   // 01 -> +1
    [InlineData(2, -1)]  // 10 -> -1
    [InlineData(3, 0)]   // 11 -> 0 (reserved, treated as no-move)
    public void OptimizedKeyWalker_DecodeVectorComponent_AllValues(byte component, int expected) {
        // Act
        int result = TestDecodeVectorComponent(component);

        // Assert
        Assert.Equal(expected, result);
        _output.WriteLine($"Component {component:X2} -> {result}");
    }

    [Fact]
    public void MatrixKeyGenerator_DeriveFirstVector_Deterministic() {
        // Arrange
        string sourceText = BuildAsciiSourceText(1024);
        var startPosition = 100;

        // Act
        byte vector1 = MatrixKeyGenerator.DeriveFirstVector(sourceText, (ulong)startPosition);
        byte vector2 = MatrixKeyGenerator.DeriveFirstVector(sourceText, (ulong)startPosition);

        // Assert
        Assert.Equal(vector1, vector2);
        Assert.InRange(vector1, (byte)0x00, (byte)0x3E); // Should not be 0x3F (stop marker)

        // Decode components
        byte x = (byte)((vector1 >> 4) & 0x3);
        byte y = (byte)((vector1 >> 2) & 0x3);
        byte z = (byte)(vector1 & 0x3);

        // None should be 3 (reserved/11)
        Assert.NotEqual(3, x);
        Assert.NotEqual(3, y);
        Assert.NotEqual(3, z);

        _output.WriteLine($"DeriveFirstVector deterministic: {vector1:X2} [x={x}, y={y}, z={z}]");
    }

    [Fact]
    public void MatrixKeyGenerator_DeriveFirstVector_DifferentPositions_ProduceDifferentVectors() {
        // Arrange
        string sourceText = BuildAsciiSourceText(1024);

        // Act
        byte vector1 = MatrixKeyGenerator.DeriveFirstVector(sourceText, 100);
        byte vector2 = MatrixKeyGenerator.DeriveFirstVector(sourceText, 200);
        byte vector3 = MatrixKeyGenerator.DeriveFirstVector(sourceText, 300);

        // Assert - different positions should produce different vectors (statistically)
        bool allDifferent = vector1 != vector2 && vector2 != vector3 && vector1 != vector3;

        _output.WriteLine($"Position 100: {vector1:X2}");
        _output.WriteLine($"Position 200: {vector2:X2}");
        _output.WriteLine($"Position 300: {vector3:X2}");
        _output.WriteLine($"All different: {allDifferent}");

        // At least some should differ (very high probability)
        Assert.True(vector1 != vector2 || vector2 != vector3);
    }

    [Fact]
    public void OptimizedKeyWalker_DeriveNextVectorInline_ProducesDifferentVectors() {
        // Arrange
        byte[] leg1Bytes = new byte[8] { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[] leg2Bytes = new byte[8] { 10, 20, 30, 40, 50, 60, 70, 80 };
        byte[] leg3Bytes = new byte[8] { 100, 101, 102, 103, 104, 105, 106, 107 };

        // Act
        byte vector1, vector2, vector3;
        unsafe {
            fixed (byte* p1 = leg1Bytes)
            fixed (byte* p2 = leg2Bytes)
            fixed (byte* p3 = leg3Bytes) {
                vector1 = TestDeriveNextVectorInline(p1);
                vector2 = TestDeriveNextVectorInline(p2);
                vector3 = TestDeriveNextVectorInline(p3);
            }
        }

        // Assert - different inputs should produce different outputs
        Assert.NotEqual(0x3F, vector1); // Should not be stop marker
        Assert.NotEqual(0x3F, vector2);
        Assert.NotEqual(0x3F, vector3);

        _output.WriteLine($"Leg1 bytes -> vector: {vector1:X2}");
        _output.WriteLine($"Leg2 bytes -> vector: {vector2:X2}");
        _output.WriteLine($"Leg3 bytes -> vector: {vector3:X2}");

        // At least some should differ
        Assert.True(vector1 != vector2 || vector2 != vector3);
    }

    // Helper method to access private DecodeVectorComponent via reflection (for testing)
    private static int TestDecodeVectorComponent(byte component) {
        var method = typeof(OptimizedKeyWalker).GetMethod("DecodeVectorComponent",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

        return (int)method!.Invoke(null, new object[] { component })!;
    }

    // Helper method to access private DeriveNextVectorInline via reflection (for testing)
    private static unsafe byte TestDeriveNextVectorInline(byte* pLegBytes) {
        var method = typeof(OptimizedKeyWalker).GetMethod("DeriveNextVectorInline",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

        return (byte)method!.Invoke(null, new object[] { (IntPtr)pLegBytes })!;
    }

    // ==========================================
    // DIRECTIONAL WALKING INTEGRATION TESTS
    // ==========================================

    [Fact]
    public void OptimizedKeyWalker_DirectionalWalk_SingleLeg_Collects8Bytes() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 32,
            Height = 32,
            Depth = 16,
            VectorMask = 0,
            KeyMask = 0
        };

        var walker = new OptimizedKeyWalker(Options.Create(settings));
        var builder = new MatrixBuilder(settings);

        string sourceText = BuildAsciiSourceText(32 * 32 * 16 * 8);
        byte[] flatMatrix = builder.BuildFlatMatrix(sourceText);

        byte[] result = new byte[8];
        byte testVector = 0x01; // [00, 00, 01] = +X direction only

        // Act
        int bytesWritten;
        unsafe {
            fixed (byte* pResult = result) {
                bytesWritten = walker.WalkMatrixDirectional(
                    flatMatrix, 10, 10, 10, // Start position
                    testVector, pResult, 8);
            }
        }

        // Assert
        Assert.Equal(8, bytesWritten);
        Assert.All(result, b => Assert.NotEqual(0, b)); // Should have collected data

        _output.WriteLine($"Single leg walk collected {bytesWritten} bytes");
        _output.WriteLine($"Bytes: {string.Join(", ", result)}");
    }

    [Fact]
    public void OptimizedKeyWalker_DirectionalWalk_WrapAroundPerStep() {
        // Arrange - small matrix for easy wrap testing
        var settings = new KeyMatrixSettings {
            Width = 16,
            Height = 16,
            Depth = 8,
            VectorMask = 0,
            KeyMask = 0
        };

        var walker = new OptimizedKeyWalker(Options.Create(settings));
        var builder = new MatrixBuilder(settings);

        string sourceText = BuildAsciiSourceText(16 * 16 * 8 * 8);
        byte[] flatMatrix = builder.BuildFlatMatrix(sourceText);

        byte[] result = new byte[16];
        byte testVector = 0x01; // +X direction

        // Act - start near boundary to force wrap
        int bytesWritten;
        unsafe {
            fixed (byte* pResult = result) {
                bytesWritten = walker.WalkMatrixDirectional(
                    flatMatrix, 14, 5, 5, // Start at x=14, will wrap at x=0 after 2 steps
                    testVector, pResult, 16);
            }
        }

        // Assert
        Assert.Equal(16, bytesWritten);
        _output.WriteLine($"Wrap-around walk collected {bytesWritten} bytes");
        _output.WriteLine($"Starting position [14,5,5], vector +X, width=16");
    }

    [Fact]
    public void OptimizedKeyWalker_DirectionalWalk_MultiLegChain() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 32,
            Height = 32,
            Depth = 16,
            VectorMask = 0,
            KeyMask = 0
        };

        var walker = new OptimizedKeyWalker(Options.Create(settings));
        var builder = new MatrixBuilder(settings);

        string sourceText = BuildAsciiSourceText(32 * 32 * 16 * 8);
        byte[] flatMatrix = builder.BuildFlatMatrix(sourceText);

        byte[] result = new byte[32]; // 4 legs × 8 bytes
        byte firstVector = 0x15; // [01, 01, 01] = +X, +Y, +Z diagonal

        // Act
        int bytesWritten;
        unsafe {
            fixed (byte* pResult = result) {
                bytesWritten = walker.WalkMatrixDirectional(
                    flatMatrix, 10, 10, 10,
                    firstVector, pResult, 32);
            }
        }

        // Assert
        Assert.Equal(32, bytesWritten);
        _output.WriteLine($"Multi-leg walk collected {bytesWritten} bytes (4 legs × 8 bytes)");

        // Show first few bytes from each leg
        _output.WriteLine($"Leg 1: {result[0]}, {result[1]}, ..., {result[7]}");
        _output.WriteLine($"Leg 2: {result[8]}, {result[9]}, ..., {result[15]}");
        _output.WriteLine($"Leg 3: {result[16]}, {result[17]}, ..., {result[23]}");
        _output.WriteLine($"Leg 4: {result[24]}, {result[25]}, ..., {result[31]}");
    }

    [Fact]
    public void OptimizedKeyWalker_DirectionalWalk_StopMarkerHandling() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 32,
            Height = 32,
            Depth = 16,
            VectorMask = 0,
            KeyMask = 0
        };

        var walker = new OptimizedKeyWalker(Options.Create(settings));
        var builder = new MatrixBuilder(settings);

        string sourceText = BuildAsciiSourceText(32 * 32 * 16 * 8);
        byte[] flatMatrix = builder.BuildFlatMatrix(sourceText);

        byte[] result = new byte[64];
        byte stopMarker = 0x3F; // [11, 11, 11] = stop marker

        // Act - should stop immediately
        int bytesWritten;
        unsafe {
            fixed (byte* pResult = result) {
                bytesWritten = walker.WalkMatrixDirectional(
                    flatMatrix, 10, 10, 10,
                    stopMarker, pResult, 64);
            }
        }

        // Assert
        Assert.Equal(0, bytesWritten); // Should not write any bytes when first vector is stop marker
        _output.WriteLine($"Stop marker test: {bytesWritten} bytes written (expected 0)");
    }

    [Fact]
    public void MatrixKeyGenerator_DirectionalWalk_GenerateAndRegenerate_Identical() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 32,
            Height = 32,
            Depth = 16,
            VectorMask = 0xABCDEF0123456789UL,
            KeyMask = 0x0123456789ABCDEFUL
        };

        var generator = new MatrixKeyGenerator(settings);
        string sourceText = BuildAsciiSourceText(32 * 32 * 16 * 8);

        // Act - Generate
        var genResult = generator.GenerateKey(sourceText, 42, 32);

        // Act - Regenerate using same startPosition
        var regenResult = generator.RegenerateKey(sourceText, 42, genResult.StartPosition, 32);

        // Assert
        Assert.Equal(genResult.KeyBytes, regenResult.KeyBytes);
        Assert.Equal(genResult.StartPosition, regenResult.StartPosition);

        _output.WriteLine($"Generate/Regenerate test passed");
        _output.WriteLine($"StartPosition: {genResult.StartPosition}");
        _output.WriteLine($"First vector: 0x{genResult.Vectors[0]:X2}");
        _output.WriteLine($"KeyBytes match: {genResult.KeyBytes.SequenceEqual(regenResult.KeyBytes)}");
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

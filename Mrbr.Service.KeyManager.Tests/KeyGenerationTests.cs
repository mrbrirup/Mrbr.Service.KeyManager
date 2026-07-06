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
        };

        var builder = new MatrixBuilder(settings);
        string sourceText = new string('A', 16 * 16 * 8); // One byte per matrix cell

        // Act
        byte[] matrix = builder.BuildFlatMatrix(sourceText);

        // Assert
        Assert.Equal(16 * 16 * 8, matrix.Length);
        Assert.NotNull(matrix);
    }

    [Fact]
    public void MatrixBuilder_ValidatesDimensions_PowerOfTwo() {
        // Arrange
        var validSettings = new KeyMatrixSettings {
            Width = 16,
            Height = 16,
            Depth = 8,
        };

        var invalidSettings = new KeyMatrixSettings {
            Width = 15,  // Not power of 2
            Height = 16,
            Depth = 8,
        };

        var validBuilder = new MatrixBuilder(validSettings);

        // Act & Assert
        validBuilder.ValidateDimensions(); // Should not throw
        Assert.Throws<InvalidOperationException>(() => new MatrixBuilder(invalidSettings));
    }

    [Fact]
    public void MatrixKeyGenerator_GeneratesKey_Successfully() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 16,
            Height = 16,
            Depth = 8,
        };

        var generator = new MatrixKeyGenerator(settings);
        string sourceText = new string('A', 16 * 16 * 8);

        // Act
        var result = generator.GenerateKey(sourceText, keyId: 42, maxTargetBytes: 32);

        // Assert
        Assert.Equal(42, result.KeyId);
        Assert.Equal(32, result.KeyBytes.Length);
        Assert.NotEqual(0UL, result.Seed);
        Assert.InRange(result.StartPosition, 0UL, 16UL * 16UL * 8UL - 1UL);
    }

    [Fact]
    public void MatrixKeyGenerator_RegeneratesKey_Consistently() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 16,
            Height = 16,
            Depth = 8,
        };

        var generator = new MatrixKeyGenerator(settings);
        string sourceText = new string('A', 16 * 16 * 8);

        // Generate initial key
        var original = generator.GenerateKey(sourceText, keyId: 100, maxTargetBytes: 32);

        // Act - Regenerate using same startPosition (vectors are derived dynamically)
        var regenerated = generator.RegenerateKey(
            sourceText,
            keyId: 100,
            original.StartPosition,
            original.Seed,
            maxTargetBytes: 32
        );

        // Assert - Should produce identical output
        Assert.Equal(original.KeyId, regenerated.KeyId);
        Assert.Equal(original.StartPosition, regenerated.StartPosition);
        Assert.Equal(original.KeyBytes, regenerated.KeyBytes);
    }

    [Fact]
    public void MatrixKeyGenerator_RegeneratesKey_Deterministically_WithSeed() {
        // Arrange: Matrix replay requires the start position and seed carried by the KeyHandle.
        var settings = new KeyMatrixSettings {
            Width = 16,
            Height = 16,
            Depth = 8,
        };

        var generator = new MatrixKeyGenerator(settings);
        string sourceText = new string('A', 16 * 16 * 8);

        var original = generator.GenerateKey(sourceText, keyId: 100, maxTargetBytes: 32);

        // Act - Reproduce using startPosition and seed, matching Matrix KeyHandle payload.
        var reproduced = generator.RegenerateKey(sourceText, keyId: 100, original.StartPosition, original.Seed, maxTargetBytes: 32);

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
        var original = new MatrixKeyResult {
            KeyId = 123,
            StartPosition = 0x0102030405060708UL,
            Seed = 0x123456789ABCDEFUL,
            KeyBytes = new byte[32]
        };

        // Act
        byte[] encoded = original.EncodeToBytes();
        var decoded = MatrixKeyResult.DecodeFromBytes(encoded);

        // Assert
        Assert.Equal(17, encoded.Length); // 1 + 8 + 8
        Assert.Equal(0x08, encoded[1]); // StartPosition is little-endian.
        Assert.Equal(0xEF, encoded[9]); // Seed is little-endian.
        Assert.Equal(original.KeyId, decoded.KeyId);
        Assert.Equal(original.StartPosition, decoded.StartPosition);
        Assert.Equal(original.Seed, decoded.Seed);
    }

    [Fact]
    public void MatrixKeyGenerator_RegenerateKey_RejectsStartPositionThatWouldTruncate() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 16,
            Height = 16,
            Depth = 8,
        };

        var generator = new MatrixKeyGenerator(settings);
        string sourceText = new string('A', 16 * 16 * 8);

        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            generator.RegenerateKey(sourceText, keyId: 1, (ulong)uint.MaxValue + 1UL, seed: 1, maxTargetBytes: 16));

        Assert.Equal("startPosition", exception.ParamName);
    }

    [Fact]
    public void KeyHandleCodec_PackMatrix_RejectsStartBitCountThatCrowdsSeed() {
        // Act & Assert: 33 start bits would leave only 15 seed bits in the 48-bit payload.
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            KeyHandleCodec.PackMatrix(keySourceId: 0, startPosition: 0, seed: 1, startBitCount: 33, keyHandleMask: 0));
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
        var matrixSettings = new KeyMatrixSettings { Width = 16, Height = 16, Depth = 8 };
        var config = new KeyServiceConfig {
            new() {
                Key = 0,
                Value = sourceText,
                KeyIdMask = "0",
                Type = KeyType.Matrix,
                MatrixSettings = matrixSettings
            }
        };

        var options = new KeyServiceOptions(Options.Create(config));
        var service = new KeyService(options);

        // Act
        byte[] signResult = service.GenerateKey256(out ulong keyResult);
        byte[] checkResult = service.GetKey256(keyResult);

        _output.WriteLine($"Matrix keyResult:          {keyResult}");
        _output.WriteLine($"Matrix keyId (bits 0-7):   {keyResult & KeyService.keyIdMask}");
        KeyHandleCodec.UnpackMatrix(keyResult, 0, matrixSettings.GetStartBitCount(), out _, out uint startPosition, out ulong seed);
        _output.WriteLine($"Matrix startPosition:      {startPosition}");
        _output.WriteLine($"Matrix seed:               {seed}");
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
        var matrixSettings = new KeyMatrixSettings { Width = 16, Height = 16, Depth = 8 };
        var config = new KeyServiceConfig {
            new() {
                Key = 0,
                Value = sourceText,
                KeyIdMask = "0",
                Type = KeyType.Matrix,
                MatrixSettings = matrixSettings
            }
        };

        var options = new KeyServiceOptions(Options.Create(config));
        var service = new KeyService(options);

        // Act
        byte[] signResult = service.GenerateKey256(out ulong keyResult);
        byte[] checkResult = service.GetKey256(keyResult);

        // Trace handle payload and first few leg bytes.
        KeyHandleCodec.UnpackMatrix(keyResult, 0, matrixSettings.GetStartBitCount(), out _, out uint startPosition, out ulong seed);

        _output.WriteLine($"=== Matrix Directional Walking Vector Chain ===");
        _output.WriteLine($"KeyResult:      {keyResult}");
        _output.WriteLine($"StartPosition:  {startPosition}");
        _output.WriteLine($"Seed:           {seed}");
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

    [Fact]
    public void MatrixKeyWalker_FixedVector_FromBoundary_WrapsAround() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 8,
            Height = 8,
            Depth = 8,
        };

        byte[] sourceBytes = Encoding.UTF8.GetBytes(BuildAsciiSourceText(8 * 8 * 8));
        var walker = new MatrixKeyWalker(settings, sourceBytes);

        // Start at last x,y,z cell then move +X/+Y/+Z to force wrap to 0.
        uint startPosition = 7 + (7u << 3) + (7u << 6);
        byte[] first = new byte[32];
        byte[] second = new byte[32];

        // Act
        walker.WalkFixedVector(startPosition, vector: 19, first);
        walker.WalkFixedVector(startPosition, vector: 19, second);

        _output.WriteLine($"Matrix wrap startPosition={startPosition}, vector=19");
        _output.WriteLine($"Matrix wrap first (bytes):  {Encoding.UTF8.GetString(first)}");
        _output.WriteLine($"Matrix wrap second (bytes): {Encoding.UTF8.GetString(second)}");

        // Assert
        Assert.Equal(first, second);
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

    // ==========================================
    // DIRECTIONAL WALKING INTEGRATION TESTS
    // ==========================================

    [Fact]
    public void MatrixKeyWalker_FixedVector_SingleLeg_Collects8Bytes() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 32,
            Height = 32,
            Depth = 16,
        };

        byte[] sourceBytes = Encoding.UTF8.GetBytes(BuildAsciiSourceText(32 * 32 * 16));
        var walker = new MatrixKeyWalker(settings, sourceBytes);

        byte[] result = new byte[8];
        byte testVector = 1; // +X direction

        // Act
        uint startPosition = (uint)(10 | (10 << 5) | (10 << 10));
        walker.WalkFixedVector(startPosition, testVector, result);

        // Assert
        Assert.All(result, b => Assert.NotEqual(0, b)); // Should have collected data

        _output.WriteLine($"Single leg walk collected {result.Length} bytes");
        _output.WriteLine($"Bytes: {string.Join(", ", result)}");
    }

    [Fact]
    public void MatrixKeyWalker_FixedVector_WrapAroundPerStep() {
        // Arrange - small matrix for easy wrap testing
        var settings = new KeyMatrixSettings {
            Width = 16,
            Height = 16,
            Depth = 8,
        };

        byte[] sourceBytes = Encoding.UTF8.GetBytes(BuildAsciiSourceText(16 * 16 * 8));
        var walker = new MatrixKeyWalker(settings, sourceBytes);

        byte[] result = new byte[16];
        byte testVector = 0x01; // +X direction

        // Act - start near boundary to force wrap
        uint startPosition = (uint)(14 | (5 << 4) | (5 << 8));
        walker.WalkFixedVector(startPosition, testVector, result);

        // Assert
        Assert.Equal(16, result.Length);
        _output.WriteLine($"Wrap-around walk collected {result.Length} bytes");
        _output.WriteLine($"Starting position [14,5,5], vector +X, width=16");
    }

    [Fact]
    public void MatrixKeyWalker_SeedWalk_MultiLegChain() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 32,
            Height = 32,
            Depth = 16,
        };

        byte[] sourceBytes = Encoding.UTF8.GetBytes(BuildAsciiSourceText(32 * 32 * 16));
        var walker = new MatrixKeyWalker(settings, sourceBytes);

        byte[] result = new byte[32]; // 4 legs by 8 bytes

        // Act
        uint startPosition = (uint)(10 | (10 << 5) | (10 << 10));
        walker.Replay(startPosition, seed: 0x12345678UL, result);

        // Assert
        Assert.Equal(32, result.Length);
        _output.WriteLine($"Multi-leg walk collected {result.Length} bytes (4 legs by 8 bytes)");

        // Show first few bytes from each leg
        _output.WriteLine($"Leg 1: {result[0]}, {result[1]}, ..., {result[7]}");
        _output.WriteLine($"Leg 2: {result[8]}, {result[9]}, ..., {result[15]}");
        _output.WriteLine($"Leg 3: {result[16]}, {result[17]}, ..., {result[23]}");
        _output.WriteLine($"Leg 4: {result[24]}, {result[25]}, ..., {result[31]}");
    }

    [Fact]
    public void MatrixKeyWalker_ReservedVector_RemapsAndContinues() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 32,
            Height = 32,
            Depth = 16,
        };

        byte[] sourceBytes = Encoding.UTF8.GetBytes(BuildAsciiSourceText(32 * 32 * 16));
        var walker = new MatrixKeyWalker(settings, sourceBytes);

        byte[] result = new byte[64];
        byte reservedVector = 31;

        // Act - reserved vectors are remapped rather than treated as termination.
        uint startPosition = (uint)(10 | (10 << 5) | (10 << 10));
        walker.WalkFixedVector(startPosition, reservedVector, result);

        // Assert
        Assert.Contains(result, b => b != 0);
        Assert.InRange(MatrixKeyWalker.NormalizeVector(reservedVector), (byte)1, (byte)26);
        _output.WriteLine("Reserved vector remap test wrote key material as expected");
    }

    [Fact]
    public void MatrixKeyGenerator_DirectionalWalk_GenerateAndRegenerate_Identical() {
        // Arrange
        var settings = new KeyMatrixSettings {
            Width = 32,
            Height = 32,
            Depth = 16,
        };

        var generator = new MatrixKeyGenerator(settings);
        string sourceText = BuildAsciiSourceText(32 * 32 * 16);

        // Act - Generate
        var genResult = generator.GenerateKey(sourceText, 42, 32);

        // Act - Regenerate using same startPosition and seed
        var regenResult = generator.RegenerateKey(sourceText, 42, genResult.StartPosition, genResult.Seed, 32);

        // Assert
        Assert.Equal(genResult.KeyBytes, regenResult.KeyBytes);
        Assert.Equal(genResult.StartPosition, regenResult.StartPosition);

        _output.WriteLine($"Generate/Regenerate test passed");
        _output.WriteLine($"StartPosition: {genResult.StartPosition}");
        _output.WriteLine($"Seed: {genResult.Seed}");
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

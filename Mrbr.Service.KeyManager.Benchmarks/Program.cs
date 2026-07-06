using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Order;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Toolchains.InProcess;
using BenchmarkDotNet.Toolchains.InProcess.Emit;
using Microsoft.Extensions.Options;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.Services;
using System.Reflection;
using System.Security.Cryptography;

BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args, BenchmarkConfig.Instance);

internal static class BenchmarkConfig {
    public static readonly IConfig Instance = ManualConfig
        .Create(DefaultConfig.Instance)
        // BenchmarkDotNet 0.15.8 does not recognise the current .NET 11 preview moniker yet.
        .AddJob(Job.Default.WithToolchain(InProcessEmitToolchain.Instance))
        .AddValidator(InProcessValidator.DontFailOnError);
}

[MemoryDiagnoser]
[RankColumn]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class BlockKeyManagerBenchmarks {
    private KeyService _service = default!;
    private byte[] _staticKey = [];
    private byte[] _destination = [];
    private byte[] _replayDestination = [];
    private ulong _keyHandle;

    [Params(16, 24, 32, 64, 128, 256)]
    public int KeySize { get; set; }

    [Params(4 * 1024, 1024 * 1024)]
    public int SourceSize { get; set; }

    [GlobalSetup]
    public void Setup() {
        _service = BenchmarkKeyServiceFactory.CreateBlockService(SourceSize);
        _staticKey = BenchmarkKeyServiceFactory.BuildBytes(KeySize);
        _destination = new byte[KeySize];
        _replayDestination = new byte[KeySize];
        _service.GenerateKey(_destination, out _keyHandle);
    }

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("KeyMaterial")]
    public void StaticKeyCopy() {
        _staticKey.AsSpan().CopyTo(_destination);
    }

    [Benchmark]
    [BenchmarkCategory("KeyMaterial")]
    public void GenerateKeyManagerSpan() {
        _service.GenerateKey(_destination, out _);
    }

    [Benchmark]
    [BenchmarkCategory("KeyMaterial")]
    public void ReplayKeyManagerSpan() {
        _service.GetKey(_keyHandle, _replayDestination);
    }

    [Benchmark]
    [BenchmarkCategory("Allocation")]
    public byte[] GenerateKeyManagerArray() {
        return _service.GenerateKey(KeySize, out _);
    }

    [Benchmark]
    [BenchmarkCategory("Allocation")]
    public byte[] ReplayKeyManagerArray() {
        return _service.GetKeyBytes(_keyHandle);
    }
}

[MemoryDiagnoser]
[RankColumn]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class BlockCryptoComparisonBenchmarks {
    private KeyService _service = default!;
    private byte[] _staticKey = [];
    private byte[] _staticWorkingKey = [];
    private byte[] _managerKey = [];
    private byte[] _plainText = [];
    private byte[] _cipherText = [];
    private byte[] _decryptedText = [];
    private byte[] _tag = [];
    private byte[] _nonce = [];
    private byte[] _hash = [];
    private AesGcm _cachedStaticAesGcm = default!;
    private ulong _keyHandle;

    [Params(16, 24, 32)]
    public int KeySize { get; set; }

    [Params(128, 4 * 1024)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void Setup() {
        _service = BenchmarkKeyServiceFactory.CreateBlockService(1024 * 1024);
        _managerKey = new byte[KeySize];
        _plainText = BenchmarkKeyServiceFactory.BuildBytes(PayloadSize);
        _cipherText = new byte[PayloadSize];
        _decryptedText = new byte[PayloadSize];
        _tag = new byte[16];
        _nonce = new byte[12];
        _hash = new byte[32];

        _service.GenerateKey(_managerKey, out _keyHandle);
        _staticKey = _managerKey.ToArray();
        _staticWorkingKey = new byte[KeySize];
        RandomNumberGenerator.Fill(_nonce);

        _cachedStaticAesGcm = new AesGcm(_staticKey, _tag.Length);
        _cachedStaticAesGcm.Encrypt(_nonce, _plainText, _cipherText, _tag);
    }

    [GlobalCleanup]
    public void Cleanup() {
        _cachedStaticAesGcm.Dispose();
    }

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("HMAC")]
    public void StaticKeyHmacSha256() {
        HMACSHA256.HashData(_staticKey, _plainText, _hash);
    }

    [Benchmark]
    [BenchmarkCategory("HMAC")]
    public void StaticKeyCopyHmacSha256() {
        _staticKey.AsSpan().CopyTo(_staticWorkingKey);
        HMACSHA256.HashData(_staticWorkingKey, _plainText, _hash);
    }

    [Benchmark]
    [BenchmarkCategory("HMAC")]
    public void KeyManagerReplayHmacSha256() {
        _service.GetKey(_keyHandle, _managerKey);
        HMACSHA256.HashData(_managerKey, _plainText, _hash);
    }

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("AES-GCM Encrypt")]
    public void StaticKeyAesGcmEncrypt() {
        using var aes = new AesGcm(_staticKey, _tag.Length);
        aes.Encrypt(_nonce, _plainText, _cipherText, _tag);
    }

    [Benchmark]
    [BenchmarkCategory("AES-GCM Encrypt")]
    public void StaticKeyCopyAesGcmEncrypt() {
        _staticKey.AsSpan().CopyTo(_staticWorkingKey);
        using var aes = new AesGcm(_staticWorkingKey, _tag.Length);
        aes.Encrypt(_nonce, _plainText, _cipherText, _tag);
    }

    [Benchmark]
    [BenchmarkCategory("AES-GCM Encrypt")]
    public void CachedStaticAesGcmEncrypt() {
        _cachedStaticAesGcm.Encrypt(_nonce, _plainText, _cipherText, _tag);
    }

    [Benchmark]
    [BenchmarkCategory("AES-GCM Encrypt")]
    public void KeyManagerReplayAesGcmEncrypt() {
        _service.GetKey(_keyHandle, _managerKey);
        using var aes = new AesGcm(_managerKey, _tag.Length);
        aes.Encrypt(_nonce, _plainText, _cipherText, _tag);
    }

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("AES-GCM Decrypt")]
    public void StaticKeyAesGcmDecrypt() {
        using var aes = new AesGcm(_staticKey, _tag.Length);
        aes.Decrypt(_nonce, _cipherText, _tag, _decryptedText);
    }

    [Benchmark]
    [BenchmarkCategory("AES-GCM Decrypt")]
    public void StaticKeyCopyAesGcmDecrypt() {
        _staticKey.AsSpan().CopyTo(_staticWorkingKey);
        using var aes = new AesGcm(_staticWorkingKey, _tag.Length);
        aes.Decrypt(_nonce, _cipherText, _tag, _decryptedText);
    }

    [Benchmark]
    [BenchmarkCategory("AES-GCM Decrypt")]
    public void CachedStaticAesGcmDecrypt() {
        _cachedStaticAesGcm.Decrypt(_nonce, _cipherText, _tag, _decryptedText);
    }

    [Benchmark]
    [BenchmarkCategory("AES-GCM Decrypt")]
    public void KeyManagerReplayAesGcmDecrypt() {
        _service.GetKey(_keyHandle, _managerKey);
        using var aes = new AesGcm(_managerKey, _tag.Length);
        aes.Decrypt(_nonce, _cipherText, _tag, _decryptedText);
    }
}

internal static class BenchmarkKeyServiceFactory {
    public static KeyService CreateBlockService(int sourceSize) {
        ResetKeyServiceOptionsState();
        string source = BuildAsciiSourceText(sourceSize);
        var config = new KeyServiceConfig {
            new() {
                KeySourceId = 0,
                KeyHandleMask = "0",
                Value = source,
                Type = KeyType.Block
            }
        };

        return new KeyService(new KeyServiceOptions(Options.Create(config)));
    }

    public static byte[] BuildBytes(int length) {
        byte[] result = GC.AllocateUninitializedArray<byte>(length);
        for (int i = 0; i < result.Length; i++) {
            result[i] = (byte)('!' + (i % 90));
        }

        return result;
    }

    private static string BuildAsciiSourceText(int length) {
        return string.Create(length, length, static (span, targetLength) => {
            for (int i = 0; i < targetLength; i++) {
                span[i] = (char)('!' + (i % 90));
            }
        });
    }

    private static void ResetKeyServiceOptionsState() {
        var type = typeof(KeyServiceOptions);
        const BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Static;

        type.GetField("_keys", flags)?.SetValue(null, null);
        type.GetField("_keyMemory", flags)?.SetValue(null, null);
        type.GetField("_keyBytes", flags)?.SetValue(null, null);
        type.GetField("_keySourceIds", flags)?.SetValue(null, null);
        type.GetField("_keyCount", flags)?.SetValue(null, 0);
        type.GetField("_initialised", flags)?.SetValue(null, false);
    }
}

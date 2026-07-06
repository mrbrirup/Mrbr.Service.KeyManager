using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.KeyHandles;
using Mrbr.Service.KeyManager.Matrices;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Mrbr.Service.KeyManager.Services;

/// <summary>
/// Provides replayable key material from configured key sources.
/// </summary>
public sealed class KeyService(KeyServiceOptions options) : IKeyService, IDisposable {
    public KeyServiceOptions KeyServiceOptions { get; init; } = options;

    public sealed record KeyServiceRecord(
        int KeySourceId,
        string Value,
        byte[] SourceBytes,
        ulong KeyHandleMask,
        KeyType Type,
        KeyBlockSettings? BlockSettings,
        KeyMatrixSettings? MatrixSettings,
        MatrixKeyWalker? MatrixWalker
    );

    public const int MaxKeyCount = 256;
    public const int keyIdMask = 255;
    public const int keySourceIdMask = 255;
    public const int keyPositionSize = KeyHandleCodec.BlockStartShift;
    public const int keyLengthSize = KeyHandleCodec.BlockLengthShift - KeyHandleCodec.BlockStartShift;
    public const int keyPositionAndLength = KeyHandleCodec.BlockLengthShift;
    public const int minMaskLength = 64;
    public const int randomMaskLength = 32;
    public const int MaxMaskLength = minMaskLength + randomMaskLength * 2;
    public const int MaxBlockKeyLength = ushort.MaxValue;

    public const int KeySize128 = 16;
    public const int KeySize192 = 24;
    public const int KeySize256 = 32;

    private static KeyServiceRecord?[] Keys => KeyServiceOptions.Keys;
    private static int KeyCount => KeyServiceOptions.KeyCount;
    private static int[] KeySourceIds => KeyServiceOptions.KeySourceIds;

    /// <summary>
    /// Hot-path Block/Matrix key generation. Writes directly to the caller-provided destination.
    /// </summary>
    public void GenerateKey(Span<byte> destination, out ulong keyHandle) => GenerateKeyBytes(destination, out keyHandle);

    /// <summary>
    /// Hot-path replay. Writes the same key material represented by <paramref name="keyHandle"/>.
    /// </summary>
    public void GetKey(ulong keyHandle, Span<byte> destination) => GetKeyBytes(keyHandle, destination);

    public byte[] GenerateKey(int length, out ulong keyHandle) => GenerateKeyBytes(length, out keyHandle);

    public ReadOnlyMemory<char> GenerateKey(out ulong keyHandle) {
        var record = GetRandomKeyServiceRecord();
        if (record.Type == KeyType.Matrix) {
            Span<byte> ignoredKey = stackalloc byte[KeySize128];
            GenerateMatrixKey(record, ignoredKey, out keyHandle);
            return ReadOnlyMemory<char>.Empty;
        }

        int length = GetLegacyBlockLength(record);
        uint start = GetRandomStart(record.Value.Length);
        keyHandle = KeyHandleCodec.PackBlock((byte)record.KeySourceId, start, (ushort)length, record.KeyHandleMask);
        return GetBlockKeyMaterial(record.Value.AsMemory(), start, (uint)length);
    }

    public byte[] GenerateKey128(out ulong keyHandle, KeyDerivationOptions options = default) => GenerateKeyBytes(KeySize128, out keyHandle, options);

    public byte[] GenerateKey192(out ulong keyHandle, KeyDerivationOptions options = default) => GenerateKeyBytes(KeySize192, out keyHandle, options);

    public byte[] GenerateKey256(out ulong keyHandle, KeyDerivationOptions options = default) => GenerateKeyBytes(KeySize256, out keyHandle, options);

    public void GenerateKeyBytes(Span<byte> destination, out ulong keyHandle, KeyDerivationOptions options = default) {
        ValidateRequestedLength(destination.Length);

        var record = GetRandomKeyServiceRecord();
        if (record.Type == KeyType.Block) {
            GenerateBlockKey(record, destination, out keyHandle);
            return;
        }

        GenerateMatrixKey(record, destination, out keyHandle);
    }

    public byte[] GenerateKeyBytes(int keySizeInBytes, out ulong keyHandle, KeyDerivationOptions options = default) {
        ValidateRequestedLength(keySizeInBytes);
        byte[] key = GC.AllocateUninitializedArray<byte>(keySizeInBytes);
        GenerateKeyBytes(key, out keyHandle, options);
        return key;
    }

    public void GenerateKey128(Span<byte> destination, out ulong keyHandle, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize128);
        GenerateKeyBytes(destination, out keyHandle, options);
    }

    public void GenerateKey192(Span<byte> destination, out ulong keyHandle, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize192);
        GenerateKeyBytes(destination, out keyHandle, options);
    }

    public void GenerateKey256(Span<byte> destination, out ulong keyHandle, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize256);
        GenerateKeyBytes(destination, out keyHandle, options);
    }

    public Task<(ReadOnlyMemory<char> Key, ulong Id)> GenerateKeyAsync() {
        var key = GenerateKey(out var keyHandle);
        return Task.FromResult((key, keyHandle));
    }

    public ReadOnlyMemory<char> GetKey(ulong keyHandle) {
        var keySourceId = KeyHandleCodec.GetKeySourceId(keyHandle);
        var record = GetKeyServiceRecord(keySourceId);
        if (record.Type == KeyType.Matrix) {
            return ReadOnlyMemory<char>.Empty;
        }

        DecodeBlockHandle(keyHandle, record, out var start, out var length);
        return GetBlockKeyMaterial(record.Value.AsMemory(), start, length);
    }

    public byte[] GetKeyBytes(ulong keyHandle) {
        var keySourceId = KeyHandleCodec.GetKeySourceId(keyHandle);
        var record = GetKeyServiceRecord(keySourceId);
        if (record.Type == KeyType.Matrix) {
            throw new ArgumentException("Matrix key handles do not encode output length. Use an overload that supplies the destination length.", nameof(keyHandle));
        }

        DecodeBlockHandle(keyHandle, record, out _, out var length);
        byte[] key = GC.AllocateUninitializedArray<byte>(length);
        GetKeyBytes(keyHandle, key);
        return key;
    }

    public byte[] GetKey128(ulong keyHandle, KeyDerivationOptions options = default) => GetKeyBytes(keyHandle, KeySize128, options);

    public byte[] GetKey192(ulong keyHandle, KeyDerivationOptions options = default) => GetKeyBytes(keyHandle, KeySize192, options);

    public byte[] GetKey256(ulong keyHandle, KeyDerivationOptions options = default) => GetKeyBytes(keyHandle, KeySize256, options);

    public void GetKeyBytes(ulong keyHandle, Span<byte> destination, KeyDerivationOptions options = default) {
        ValidateRequestedLength(destination.Length);

        var keySourceId = KeyHandleCodec.GetKeySourceId(keyHandle);
        var record = GetKeyServiceRecord(keySourceId);
        if (record.Type == KeyType.Block) {
            GetBlockKey(record, keyHandle, destination);
            return;
        }

        GetMatrixKey(record, keyHandle, destination);
    }

    public byte[] GetKeyBytes(ulong keyHandle, ulong keySizeInBytes, KeyDerivationOptions options = default) {
        if (keySizeInBytes > int.MaxValue) {
            throw new ArgumentOutOfRangeException(nameof(keySizeInBytes), "Key size is too large.");
        }

        byte[] key = GC.AllocateUninitializedArray<byte>((int)keySizeInBytes);
        GetKeyBytes(keyHandle, key, options);
        return key;
    }

    public void GetKey128(ulong keyHandle, Span<byte> destination, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize128);
        GetKeyBytes(keyHandle, destination, options);
    }

    public void GetKey192(ulong keyHandle, Span<byte> destination, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize192);
        GetKeyBytes(keyHandle, destination, options);
    }

    public void GetKey256(ulong keyHandle, Span<byte> destination, KeyDerivationOptions options = default) {
        ValidateNamedKeySize(destination.Length, KeySize256);
        GetKeyBytes(keyHandle, destination, options);
    }

    public Task<ReadOnlyMemory<char>> GetKeyAsync(ulong keyHandle) => Task.FromResult(GetKey(keyHandle));

    public bool ContainsKey(ulong keyId) => ContainsKeySource(keyId);

    public bool ContainsKeySource(ulong keySourceId) => keySourceId < MaxKeyCount && Keys[(int)keySourceId] != null;

    public bool DeleteKey(ulong keyId) => DeleteKeySource(keyId);

    public bool DeleteKeySource(ulong keySourceId) => KeyServiceOptions.DeleteKey(keySourceId);

    public bool DeleteAllKeys() => KeyServiceOptions.DeleteAllKeys();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ulong GetRandomKeyId() => GetRandomKeySourceId();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ulong GetRandomKeySourceId() {
        if (KeyCount <= 0) {
            throw new InvalidOperationException("No key sources are configured.");
        }

        return (ulong)KeySourceIds[RandomNumberGenerator.GetInt32(KeyCount)];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static KeyServiceRecord GetRandomKeyServiceRecord() => GetKeyServiceRecord(GetRandomKeySourceIdStatic());

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong GetRandomKeySourceIdStatic() {
        if (KeyCount <= 0) {
            throw new InvalidOperationException("No key sources are configured.");
        }

        return (ulong)KeySourceIds[RandomNumberGenerator.GetInt32(KeyCount)];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static KeyServiceRecord GetKeyServiceRecord(ulong keySourceId) {
        if (keySourceId < MaxKeyCount) {
            var record = Keys[(int)keySourceId];
            if (record != null) {
                return record;
            }
        }

        throw new KeyNotFoundException($"No key source exists for id '{keySourceId}'.");
    }

    private static void GenerateBlockKey(KeyServiceRecord record, Span<byte> destination, out ulong keyHandle) {
        var source = record.SourceBytes.AsSpan();
        if (source.IsEmpty) {
            throw new InvalidOperationException($"Key source '{record.KeySourceId}' has no source bytes.");
        }

        uint start = GetRandomStart(source.Length);
        CopyWrapped(source, (int)start, destination);
        keyHandle = KeyHandleCodec.PackBlock((byte)record.KeySourceId, start, (ushort)destination.Length, record.KeyHandleMask);
    }

    private static void GetBlockKey(KeyServiceRecord record, ulong keyHandle, Span<byte> destination) {
        DecodeBlockHandle(keyHandle, record, out var start, out var length);
        if (destination.Length != length) {
            throw new ArgumentException($"Destination length must match key handle length {length}.", nameof(destination));
        }

        CopyWrapped(record.SourceBytes.AsSpan(), (int)start, destination);
    }

    private static void DecodeBlockHandle(ulong keyHandle, KeyServiceRecord record, out uint start, out ushort length) {
        if (KeyHandleCodec.GetFormat(keyHandle, record.KeyHandleMask) != KeyHandleCodec.BlockFormat) {
            throw new ArgumentException("Key handle does not contain a Block payload.", nameof(keyHandle));
        }

        KeyHandleCodec.UnpackBlock(keyHandle, record.KeyHandleMask, out var decodedKeySourceId, out start, out length);
        if (decodedKeySourceId != record.KeySourceId) {
            throw new InvalidOperationException($"KeyHandleMask for key source '{record.KeySourceId}' modifies KeySourceId bits and is invalid.");
        }

        if (length == 0) {
            throw new ArgumentOutOfRangeException(nameof(keyHandle), "Decoded key length cannot be zero.");
        }

        if (start >= record.SourceBytes.Length) {
            throw new ArgumentOutOfRangeException(nameof(keyHandle), "Decoded start position is outside configured key source bounds.");
        }
    }

    private static void GenerateMatrixKey(KeyServiceRecord record, Span<byte> destination, out ulong keyHandle) {
        var walker = record.MatrixWalker ?? throw new InvalidOperationException($"Key source '{record.KeySourceId}' is not configured as a Matrix source.");
        walker.Generate(destination, out uint startPosition, out ulong seed);
        keyHandle = KeyHandleCodec.PackMatrix((byte)record.KeySourceId, startPosition, seed, walker.StartBitCount, record.KeyHandleMask);
    }

    private static void GetMatrixKey(KeyServiceRecord record, ulong keyHandle, Span<byte> destination) {
        var walker = record.MatrixWalker ?? throw new InvalidOperationException($"Key source '{record.KeySourceId}' is not configured as a Matrix source.");
        if (KeyHandleCodec.GetFormat(keyHandle, record.KeyHandleMask) != KeyHandleCodec.MatrixFormat) {
            throw new ArgumentException("Key handle does not contain a Matrix payload.", nameof(keyHandle));
        }

        KeyHandleCodec.UnpackMatrix(keyHandle, record.KeyHandleMask, walker.StartBitCount, out var decodedKeySourceId, out var startPosition, out var seed);
        if (decodedKeySourceId != record.KeySourceId) {
            throw new InvalidOperationException($"KeyHandleMask for key source '{record.KeySourceId}' modifies KeySourceId bits and is invalid.");
        }

        walker.Replay(startPosition, seed, destination);
    }

    private static void CopyWrapped(ReadOnlySpan<byte> source, int start, Span<byte> destination) {
        int firstSegmentLength = Math.Min(source.Length - start, destination.Length);
        source.Slice(start, firstSegmentLength).CopyTo(destination);

        int remaining = destination.Length - firstSegmentLength;
        if (remaining == 0) {
            return;
        }

        int written = firstSegmentLength;
        while (remaining > 0) {
            int copyLength = Math.Min(source.Length, remaining);
            source.Slice(0, copyLength).CopyTo(destination.Slice(written, copyLength));
            written += copyLength;
            remaining -= copyLength;
        }
    }

    private static ReadOnlyMemory<char> GetBlockKeyMaterial(ReadOnlyMemory<char> source, uint keyPosition, uint keyLength) {
        var sourceSpan = source.Span;
        var sourceLength = sourceSpan.Length;
        int iKeyPosition = (int)(keyPosition % (uint)sourceLength);
        int iKeyLength = (int)keyLength;

        if (iKeyPosition + iKeyLength <= sourceLength) {
            return source.Slice(iKeyPosition, iKeyLength);
        }

        int firstSegmentLength = sourceLength - iKeyPosition;
        int secondSegmentLength = iKeyLength - firstSegmentLength;
        char[] wrapped = GC.AllocateUninitializedArray<char>(iKeyLength);
        sourceSpan.Slice(iKeyPosition, firstSegmentLength).CopyTo(wrapped.AsSpan(0, firstSegmentLength));

        int written = firstSegmentLength;
        while (secondSegmentLength > 0) {
            int copyLength = Math.Min(sourceLength, secondSegmentLength);
            sourceSpan.Slice(0, copyLength).CopyTo(wrapped.AsSpan(written, copyLength));
            written += copyLength;
            secondSegmentLength -= copyLength;
        }

        return wrapped;
    }

    private static int GetLegacyBlockLength(KeyServiceRecord record) {
        int minLength = record.BlockSettings?.MinLength ?? minMaskLength;
        int maxLength = record.BlockSettings?.MaxLength ?? MaxMaskLength;
        if (maxLength < minLength) {
            maxLength = minLength;
        }

        maxLength = Math.Min(maxLength, MaxBlockKeyLength);
        return RandomNumberGenerator.GetInt32(minLength, maxLength + 1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint GetRandomStart(int sourceLength) => (uint)RandomNumberGenerator.GetInt32(sourceLength);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ValidateRequestedLength(int keySizeInBytes) {
        if (keySizeInBytes <= 0 || keySizeInBytes > MaxBlockKeyLength) {
            throw new ArgumentOutOfRangeException(nameof(keySizeInBytes), $"Key size must be between 1 and {MaxBlockKeyLength} bytes.");
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ValidateNamedKeySize(int actualSize, int expectedSize) {
        if (actualSize != expectedSize) {
            throw new ArgumentException($"Destination must be {expectedSize} bytes.", nameof(actualSize));
        }
    }

    public void Dispose() {
        GC.SuppressFinalize(this);
    }
}

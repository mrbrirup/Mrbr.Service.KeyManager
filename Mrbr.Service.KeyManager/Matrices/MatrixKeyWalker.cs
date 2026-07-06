using Mrbr.Service.KeyManager.Configuration;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Mrbr.Service.KeyManager.Matrices;

/// <summary>
/// High-throughput Matrix key walker. The matrix is a flat one-byte-per-cell source buffer.
/// </summary>
public sealed unsafe class MatrixKeyWalker {
    private const ulong SplitMixIncrement = 0x9E3779B97F4A7C15UL;

    private readonly byte[] _matrix;
    private readonly int _matrixLength;
    private readonly int _widthMask;
    private readonly int _heightMask;
    private readonly int _depthMask;
    private readonly int _widthBits;
    private readonly int _heightBits;
    private readonly int _zShift;
    private readonly int _startBitCount;
    private readonly int _seedBitCount;
    private readonly ulong _seedMask;

    public MatrixKeyWalker(KeyMatrixSettings settings, byte[] sourceBytes) {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(sourceBytes);

        settings.Validate(sourceBytes.Length);

        _matrix = sourceBytes;
        _matrixLength = settings.GetMatrixLength();
        _widthMask = settings.Width - 1;
        _heightMask = settings.Height - 1;
        _depthMask = settings.Depth - 1;
        _widthBits = settings.GetWidthBitCount();
        _heightBits = settings.GetHeightBitCount();
        _zShift = _widthBits + _heightBits;
        _startBitCount = settings.GetStartBitCount();
        _seedBitCount = KeyMatrixSettings.HandlePayloadBits - _startBitCount;
        _seedMask = CreateMask(_seedBitCount);
    }

    public int MatrixLength => _matrixLength;

    public int StartBitCount => _startBitCount;

    public int SeedBitCount => _seedBitCount;

    public ulong SeedMask => _seedMask;

    public void Generate(Span<byte> destination, out uint startPosition, out ulong seed) {
        startPosition = (uint)RandomNumberGenerator.GetInt32(_matrixLength);
        seed = CreateSeed();
        Walk(startPosition, seed, destination);
    }

    public void Replay(uint startPosition, ulong seed, Span<byte> destination) {
        if (startPosition >= _matrixLength) {
            throw new ArgumentOutOfRangeException(nameof(startPosition), "Matrix start position is outside configured source bounds.");
        }

        Walk(startPosition, seed & _seedMask, destination);
    }

    public void WalkFixedVector(uint startPosition, byte vector, Span<byte> destination) {
        if (startPosition >= _matrixLength) {
            throw new ArgumentOutOfRangeException(nameof(startPosition), "Matrix start position is outside configured source bounds.");
        }

        if (destination.IsEmpty) {
            return;
        }

        int x = (int)startPosition & _widthMask;
        int y = ((int)startPosition >> _widthBits) & _heightMask;
        int z = ((int)startPosition >> _zShift) & _depthMask;
        int written = 0;

        DecodeVector(vector, out int dx, out int dy, out int dz);

        fixed (byte* pMatrix = _matrix)
        fixed (byte* pDestination = destination) {
            while (destination.Length - written >= KeyMatrixSettings.LegMagnitude) {
                WalkFullLeg8(
                    pMatrix,
                    pDestination,
                    ref written,
                    ref x,
                    ref y,
                    ref z,
                    dx,
                    dy,
                    dz,
                    _widthMask,
                    _heightMask,
                    _depthMask,
                    _widthBits,
                    _zShift);
            }

            int remaining = destination.Length - written;
            if (remaining > 0) {
                WalkPartialLeg(
                    pMatrix,
                    pDestination,
                    ref written,
                    ref x,
                    ref y,
                    ref z,
                    dx,
                    dy,
                    dz,
                    _widthMask,
                    _heightMask,
                    _depthMask,
                    _widthBits,
                    _zShift,
                    remaining);
            }
        }
    }

    public static byte NormalizeVector(byte vector) {
        if (vector is >= 1 and <= 26) {
            return vector;
        }

        return (byte)((vector % 26) + 1);
    }

    public static void DecodeVector(byte vector, out int dx, out int dy, out int dz) {
        switch (NormalizeVector(vector)) {
            case 1:
                dx = 1; dy = 0; dz = 0;
                return;
            case 2:
                dx = -1; dy = 0; dz = 0;
                return;
            case 3:
                dx = 0; dy = 1; dz = 0;
                return;
            case 4:
                dx = 0; dy = -1; dz = 0;
                return;
            case 5:
                dx = 0; dy = 0; dz = 1;
                return;
            case 6:
                dx = 0; dy = 0; dz = -1;
                return;
            case 7:
                dx = 1; dy = 1; dz = 0;
                return;
            case 8:
                dx = -1; dy = 1; dz = 0;
                return;
            case 9:
                dx = 1; dy = -1; dz = 0;
                return;
            case 10:
                dx = -1; dy = -1; dz = 0;
                return;
            case 11:
                dx = 1; dy = 0; dz = 1;
                return;
            case 12:
                dx = -1; dy = 0; dz = 1;
                return;
            case 13:
                dx = 1; dy = 0; dz = -1;
                return;
            case 14:
                dx = -1; dy = 0; dz = -1;
                return;
            case 15:
                dx = 0; dy = 1; dz = 1;
                return;
            case 16:
                dx = 0; dy = -1; dz = 1;
                return;
            case 17:
                dx = 0; dy = 1; dz = -1;
                return;
            case 18:
                dx = 0; dy = -1; dz = -1;
                return;
            case 19:
                dx = 1; dy = 1; dz = 1;
                return;
            case 20:
                dx = -1; dy = 1; dz = 1;
                return;
            case 21:
                dx = 1; dy = -1; dz = 1;
                return;
            case 22:
                dx = -1; dy = -1; dz = 1;
                return;
            case 23:
                dx = 1; dy = 1; dz = -1;
                return;
            case 24:
                dx = -1; dy = 1; dz = -1;
                return;
            case 25:
                dx = 1; dy = -1; dz = -1;
                return;
            default:
                dx = -1; dy = -1; dz = -1;
                return;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static byte NextVector(ref ulong state) => (byte)((NextRandom(ref state) % 26) + 1);

    private void Walk(uint startPosition, ulong seed, Span<byte> destination) {
        if (destination.IsEmpty) {
            return;
        }

        int x = (int)startPosition & _widthMask;
        int y = ((int)startPosition >> _widthBits) & _heightMask;
        int z = ((int)startPosition >> _zShift) & _depthMask;
        int written = 0;
        ulong state = seed == 0 ? SplitMixIncrement : seed;

        int widthMask = _widthMask;
        int heightMask = _heightMask;
        int depthMask = _depthMask;
        int widthBits = _widthBits;
        int zShift = _zShift;

        fixed (byte* pMatrix = _matrix)
        fixed (byte* pDestination = destination) {
            while (destination.Length - written >= KeyMatrixSettings.LegMagnitude) {
                DecodeVector(NextVector(ref state), out int dx, out int dy, out int dz);
                WalkFullLeg8(
                    pMatrix,
                    pDestination,
                    ref written,
                    ref x,
                    ref y,
                    ref z,
                    dx,
                    dy,
                    dz,
                    widthMask,
                    heightMask,
                    depthMask,
                    widthBits,
                    zShift);
            }

            int remaining = destination.Length - written;
            if (remaining > 0) {
                DecodeVector(NextVector(ref state), out int dx, out int dy, out int dz);
                WalkPartialLeg(
                    pMatrix,
                    pDestination,
                    ref written,
                    ref x,
                    ref y,
                    ref z,
                    dx,
                    dy,
                    dz,
                    widthMask,
                    heightMask,
                    depthMask,
                    widthBits,
                    zShift,
                    remaining);
            }
        }
    }

    private ulong CreateSeed() {
        Span<byte> seedBytes = stackalloc byte[sizeof(ulong)];
        ulong seed;
        do {
            RandomNumberGenerator.Fill(seedBytes);
            seed = BinaryPrimitives.ReadUInt64LittleEndian(seedBytes) & _seedMask;
        }
        while (seed == 0);

        return seed;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong NextRandom(ref ulong state) {
        state += SplitMixIncrement;
        ulong value = state;
        value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9UL;
        value = (value ^ (value >> 27)) * 0x94D049BB133111EBUL;
        return value ^ (value >> 31);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong CreateMask(int bits) => (1UL << bits) - 1UL;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void WalkFullLeg8(
        byte* pMatrix,
        byte* pDestination,
        ref int written,
        ref int x,
        ref int y,
        ref int z,
        int dx,
        int dy,
        int dz,
        int widthMask,
        int heightMask,
        int depthMask,
        int widthBits,
        int zShift) {
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void WalkPartialLeg(
        byte* pMatrix,
        byte* pDestination,
        ref int written,
        ref int x,
        ref int y,
        ref int z,
        int dx,
        int dy,
        int dz,
        int widthMask,
        int heightMask,
        int depthMask,
        int widthBits,
        int zShift,
        int remaining) {
        if (remaining-- == 0) return;
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
        if (remaining-- == 0) return;
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
        if (remaining-- == 0) return;
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
        if (remaining-- == 0) return;
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
        if (remaining-- == 0) return;
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
        if (remaining-- == 0) return;
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
        if (remaining-- == 0) return;
        x = (x + dx) & widthMask; y = (y + dy) & heightMask; z = (z + dz) & depthMask;
        pDestination[written++] = pMatrix[x | (y << widthBits) | (z << zShift)];
    }
}

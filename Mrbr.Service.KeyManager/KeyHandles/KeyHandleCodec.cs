using System.Runtime.CompilerServices;

namespace Mrbr.Service.KeyManager.KeyHandles;

/// <summary>
/// Packs and unpacks replayable key handles.
/// </summary>
public static class KeyHandleCodec {
    public const ulong KeySourceIdMask = 0xFFUL;
    public const ulong PayloadMask = 0xFFFFFFFFFFFFFF00UL;

    public const int KeySourceIdShift = 0;
    public const int FormatShift = 8;
    public const int BlockStartShift = 16;
    public const int BlockLengthShift = 48;
    public const int MatrixStartShift = 16;

    public const byte BlockFormat = 1;
    public const byte MatrixFormat = 2;

    private const int MatrixPayloadBits = 48;
    private const int MatrixMinimumSeedBits = 16;
    private const ulong FormatMask = 0xFFUL;
    private const ulong BlockStartMask = 0xFFFFFFFFUL;
    private const ulong BlockLengthMask = 0xFFFFUL;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte GetKeySourceId(ulong keyHandle) => (byte)(keyHandle & KeySourceIdMask);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong NormalizeMask(ulong keyHandleMask) => keyHandleMask & PayloadMask;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong PackBlock(byte keySourceId, uint start, ushort length, ulong keyHandleMask) {
        ulong raw = keySourceId |
            ((ulong)BlockFormat << FormatShift) |
            ((ulong)start << BlockStartShift) |
            ((ulong)length << BlockLengthShift);

        return raw ^ NormalizeMask(keyHandleMask);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void UnpackBlock(ulong keyHandle, ulong keyHandleMask, out byte keySourceId, out uint start, out ushort length) {
        ulong raw = keyHandle ^ NormalizeMask(keyHandleMask);
        keySourceId = (byte)(raw & KeySourceIdMask);
        start = (uint)((raw >> BlockStartShift) & BlockStartMask);
        length = (ushort)((raw >> BlockLengthShift) & BlockLengthMask);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong PackMatrix(byte keySourceId, uint startPosition, ulong seed, int startBitCount, ulong keyHandleMask) {
        ValidateMatrixStartBitCount(startBitCount);

        int seedBitCount = MatrixPayloadBits - startBitCount;
        ulong raw = keySourceId |
            ((ulong)MatrixFormat << FormatShift) |
            (((ulong)startPosition & CreateMask(startBitCount)) << MatrixStartShift) |
            ((seed & CreateMask(seedBitCount)) << (MatrixStartShift + startBitCount));

        return raw ^ NormalizeMask(keyHandleMask);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void UnpackMatrix(
        ulong keyHandle,
        ulong keyHandleMask,
        int startBitCount,
        out byte keySourceId,
        out uint startPosition,
        out ulong seed) {
        ValidateMatrixStartBitCount(startBitCount);

        ulong raw = keyHandle ^ NormalizeMask(keyHandleMask);
        int seedBitCount = MatrixPayloadBits - startBitCount;
        keySourceId = (byte)(raw & KeySourceIdMask);
        startPosition = (uint)((raw >> MatrixStartShift) & CreateMask(startBitCount));
        seed = (raw >> (MatrixStartShift + startBitCount)) & CreateMask(seedBitCount);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte GetFormat(ulong keyHandle, ulong keyHandleMask) =>
        (byte)(((keyHandle ^ NormalizeMask(keyHandleMask)) >> FormatShift) & FormatMask);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong CreateMask(int bitCount) => (1UL << bitCount) - 1UL;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ValidateMatrixStartBitCount(int startBitCount) {
        if (startBitCount <= 0 || startBitCount > MatrixPayloadBits - MatrixMinimumSeedBits) {
            throw new ArgumentOutOfRangeException(nameof(startBitCount), $"Matrix start bit count must leave at least {MatrixMinimumSeedBits} seed bits in the key handle.");
        }
    }
}

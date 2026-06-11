using System.Runtime.CompilerServices;

namespace Mrbr.Service.KeyManager.Compression;


public static partial class BitPacker {

    private const ulong Block_KeyLength = Bin_8;
    private const ulong Block_KeyMask = Bin_8_Max;

    private const ulong Block_PositionPosition = Block_KeyLength;
    private const ulong Block_PositionLength = Bin_20;
    private const ulong Block_PositionMask = Bin_20_Max;

    private const ulong Block_LengthPosition = Block_PositionPosition * Block_PositionLength;
    private const ulong Block_LengthMask = Bin_8_Max;
    //   0-255:8 0-1048575:20  0-255:8
    //   [keyId] [keyPosition] [keyLength]

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong BlockKeyPack(uint key, uint start, uint length) =>
        key + (start * Block_PositionPosition) + (length * Block_LengthPosition);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void BlockKeyUnpack(ulong packed, out uint key, out uint start, out uint length) {
        key = (uint)(packed & Block_KeyMask);
        start = (uint)((packed / Block_PositionPosition) & Block_PositionMask);
        length = (uint)((packed / Block_LengthPosition) & Block_LengthMask);
    }
}
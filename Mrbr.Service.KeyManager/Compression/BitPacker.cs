using System.Runtime.CompilerServices;

namespace Mrbr.Service.KeyManager.Compression;


public static partial class BitPacker {

    /// <summary>
    /// Bit width of the key segment in a packed block key (8 bits).
    /// </summary>
    private const ulong Block_KeyLength = Bin_8;

    /// <summary>
    /// Mask used to extract the key segment from a packed block key.
    /// </summary>
    private const ulong Block_KeyMask = Bin_8_Max;

    /// <summary>
    /// Positional multiplier for the start segment (immediately after the key segment).
    /// </summary>
    private const ulong Block_PositionPosition = Block_KeyLength;

    /// <summary>
    /// Bit width of the start segment in a packed block key (20 bits).
    /// </summary>
    private const ulong Block_PositionLength = Bin_20;

    /// <summary>
    /// Mask used to extract the start segment from a packed block key.
    /// </summary>
    private const ulong Block_PositionMask = Bin_20_Max;

    /// <summary>
    /// Positional multiplier for the length segment (after key and start segments).
    /// </summary>
    private const ulong Block_LengthPosition = Block_PositionPosition * Block_PositionLength;

    /// <summary>
    /// Mask used to extract the length segment from a packed block key.
    /// </summary>
    private const ulong Block_LengthMask = Bin_8_Max;

    /// <summary>
    /// Packs block key components into a single <see cref="ulong"/>.
    /// </summary>
    /// <param name="key">Key identifier (0-255).</param>
    /// <param name="start">Start position within the key space (0-1,048,575).</param>
    /// <param name="length">Block length (0-255).</param>
    /// <returns>
    /// A packed value using the format: [key:8][start:20][length:8].
    /// </returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong BlockKeyPack(uint key, uint start, uint length) =>
        key + (start * Block_PositionPosition) + (length * Block_LengthPosition);

    /// <summary>
    /// Unpacks a packed block key into its component values.
    /// </summary>
    /// <param name="packed">The packed value in the format [key:8][start:20][length:8].</param>
    /// <param name="key">Receives the key identifier (0-255).</param>
    /// <param name="start">Receives the start position (0-1,048,575).</param>
    /// <param name="length">Receives the block length (0-255).</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void BlockKeyUnpack(ulong packed, out uint key, out uint start, out uint length) {
        key = (uint)(packed & Block_KeyMask);
        start = (uint)((packed / Block_PositionPosition) & Block_PositionMask);
        length = (uint)((packed / Block_LengthPosition) & Block_LengthMask);
    }
}
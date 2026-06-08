
using Microsoft.Extensions.Options;
using Mrbr.Service.KeyManager.Configuration;
using System.Runtime.CompilerServices;
namespace Mrbr.Service.KeyManager.Matrices;

////public class KeyMatrixSettings {
////    public const string SectionName = "KeyMatrixSettings";

////    [Range(8, 2048, ErrorMessage = "Width must be between 8 and 2048.")]
////    public int Width { get; set; }

////    [Range(8, 2048, ErrorMessage = "Height must be between 8 and 2048.")]
////    public int Height { get; set; }

////    [Range(8, 2048, ErrorMessage = "Depth must be between 8 and 2048.")]
////    public int Depth { get; set; }
////}
////public class KeyMatrixSettings {
////    public int Width { get; set; }
////    public int Height { get; set; }
////    public int Depth { get; set; }
////    public ulong VectorMask { get; set; }
////    public ulong KeyMask { get; set; }
////}

////// Injected wrapper to hold the dictionary of all loaded matrices
////public class CryptoSettingsRegistry {
////    // Maps KeyIndex -> Matrix Settings
////    public Dictionary<int, KeyMatrixSettings> Matrices { get; set; } = new();
////}




public unsafe class OptimizedKeyWalker {
    // Bitwise masks and strides precalculated once at startup from IOptions
    private readonly int _widthMask;
    private readonly int _heightMask;
    private readonly int _depthMask;
    private readonly int _strideY;
    private readonly int _strideZ;
    private readonly ulong _vectorMask;
    private readonly ulong _keyMask;

    public OptimizedKeyWalker(IOptions<KeyMatrixSettings> options) {
        KeyMatrixSettings settings = options.Value;

        // Configuration limits are strictly validated as powers of 2 at boot
        _widthMask = settings.Width - 1;
        _heightMask = settings.Height - 1;
        _depthMask = settings.Depth - 1;

        // Stride calculations optimized for an 8-byte cell layout
        _strideY = settings.Width * 8;
        _strideZ = settings.Width * settings.Height * 8;

        _vectorMask = settings.VectorMask;
        _keyMask = settings.KeyMask;
    }
    const ulong Mask1FU64 = 0x1FUL;
    /// <summary>
    /// Compresses sixteen 5-bit vector steps into a 10-byte block.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Pack5BitVectors(ReadOnlySpan<byte> unpacked16Bytes, Span<byte> packed10Bytes) {
        fixed (byte* pIn = unpacked16Bytes)
        fixed (byte* pPacked = packed10Bytes) {
            ulong highRegister =
                ((pIn[0] & Mask1FU64)) |
                ((ulong)(pIn[1] & Mask1FU64) << 5) |
                ((ulong)(pIn[2] & Mask1FU64) << 10) |
                ((ulong)(pIn[3] & Mask1FU64) << 15) |
                ((ulong)(pIn[4] & Mask1FU64) << 20) |
                ((ulong)(pIn[5] & Mask1FU64) << 25) |
                ((ulong)(pIn[6] & Mask1FU64) << 30) |
                ((ulong)(pIn[7] & Mask1FU64) << 35) |
                ((ulong)(pIn[8] & Mask1FU64) << 40) |
                ((ulong)(pIn[9] & Mask1FU64) << 45) |
                ((ulong)(pIn[10] & Mask1FU64) << 50) |
                ((ulong)(pIn[11] & Mask1FU64) << 55);

            *(ulong*)pPacked = highRegister;

            uint lowRegister =
                ((uint)(pIn[12] & Mask1FU64) << 12) |
                ((uint)(pIn[13] & Mask1FU64) << 17) |
                ((uint)(pIn[14] & Mask1FU64) << 22) |
                ((uint)(pIn[15] & Mask1FU64) << 27);

            *(uint*)(pPacked + 6) |= lowRegister;
        }
    }

    /// <summary>
    /// Expands a 10-byte packed stream into an aligned 16-byte buffer on the stack.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Unpack5BitVectors(ReadOnlySpan<byte> packed10Bytes, byte* pOut) {
        fixed (byte* pPacked = packed10Bytes) {
            ulong highRegister = *(ulong*)pPacked;

            pOut[0] = (byte)(highRegister & 0x1F);
            pOut[1] = (byte)((highRegister >> 5) & 0x1F);
            pOut[2] = (byte)((highRegister >> 10) & 0x1F);
            pOut[3] = (byte)((highRegister >> 15) & 0x1F);
            pOut[4] = (byte)((highRegister >> 20) & 0x1F);
            pOut[5] = (byte)((highRegister >> 25) & 0x1F);
            pOut[6] = (byte)((highRegister >> 30) & 0x1F);
            pOut[7] = (byte)((highRegister >> 35) & 0x1F);
            pOut[8] = (byte)((highRegister >> 40) & 0x1F);
            pOut[9] = (byte)((highRegister >> 45) & 0x1F);
            pOut[10] = (byte)((highRegister >> 50) & 0x1F);
            pOut[11] = (byte)((highRegister >> 55) & 0x1F);

            uint lowRegister = *(uint*)(pPacked + 6);

            pOut[12] = (byte)((lowRegister >> 12) & 0x1F);
            pOut[13] = (byte)((lowRegister >> 17) & 0x1F);
            pOut[14] = (byte)((lowRegister >> 22) & 0x1F);
            pOut[15] = (byte)((lowRegister >> 27) & 0x1F);
        }
    }

    /// <summary>
    /// Performs the unrolled 3D matrix walk. Supports early exit via target length or the 31 stop marker.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int WalkMatrixUnsafe(
        byte[] flatMatrix,
        int sx, int sy, int sz,
        byte* pVectors,
        byte* pResult,
        int maxTargetBytes) // e.g., 32 for AES256, 64 for AES512
    {
        int cx = sx; int cy = sy; int cz = sz;
        int bytesWritten = 0;

        int wMask = _widthMask; int hMask = _heightMask; int dMask = _depthMask;
        int sY = _strideY; int sZ = _strideZ;

        fixed (byte* pMatrix = flatMatrix) {
            int* pX = &cx; int* pY = &cy; int* pZ = &cz;
            byte v;

            // ==========================================
            // STEP 1
            // ==========================================
            v = pVectors[0];
            if (bytesWritten >= maxTargetBytes || v == 31) goto EndOfWalk;
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 2
            // ==========================================
            v = pVectors[1];
            if (bytesWritten >= maxTargetBytes || v == 31) goto EndOfWalk;
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 3
            // ==========================================
            v = pVectors[2];
            if (bytesWritten >= maxTargetBytes || v == 31) goto EndOfWalk;
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 4
            // ==========================================
            v = pVectors[3];
            if (bytesWritten >= maxTargetBytes || v == 31) goto EndOfWalk;
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 5
            // ==========================================
            v = pVectors[4];
            if (v == 31 || bytesWritten >= maxTargetBytes) goto EndOfWalk; // Short cutting as more likely to hit stop marker based on key size requirement in step 4
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 6
            // ==========================================
            v = pVectors[5];
            if (bytesWritten >= maxTargetBytes || v == 31) goto EndOfWalk;
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 7
            // ==========================================
            v = pVectors[6];
            if (bytesWritten >= maxTargetBytes || v == 31) goto EndOfWalk;
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 8
            // ==========================================
            v = pVectors[7];
            if (bytesWritten >= maxTargetBytes || v == 31) goto EndOfWalk;
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 9
            // ==========================================
            v = pVectors[8];
            if (v == 31 || bytesWritten >= maxTargetBytes) goto EndOfWalk; // Short cutting as more likely to hit stop marker based on key size requirement in step 8
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 10
            // ==========================================
            v = pVectors[9];
            if (bytesWritten >= maxTargetBytes || v == 31) goto EndOfWalk;
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 11
            // ==========================================
            v = pVectors[10];
            if (bytesWritten >= maxTargetBytes || v == 31) goto EndOfWalk;
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 12
            // ==========================================
            v = pVectors[11];
            if (bytesWritten >= maxTargetBytes || v == 31) goto EndOfWalk;
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 13
            // ==========================================
            v = pVectors[12];
            if (bytesWritten >= maxTargetBytes || v == 31) goto EndOfWalk;
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 14
            // ==========================================
            v = pVectors[13];
            if (bytesWritten >= maxTargetBytes || v == 31) goto EndOfWalk;
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 15
            // ==========================================
            v = pVectors[14];
            if (bytesWritten >= maxTargetBytes || v == 31) goto EndOfWalk;
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }
            // ==========================================
            // STEP 16
            // ==========================================
            v = pVectors[15];
            if (bytesWritten >= maxTargetBytes || v == 31) goto EndOfWalk;
            if (v != 0) {
                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
                bytesWritten += 8;
            }



        EndOfWalk:;
        }
        return bytesWritten;
    }

    /// <summary>
    /// Applies or removes the obfuscation masks, skipping the first 32 bytes (KeyIndex).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ApplyCryptoMasks(Span<byte> targetVectors, Span<byte> targetKey) {
        fixed (byte* pVec = targetVectors)
        fixed (byte* pKey = targetKey) {
            // Symmetrical XOR masks applied directly across byte blocks
            *(ulong*)pVec ^= _vectorMask;

            ulong* pKeyData64 = (ulong*)(pKey + 32); // Skip 32-byte KeyIndex completely
            int remainingUlongCount = (targetKey.Length - 32) >> 3; // Fast divide-by-8 shift

            for (int i = 0; i < remainingUlongCount; i++) {
                pKeyData64[i] ^= _keyMask;
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void EvaluateVectorStep(byte vectorId, int* cx, int* cy, int* cz, int wMask, int hMask, int dMask) {
        // --- 1. EDGE MOVES (Highest Statistical Probability: 12/26 or ~46%) ---
        if (vectorId == 7) { *cx = (*cx + 1) & wMask; *cy = (*cy + 1) & hMask; }
        else if (vectorId == 8) { *cx = (*cx - 1) & wMask; *cy = (*cy + 1) & hMask; }
        else if (vectorId == 9) { *cx = (*cx + 1) & wMask; *cy = (*cy - 1) & hMask; }
        else if (vectorId == 10) { *cx = (*cx - 1) & wMask; *cy = (*cy - 1) & hMask; }
        else if (vectorId == 11) { *cx = (*cx + 1) & wMask; *cz = (*cz + 1) & dMask; }
        else if (vectorId == 12) { *cx = (*cx - 1) & wMask; *cz = (*cz + 1) & dMask; }
        else if (vectorId == 13) { *cx = (*cx + 1) & wMask; *cz = (*cz - 1) & dMask; }
        else if (vectorId == 14) { *cx = (*cx - 1) & wMask; *cz = (*cz - 1) & dMask; }
        else if (vectorId == 15) { *cy = (*cy + 1) & hMask; *cz = (*cz + 1) & dMask; }
        else if (vectorId == 16) { *cy = (*cy - 1) & hMask; *cz = (*cz + 1) & dMask; }
        else if (vectorId == 17) { *cy = (*cy + 1) & hMask; *cz = (*cz - 1) & dMask; }
        else if (vectorId == 18) { *cy = (*cy - 1) & hMask; *cz = (*cz - 1) & dMask; }

        // --- 2. CORNER MOVES (Medium Statistical Probability: 8/26 or ~31%) ---
        else if (vectorId == 19) { *cx = (*cx + 1) & wMask; *cy = (*cy + 1) & hMask; *cz = (*cz + 1) & dMask; }
        else if (vectorId == 20) { *cx = (*cx - 1) & wMask; *cy = (*cy + 1) & hMask; *cz = (*cz + 1) & dMask; }
        else if (vectorId == 21) { *cx = (*cx + 1) & wMask; *cy = (*cy - 1) & hMask; *cz = (*cz + 1) & dMask; }
        else if (vectorId == 22) { *cx = (*cx - 1) & wMask; *cy = (*cy - 1) & hMask; *cz = (*cz + 1) & dMask; }
        else if (vectorId == 23) { *cx = (*cx + 1) & wMask; *cy = (*cy + 1) & hMask; *cz = (*cz - 1) & dMask; }
        else if (vectorId == 24) { *cx = (*cx - 1) & wMask; *cy = (*cy + 1) & hMask; *cz = (*cz - 1) & dMask; }
        else if (vectorId == 25) { *cx = (*cx + 1) & wMask; *cy = (*cy - 1) & hMask; *cz = (*cz - 1) & dMask; }
        else if (vectorId == 26) { *cx = (*cx - 1) & wMask; *cy = (*cy - 1) & hMask; *cz = (*cz - 1) & dMask; }

        // --- 3. FACE MOVES (Lowest Statistical Probability: 6/26 or ~23%) ---
        else if (vectorId == 1) *cx = (*cx + 1) & wMask;
        else if (vectorId == 2) *cx = (*cx - 1) & wMask;
        else if (vectorId == 3) *cy = (*cy + 1) & hMask;
        else if (vectorId == 4) *cy = (*cy - 1) & hMask;
        else if (vectorId == 5) *cz = (*cz + 1) & dMask;
        else if (vectorId == 6) *cz = (*cz - 1) & dMask;
    }
}

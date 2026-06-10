
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
    const ulong Mask3FU64 = 0x3FUL;

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
    /// Compresses sixteen 6-bit directional vectors into a 12-byte block.
    /// Each vector encodes [2bit-X | 2bit-Y | 2bit-Z] direction components.
    /// 16 vectors × 6 bits = 96 bits = 12 bytes.
    /// Uses byte-level bit packing for correctness over micro-optimization.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Pack6BitVectors(ReadOnlySpan<byte> unpacked16Bytes, Span<byte> packed12Bytes) {
        // Pack 16 6-bit values into 12 bytes (96 bits)
        // Layout: AAAAAA|BBBBBB|CC|CCCCDD|DDDDEE|EEEEEE| ... (4 vectors per 3 bytes)

        // Group 1: vectors 0-3 into bytes 0-2
        packed12Bytes[0] = (byte)((unpacked16Bytes[0] & 0x3F) | ((unpacked16Bytes[1] & 0x03) << 6));
        packed12Bytes[1] = (byte)(((unpacked16Bytes[1] & 0x3C) >> 2) | ((unpacked16Bytes[2] & 0x0F) << 4));
        packed12Bytes[2] = (byte)(((unpacked16Bytes[2] & 0x30) >> 4) | ((unpacked16Bytes[3] & 0x3F) << 2));

        // Group 2: vectors 4-7 into bytes 3-5
        packed12Bytes[3] = (byte)((unpacked16Bytes[4] & 0x3F) | ((unpacked16Bytes[5] & 0x03) << 6));
        packed12Bytes[4] = (byte)(((unpacked16Bytes[5] & 0x3C) >> 2) | ((unpacked16Bytes[6] & 0x0F) << 4));
        packed12Bytes[5] = (byte)(((unpacked16Bytes[6] & 0x30) >> 4) | ((unpacked16Bytes[7] & 0x3F) << 2));

        // Group 3: vectors 8-11 into bytes 6-8
        packed12Bytes[6] = (byte)((unpacked16Bytes[8] & 0x3F) | ((unpacked16Bytes[9] & 0x03) << 6));
        packed12Bytes[7] = (byte)(((unpacked16Bytes[9] & 0x3C) >> 2) | ((unpacked16Bytes[10] & 0x0F) << 4));
        packed12Bytes[8] = (byte)(((unpacked16Bytes[10] & 0x30) >> 4) | ((unpacked16Bytes[11] & 0x3F) << 2));

        // Group 4: vectors 12-15 into bytes 9-11
        packed12Bytes[9] = (byte)((unpacked16Bytes[12] & 0x3F) | ((unpacked16Bytes[13] & 0x03) << 6));
        packed12Bytes[10] = (byte)(((unpacked16Bytes[13] & 0x3C) >> 2) | ((unpacked16Bytes[14] & 0x0F) << 4));
        packed12Bytes[11] = (byte)(((unpacked16Bytes[14] & 0x30) >> 4) | ((unpacked16Bytes[15] & 0x3F) << 2));
    }

    /// <summary>
    /// Expands a 12-byte packed stream into 16 6-bit directional vectors.
    /// Each vector is decoded as [2bit-X | 2bit-Y | 2bit-Z] components.
    /// Uses byte-level bit unpacking for correctness.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Unpack6BitVectors(ReadOnlySpan<byte> packed12Bytes, byte* pOut) {
        // Unpack 12 bytes (96 bits) into 16 6-bit values
        // Layout: AAAAAA|BBBBBB|CC|CCCCDD|DDDDEE|EEEEEE| ... (4 vectors per 3 bytes)

        // Group 1: bytes 0-2 into vectors 0-3
        pOut[0] = (byte)(packed12Bytes[0] & 0x3F);
        pOut[1] = (byte)(((packed12Bytes[0] >> 6) & 0x03) | ((packed12Bytes[1] & 0x0F) << 2));
        pOut[2] = (byte)(((packed12Bytes[1] >> 4) & 0x0F) | ((packed12Bytes[2] & 0x03) << 4));
        pOut[3] = (byte)((packed12Bytes[2] >> 2) & 0x3F);

        // Group 2: bytes 3-5 into vectors 4-7
        pOut[4] = (byte)(packed12Bytes[3] & 0x3F);
        pOut[5] = (byte)(((packed12Bytes[3] >> 6) & 0x03) | ((packed12Bytes[4] & 0x0F) << 2));
        pOut[6] = (byte)(((packed12Bytes[4] >> 4) & 0x0F) | ((packed12Bytes[5] & 0x03) << 4));
        pOut[7] = (byte)((packed12Bytes[5] >> 2) & 0x3F);

        // Group 3: bytes 6-8 into vectors 8-11
        pOut[8] = (byte)(packed12Bytes[6] & 0x3F);
        pOut[9] = (byte)(((packed12Bytes[6] >> 6) & 0x03) | ((packed12Bytes[7] & 0x0F) << 2));
        pOut[10] = (byte)(((packed12Bytes[7] >> 4) & 0x0F) | ((packed12Bytes[8] & 0x03) << 4));
        pOut[11] = (byte)((packed12Bytes[8] >> 2) & 0x3F);

        // Group 4: bytes 9-11 into vectors 12-15
        pOut[12] = (byte)(packed12Bytes[9] & 0x3F);
        pOut[13] = (byte)(((packed12Bytes[9] >> 6) & 0x03) | ((packed12Bytes[10] & 0x0F) << 2));
        pOut[14] = (byte)(((packed12Bytes[10] >> 4) & 0x0F) | ((packed12Bytes[11] & 0x03) << 4));
        pOut[15] = (byte)((packed12Bytes[11] >> 2) & 0x3F);
    }

    /// <summary>
    /// Decodes a 2-bit vector component into a movement delta.
    /// 00 (0) = no move (0), 01 (1) = plus (+1), 10 (2) = minus (-1), 11 (3) = reserved.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int DecodeVectorComponent(byte component) {
        // Fast branchless decode: 0→0, 1→+1, 2→-1, 3→0 (treat reserved as no-move)
        return component == 0 ? 0 : (component == 1 ? 1 : (component == 2 ? -1 : 0));
    }

    /// <summary>
    /// Derives the next 6-bit directional vector from a leg's collected 8 bytes.
    /// Uses fast XOR-fold hash to produce deterministic vector, avoiding 0x3F (stop marker).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte DeriveNextVectorInline(byte* pLegBytes) {
        // XOR-fold all 8 bytes into a single byte
        byte hash = (byte)(pLegBytes[0] ^ pLegBytes[1] ^ pLegBytes[2] ^ pLegBytes[3] ^
                           pLegBytes[4] ^ pLegBytes[5] ^ pLegBytes[6] ^ pLegBytes[7]);

        // Map to 6-bit space: ensure each 2-bit component is 00, 01, or 10 (not 11)
        // This avoids creating 0x3F (all 11s = stop marker) and creates valid directions
        byte x = (byte)((hash >> 6) & 0x3); // Top 2 bits
        byte y = (byte)((hash >> 4) & 0x3); // Middle 2 bits
        byte z = (byte)((hash >> 2) & 0x3); // Bottom 2 bits

        // Clamp 11 (3) to 10 (2) to avoid reserved value
        if (x == 3) x = 2;
        if (y == 3) y = 2;
        if (z == 3) z = 2;

        // Recombine into 6-bit vector: [x:2bit | y:2bit | z:2bit]
        return (byte)((x << 4) | (y << 2) | z);
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
    /// Performs directional 3D matrix walk where each vector specifies a direction to walk 8 steps.
    /// Each leg collects 1 byte per step (8 bytes total), and the next vector is derived from those bytes.
    /// Supports early exit via target length or 0x3F stop marker.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int WalkMatrixDirectional(
        byte[] flatMatrix,
        int sx, int sy, int sz,
        byte firstVector,
        byte* pResult,
        int maxTargetBytes)
    {
        int cx = sx; int cy = sy; int cz = sz;
        int bytesWritten = 0;

        int wMask = _widthMask; int hMask = _heightMask; int dMask = _depthMask;
        int sY = _strideY; int sZ = _strideZ;

        byte currentVector = firstVector;
        int maxLegs = (maxTargetBytes / 8) + 1; // Calculate needed legs plus one for stop marker

        fixed (byte* pMatrix = flatMatrix) {
            // Unrolled loop for up to 16 legs (supports up to 128-byte keys)
            // Each leg walks 8 steps in the direction specified by currentVector

            // ==========================================
            // LEG 1
            // ==========================================
            if (bytesWritten >= maxTargetBytes || currentVector == 0x3F) goto EndOfDirectionalWalk;
            {
                int dx = DecodeVectorComponent((byte)((currentVector >> 4) & 0x3));
                int dy = DecodeVectorComponent((byte)((currentVector >> 2) & 0x3));
                int dz = DecodeVectorComponent((byte)(currentVector & 0x3));

                // Walk 8 steps - each step moves the position and reads one byte from that cell
                for (int step = 0; step < 8 && bytesWritten < maxTargetBytes; step++) {
                    cx = (cx + dx) & wMask;
                    cy = (cy + dy) & hMask;
                    cz = (cz + dz) & dMask;
                    int cellOffset = (cx << 3) + (cy * sY) + (cz * sZ);
                    // Read the byte at this step index within the 8-byte cell
                    pResult[bytesWritten++] = pMatrix[cellOffset + step];
                }

                if (bytesWritten >= 8) {
                    currentVector = DeriveNextVectorInline(pResult + bytesWritten - 8);
                }
            }

            // ==========================================
            // LEG 2
            // ==========================================
            if (bytesWritten >= maxTargetBytes || currentVector == 0x3F) goto EndOfDirectionalWalk;
            {
                int dx = DecodeVectorComponent((byte)((currentVector >> 4) & 0x3));
                int dy = DecodeVectorComponent((byte)((currentVector >> 2) & 0x3));
                int dz = DecodeVectorComponent((byte)(currentVector & 0x3));

                for (int step = 0; step < 8 && bytesWritten < maxTargetBytes; step++) {
                    cx = (cx + dx) & wMask;
                    cy = (cy + dy) & hMask;
                    cz = (cz + dz) & dMask;
                    int cellOffset = (cx << 3) + (cy * sY) + (cz * sZ);
                    pResult[bytesWritten++] = pMatrix[cellOffset + step];
                }

                if (bytesWritten >= 16) {
                    currentVector = DeriveNextVectorInline(pResult + bytesWritten - 8);
                }
            }

            // ==========================================
            // LEG 3
            // ==========================================
            if (bytesWritten >= maxTargetBytes || currentVector == 0x3F) goto EndOfDirectionalWalk;
            {
                int dx = DecodeVectorComponent((byte)((currentVector >> 4) & 0x3));
                int dy = DecodeVectorComponent((byte)((currentVector >> 2) & 0x3));
                int dz = DecodeVectorComponent((byte)(currentVector & 0x3));

                for (int step = 0; step < 8 && bytesWritten < maxTargetBytes; step++) {
                    cx = (cx + dx) & wMask;
                    cy = (cy + dy) & hMask;
                    cz = (cz + dz) & dMask;
                    int cellOffset = (cx << 3) + (cy * sY) + (cz * sZ);
                    pResult[bytesWritten++] = pMatrix[cellOffset + step];
                }

                if (bytesWritten >= 24) {
                    currentVector = DeriveNextVectorInline(pResult + bytesWritten - 8);
                }
            }

            // ==========================================
            // LEG 4
            // ==========================================
            if (bytesWritten >= maxTargetBytes || currentVector == 0x3F) goto EndOfDirectionalWalk;
            {
                int dx = DecodeVectorComponent((byte)((currentVector >> 4) & 0x3));
                int dy = DecodeVectorComponent((byte)((currentVector >> 2) & 0x3));
                int dz = DecodeVectorComponent((byte)(currentVector & 0x3));

                for (int step = 0; step < 8 && bytesWritten < maxTargetBytes; step++) {
                    cx = (cx + dx) & wMask;
                    cy = (cy + dy) & hMask;
                    cz = (cz + dz) & dMask;
                    int cellOffset = (cx << 3) + (cy * sY) + (cz * sZ);
                    pResult[bytesWritten++] = pMatrix[cellOffset + step];
                }

                if (bytesWritten >= 32) {
                    currentVector = DeriveNextVectorInline(pResult + bytesWritten - 8);
                }
            }

            // ==========================================
            // LEG 5
            // ==========================================
            if (bytesWritten >= maxTargetBytes || currentVector == 0x3F) goto EndOfDirectionalWalk;
            {
                int dx = DecodeVectorComponent((byte)((currentVector >> 4) & 0x3));
                int dy = DecodeVectorComponent((byte)((currentVector >> 2) & 0x3));
                int dz = DecodeVectorComponent((byte)(currentVector & 0x3));

                for (int step = 0; step < 8 && bytesWritten < maxTargetBytes; step++) {
                    cx = (cx + dx) & wMask;
                    cy = (cy + dy) & hMask;
                    cz = (cz + dz) & dMask;
                    int cellOffset = (cx << 3) + (cy * sY) + (cz * sZ);
                    pResult[bytesWritten++] = pMatrix[cellOffset + step];
                }

                if (bytesWritten >= 40) {
                    currentVector = DeriveNextVectorInline(pResult + bytesWritten - 8);
                }
            }

            // ==========================================
            // LEG 6
            // ==========================================
            if (bytesWritten >= maxTargetBytes || currentVector == 0x3F) goto EndOfDirectionalWalk;
            {
                int dx = DecodeVectorComponent((byte)((currentVector >> 4) & 0x3));
                int dy = DecodeVectorComponent((byte)((currentVector >> 2) & 0x3));
                int dz = DecodeVectorComponent((byte)(currentVector & 0x3));

                for (int step = 0; step < 8 && bytesWritten < maxTargetBytes; step++) {
                    cx = (cx + dx) & wMask;
                    cy = (cy + dy) & hMask;
                    cz = (cz + dz) & dMask;
                    int cellOffset = (cx << 3) + (cy * sY) + (cz * sZ);
                    pResult[bytesWritten++] = pMatrix[cellOffset + step];
                }

                if (bytesWritten >= 48) {
                    currentVector = DeriveNextVectorInline(pResult + bytesWritten - 8);
                }
            }

            // ==========================================
            // LEG 7
            // ==========================================
            if (bytesWritten >= maxTargetBytes || currentVector == 0x3F) goto EndOfDirectionalWalk;
            {
                int dx = DecodeVectorComponent((byte)((currentVector >> 4) & 0x3));
                int dy = DecodeVectorComponent((byte)((currentVector >> 2) & 0x3));
                int dz = DecodeVectorComponent((byte)(currentVector & 0x3));

                for (int step = 0; step < 8 && bytesWritten < maxTargetBytes; step++) {
                    cx = (cx + dx) & wMask;
                    cy = (cy + dy) & hMask;
                    cz = (cz + dz) & dMask;
                    int cellOffset = (cx << 3) + (cy * sY) + (cz * sZ);
                    pResult[bytesWritten++] = pMatrix[cellOffset + step];
                }

                if (bytesWritten >= 56) {
                    currentVector = DeriveNextVectorInline(pResult + bytesWritten - 8);
                }
            }

            // ==========================================
            // LEG 8
            // ==========================================
            if (bytesWritten >= maxTargetBytes || currentVector == 0x3F) goto EndOfDirectionalWalk;
            {
                int dx = DecodeVectorComponent((byte)((currentVector >> 4) & 0x3));
                int dy = DecodeVectorComponent((byte)((currentVector >> 2) & 0x3));
                int dz = DecodeVectorComponent((byte)(currentVector & 0x3));

                for (int step = 0; step < 8 && bytesWritten < maxTargetBytes; step++) {
                    cx = (cx + dx) & wMask;
                    cy = (cy + dy) & hMask;
                    cz = (cz + dz) & dMask;
                    int cellOffset = (cx << 3) + (cy * sY) + (cz * sZ);
                    pResult[bytesWritten++] = pMatrix[cellOffset + step];
                }

                if (bytesWritten >= 64) {
                    currentVector = DeriveNextVectorInline(pResult + bytesWritten - 8);
                }
            }

            // ==========================================
            // Additional legs 9-16 for larger keys (up to 128 bytes)
            // ==========================================
            for (int leg = 9; leg <= 16 && bytesWritten < maxTargetBytes; leg++) {
                if (currentVector == 0x3F) break;

                int dx = DecodeVectorComponent((byte)((currentVector >> 4) & 0x3));
                int dy = DecodeVectorComponent((byte)((currentVector >> 2) & 0x3));
                int dz = DecodeVectorComponent((byte)(currentVector & 0x3));

                for (int step = 0; step < 8 && bytesWritten < maxTargetBytes; step++) {
                    cx = (cx + dx) & wMask;
                    cy = (cy + dy) & hMask;
                    cz = (cz + dz) & dMask;
                    int cellOffset = (cx << 3) + (cy * sY) + (cz * sZ);
                    pResult[bytesWritten++] = pMatrix[cellOffset + step];
                }

                if ((bytesWritten % 8) == 0 && bytesWritten >= 8) {
                    currentVector = DeriveNextVectorInline(pResult + bytesWritten - 8);
                }
            }

        EndOfDirectionalWalk:;
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

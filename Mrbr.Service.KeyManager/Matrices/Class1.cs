using System;
namespace Mrbr.Service.KeyManager.Matrices;

//public class Dummy1 {
//    // The 27 possible [dx, dy, dz] movements mapped to 5-bit indices (0 to 26)
//    private static readonly (int dx, int dy, int dz)[] Vectors = new (int, int, int)[] {
//    (0, 0, 0),   // 0: No movement
//    (1, 0, 0),   // 1: +X (East)
//    (-1, 0, 0),  // 2: -X (West)
//    (0, 1, 0),   // 3: +Y (North)
//    (0, -1, 0),  // 4: -Y (South)
//    (0, 0, 1),   // 5: +Z (Up)
//    (0, 0, -1),  // 6: -Z (Down)
//    // ... 12 Edge Moves (e.g., 1, 1, 0)
//    // ... 8 Corner Moves (e.g., 1, 1, 1)
//};
//    public byte[] GenerateKeyResult(
//        byte[,,][] matrix3D,       // Your 3D matrix holding the byte[8] arrays
//        int sx, int sy, int sz,    // The starting 3D coordinates
//        byte[] vectorPath)         // Array of up to 16 bytes, each holding a 5-bit vector index (0-26)
//    {
//        int width = matrix3D.GetLength(0);
//        int height = matrix3D.GetLength(1);
//        int depth = matrix3D.GetLength(2);

//        // 16 steps * 8 bytes = 128 bytes total key size
//        byte[] keyResult = new byte[16 * 8];
//        int resultOffset = 0;

//        int cx = sx;
//        int cy = sy;
//        int cz = sz;

//        for (int i = 0; i < vectorPath.Length && i < 16; i++) {
//            // 1. Get the direction from our 5-bit vector index
//            var (dx, dy, dz) = Vectors[vectorPath[i]];

//            // 2. Move and apply Modulo wrapper (handles negative numbers correctly in C#)
//            cx = (cx + dx) % width;
//            if (cx < 0) cx += width;

//            cy = (cy + dy) % height;
//            if (cy < 0) cy += height;

//            cz = (cz + dz) % depth;
//            if (cz < 0) cz += depth;

//            // 3. Retrieve the 8-byte array from the matrix
//            byte[] r = matrix3D[cx, cy, cz];

//            // 4. Copy the 8 bytes directly into the final keyResult array
//            Buffer.BlockCopy(r, 0, keyResult, resultOffset, 8);
//            resultOffset += 8;
//        }

//        return keyResult;
//    }

//    public static void GenerateKeyResultOptimized(
//        byte[] flatMatrix,          // Flattened 1D array of your 3D matrix
//        int widthMask,              // e.g., 63 for a width of 64
//        int heightMask,             // e.g., 63 for a height of 64
//        int depthMask,              // e.g., 63 for a depth of 64
//        int strideY,                // Precalculated: width * 8
//        int strideZ,                // Precalculated: width * height * 8
//        int sx, int sy, int sz,     // Starting positions
//        ReadOnlySpan<byte> vectors, // 16 bytes, each containing a 5-bit vector ID (0-26)
//        Span<byte> keyResult)       // Destination buffer (128 bytes), allocated on the stack
//    {
//        // Local copies of coordinates held in CPU registers
//        int cx = sx;
//        int cy = sy;
//        int cz = sz;

//        // STEP 1: Process first vector inline
//        // Inline evaluation of the vector ID eliminates loops and array lookups
//        switch (vectors[0]) {
//            case 0: break; // No movement
//            case 1: cx = (cx + 1) & widthMask; break; // +X
//            case 2: cx = (cx - 1) & widthMask; break; // -X
//            case 3: cy = (cy + 1) & heightMask; break; // +Y
//            case 4: cy = (cy - 1) & heightMask; break; // -Y
//            case 5: cz = (cz + 1) & depthMask; break; // +Z
//            case 6: cz = (cz - 1) & depthMask; break; // -Z
//            case 7: cx = (cx + 1) & widthMask; cy = (cy + 1) & heightMask; break; // +X, +Y
//            case 8: cx = (cx - 1) & widthMask; cy = (cy + 1) & heightMask; break; // -X, +Y
//                                                                                  // ... include all 26 cases here ...
//            case 26: cx = (cx - 1) & widthMask; cy = (cy - 1) & heightMask; cz = (cz - 1) & depthMask; break;
//        }

//        // Calculate memory offset directly in the flat 1D array
//        // Multiplying by 8 is optimized by the compiler to a bit-shift (<< 3)
//        int offset0 = (cx * 8) + (cy * strideY) + (cz * strideZ);

//        // Copy 8 bytes instantly using Spans (compiles down to optimized SIMD/CPU move instructions)
//        flatMatrix.AsSpan(offset0, 8).CopyTo(keyResult.Slice(0, 8));

//        // STEP 2: Process second vector inline
//        switch (vectors[1]) {
//            case 0: break;
//            case 1: cx = (cx + 1) & widthMask; break;
//            case 2: cx = (cx - 1) & widthMask; break;
//            case 3: cy = (cy + 1) & heightMask; break;
//            case 4: cy = (cy - 1) & heightMask; break;
//            case 5: cz = (cz + 1) & depthMask; break;
//            case 6: cz = (cz - 1) & depthMask; break;
//            case 7: cx = (cx + 1) & widthMask; cy = (cy + 1) & heightMask; break;
//            case 8: cx = (cx - 1) & widthMask; cy = (cy + 1) & heightMask; break;
//                // ... same 26 cases ...
//        }
//        int offset1 = (cx * 8) + (cy * strideY) + (cz * strideZ);
//        flatMatrix.AsSpan(offset1, 8).CopyTo(keyResult.Slice(8, 8));

//        // [ REPEAT THIS PATTERN UNROLLED FOR STEPS 2 TO 15 ]
//        // Each block increments the keyResult slice offset by 8 (Slice(16, 8), Slice(24, 8)... up to Slice(120, 8))
//    }
//}



//public unsafe partial class OptimizedKeyWalker {
//    // Stride constants and masks pre-calculated and injected via DI configuration
//    private readonly int _widthMask;
//    private readonly int _heightMask;
//    private readonly int _depthMask;
//    private readonly int _strideY;
//    private readonly int _strideZ;

//    public OptimizedKeyWalker(int width, int height, int depth) {
//        _widthMask = width - 1;
//        _heightMask = height - 1;
//        _depthMask = depth - 1;

//        // Multiplying by 8 because each matrix element contains 8 bytes
//        _strideY = width * 8;
//        _strideZ = width * height * 8;
//    }

//    [MethodImpl(MethodImplOptions.AggressiveInlining)]
//    public int WalkMatrixUnsafe(
//        byte[] flatMatrix,          // Fast 1D matrix
//        int sx, int sy, int sz,     // Starting positions
//        ReadOnlySpan<byte> vectors, // 16 bytes containing 5-bit vector IDs
//        Span<byte> keyResult)       // Pre-allocated destination buffer (min 128 bytes)
//    {
//        int cx = sx;
//        int cy = sy;
//        int cz = sz;
//        int bytesWritten = 0;

//        // Pin the arrays to get raw memory pointers (bypasses all bounds checks)
//        fixed (byte* pMatrix = flatMatrix)
//        fixed (byte* pResult = keyResult) {
//            byte v;

//            // ==========================================
//            // STEP 1
//            // ==========================================
//            v = vectors[0];
//            if (v != 0) // Skip calculation and skip data copying if zero vector
//            {
//                // Unrolled vector evaluation matching your 26-direction lookup table
//                if (v == 1) cx = (cx + 1) & _widthMask;
//                else if (v == 2) cx = (cx - 1) & _widthMask;
//                else if (v == 3) cy = (cy + 1) & _heightMask;
//                // ... handle all other non-zero vector cases inline ...

//                int offset = (cx << 3) + (cy * _strideY) + (cz * _strideZ);

//                // Extremely fast memory copy via CPU 64-bit register (8 bytes)
//                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
//                bytesWritten += 8;
//            }

//            // ==========================================
//            // STEP 2
//            // ==========================================
//            v = vectors[1];
//            if (v != 0) {
//                if (v == 1) cx = (cx + 1) & _widthMask;
//                else if (v == 2) cx = (cx - 1) & _widthMask;
//                else if (v == 3) cy = (cy + 1) & _heightMask;
//                // ... inline vector cases ...

//                int offset = (cx << 3) + (cy * _strideY) + (cz * _strideZ);
//                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
//                bytesWritten += 8;
//            }
//            // If the algorithm hits consecutive zeroes, bytesWritten stops increasing.

//            // [ REPEAT UNROLLED COPIES FOR STEPS 3 TO 16 USING THE SAME `v = vectors[i]` PATTERN ]

//        } // Array pinning ends here automatically

//        // Returns the final truncated size (e.g., if only 3 non-zero steps ran, returns 24)
//        return bytesWritten;
//    }
//    [MethodImpl(MethodImplOptions.AggressiveInlining)]
//    public void ProcessCryptoHotPath(ReadOnlySpan<byte> vectors, int sx, int sy, int sz) {
//        // 1. Instant allocation on the stack (128 bytes = 16 steps * 8 bytes)
//        Span<byte> resultBuffer = stackalloc byte[128];

//        // 2. Run your highly optimized unsafe matrix walker
//        int bytesWritten = _keyWalker.WalkMatrixUnsafe(_flatMatrix, sx, sy, sz, vectors, resultBuffer);

//        // 3. Slice it to get the exact truncated key size without copying memory
//        ReadOnlySpan<byte> truncatedKey = resultBuffer.Slice(0, bytesWritten);

//        // 4. Use the key inline for your hashing, encryption, or signing
//        ExecuteCryptographicOperation(truncatedKey);

//        // 5. OPTIONAL: If compliance demands zeroing, clear the stack memory in 1 CPU cycle
//        // (Only clears the exact bytes used, rather than a large pooled array)
//        resultBuffer.Slice(0, bytesWritten).Clear();
//    }
//    [MethodImpl(MethodImplOptions.AggressiveInlining)]
//    public unsafe void MaskVectorsAndKey(
//    Span<byte> actualVectors,   // The raw vector bytes used for the walk
//    Span<byte> generatedKey,    // The 128-byte (or shorter) key produced by the 3D walk
//    ulong vectorMask,
//    ulong keyMask) {
//        // --- 1. MASK THE VECTORS ---
//        // Pin the vector span to read it directly as a 64-bit integer
//        fixed (byte* pVec = actualVectors) {
//            // Interpret the first 8 bytes of your vector path as a single ulong
//            // XOR applies your mask instantly in 1 CPU cycle
//            *(ulong*)pVec ^= vectorMask;
//        }

//        // --- 2. MASK THE GENERATED KEY ---
//        // A 128-byte key is made of exactly sixteen 8-byte chunks (ulongs)
//        // We unroll the loop or loop quickly to XOR the entire key with your KeyMask
//        fixed (byte* pKey = generatedKey) {
//            ulong* pKey64 = (ulong*)pKey;
//            int ulongCount = generatedKey.Length / 8;

//            for (int i = 0; i < ulongCount; i++) {
//                pKey64[i] ^= keyMask;
//            }
//        }
//    }
//    [MethodImpl(MethodImplOptions.AggressiveInlining)]
//    public unsafe void UnmaskVectorsAndKey(
//    Span<byte> savedMaskedVectors,
//    Span<byte> savedMaskedKey,
//    ulong vectorMask,
//    ulong keyMask) {
//        // 1. Remove the KeyMask from the stored key
//        fixed (byte* pKey = savedMaskedKey) {
//            ulong* pKey64 = (ulong*)pKey;
//            int ulongCount = savedMaskedKey.Length / 8;

//            for (int i = 0; i < ulongCount; i++) {
//                pKey64[i] ^= keyMask;
//            }
//        }

//        // 2. Remove the VectorMask from the stored vectors
//        fixed (byte* pVec = savedMaskedVectors) {
//            *(ulong*)pVec ^= vectorMask;
//        }

//        // Now, your safe vectors and unmasked key can be passed back into 
//        // the matrix walker or used to decrypt your database ciphertext!
//    }
//    [MethodImpl(MethodImplOptions.AggressiveInlining)]
//    public unsafe void MaskVectorsAndKeyWithIndex(
//    Span<byte> actualVectors,   // The raw vector bytes used for the walk
//    Span<byte> generatedKey,    // The full buffer containing [32-byte KeyIndex][Matrix Key Data]
//    ulong vectorMask,
//    ulong keyMask) {
//        // 1. Mask the vectors instantly
//        fixed (byte* pVec = actualVectors) {
//            *(ulong*)pVec ^= vectorMask;
//        }

//        // 2. Mask the key, bypassing the first 32 bytes (KeyIndex)
//        fixed (byte* pKey = generatedKey) {
//            // Advance the pointer directly past the 32-byte KeyIndex
//            ulong* pKeyData64 = (ulong*)(pKey + 32);

//            // Calculate remaining 64-bit blocks to mask
//            // e.g., if total length is 128 bytes, 128 - 32 = 96 bytes remaining (12 blocks)
//            int remainingUlongCount = (generatedKey.Length - 32) / 8;

//            for (int i = 0; i < remainingUlongCount; i++) {
//                pKeyData64[i] ^= keyMask;
//            }
//        }
//    }
//    // Define these at the top of your class for human readability
//    private const int Vector0 = 0;
//    private const int Vector1 = 1;
//    private const int Vector2 = 2;
//    // ... up to Vector15 = 15;

//    [MethodImpl(MethodImplOptions.AggressiveInlining)]
//    public static unsafe void Unpack5BitVectors(ReadOnlySpan<byte> packed10Bytes, byte* pOut) {
//        fixed (byte* pPacked = packed10Bytes) {
//            ulong highRegister = *(ulong*)pPacked;

//            // Code reads beautifully, but executes as raw CPU pointer math
//            pOut[Vector0] = (byte)(highRegister & 0x1F);
//            pOut[Vector1] = (byte)((highRegister >> 5) & 0x1F);
//            pOut[Vector2] = (byte)((highRegister >> 10) & 0x1F);
//            // ...
//        }
//    }
//    [MethodImpl(MethodImplOptions.AggressiveInlining)]
//    public static unsafe void Pack5BitVectors(ReadOnlySpan<byte> unpacked16Bytes, Span<byte> packed10Bytes) {
//        // Pin both arrays to get direct, bounds-free CPU memory pointers
//        fixed (byte* pIn = unpacked16Bytes)
//        fixed (byte* pPacked = packed10Bytes) {
//            // 1. Pack the first 12 vectors (0 to 11) into a single 64-bit ulong register
//            // Each vector is masked with 0x1F to ensure it does not bleed into other positions
//            ulong highRegister =
//                ((ulong)(pIn[0] & 0x1F)) |
//                ((ulong)(pIn[1] & 0x1F) << 5) |
//                ((ulong)(pIn[2] & 0x1F) << 10) |
//                ((ulong)(pIn[3] & 0x1F) << 15) |
//                ((ulong)(pIn[4] & 0x1F) << 20) |
//                ((ulong)(pIn[5] & 0x1F) << 25) |
//                ((ulong)(pIn[6] & 0x1F) << 30) |
//                ((ulong)(pIn[7] & 0x1F) << 35) |
//                ((ulong)(pIn[8] & 0x1F) << 40) |
//                ((ulong)(pIn[9] & 0x1F) << 45) |
//                ((ulong)(pIn[10] & 0x1F) << 50) |
//                ((ulong)(pIn[11] & 0x1F) << 55);

//            // Instantly write the 64-bit block to the first 8 bytes of our destination pointer
//            *(ulong*)pPacked = highRegister;

//            // 2. Pack the final 4 vectors (12 to 15) into a 32-bit uint register
//            // Because we will write to an offset, we calculate the remaining shifts
//            // Vector 12 sits at bit 60 globally. Written at offset 6 (48 bits in), it needs a shift of 12 (60 - 48 = 12)
//            uint lowRegister =
//                ((uint)(pIn[12] & 0x1F) << 12) |
//                ((uint)(pIn[13] & 0x1F) << 17) |
//                ((uint)(pIn[14] & 0x1F) << 22) |
//                ((uint)(pIn[15] & 0x1F) << 27);

//            // To preserve the bits already written to bytes 6 and 7 by the highRegister,
//            // we use a bitwise OR directly against the memory address at offset 6
//            *(uint*)(pPacked + 6) |= lowRegister;
//        }
//    }
//    [MethodImpl(MethodImplOptions.AggressiveInlining)]
//    private static unsafe void EvaluateVectorStep(
//    byte vectorId,
//    int* cx, int* cy, int* cz,
//    int wMask, int hMask, int dMask) {
//        // --- FACE MOVES (1 Axis Changes) ---
//        if (vectorId == 1) *cx = (*cx + 1) & wMask; // +X (East)
//        else if (vectorId == 2) *cx = (*cx - 1) & wMask; // -X (West)
//        else if (vectorId == 3) *cy = (*cy + 1) & hMask; // +Y (North)
//        else if (vectorId == 4) *cy = (*cy - 1) & hMask; // -Y (South)
//        else if (vectorId == 5) *cz = (*cz + 1) & dMask; // +Z (Up)
//        else if (vectorId == 6) *cz = (*cz - 1) & dMask; // -Z (Down)

//        // --- EDGE MOVES (2 Axes Change) ---
//        else if (vectorId == 7) { *cx = (*cx + 1) & wMask; *cy = (*cy + 1) & hMask; } // +X, +Y
//        else if (vectorId == 8) { *cx = (*cx - 1) & wMask; *cy = (*cy + 1) & hMask; } // -X, +Y
//        else if (vectorId == 9) { *cx = (*cx + 1) & wMask; *cy = (*cy - 1) & hMask; } // +X, -Y
//        else if (vectorId == 10) { *cx = (*cx - 1) & wMask; *cy = (*cy - 1) & hMask; } // -X, -Y
//        else if (vectorId == 11) { *cx = (*cx + 1) & wMask; *cz = (*cz + 1) & dMask; } // +X, +Z
//        else if (vectorId == 12) { *cx = (*cx - 1) & wMask; *cz = (*cz + 1) & dMask; } // -X, +Z
//        else if (vectorId == 13) { *cx = (*cx + 1) & wMask; *cz = (*cz - 1) & dMask; } // +X, -Z
//        else if (vectorId == 14) { *cx = (*cx - 1) & wMask; *cz = (*cz - 1) & dMask; } // -X, -Z
//        else if (vectorId == 15) { *cy = (*cy + 1) & hMask; *cz = (*cz + 1) & dMask; } // +Y, +Z
//        else if (vectorId == 16) { *cy = (*cy - 1) & hMask; *cz = (*cz + 1) & dMask; } // -Y, +Z
//        else if (vectorId == 17) { *cy = (*cy + 1) & hMask; *cz = (*cz - 1) & dMask; } // +Y, -Z
//        else if (vectorId == 18) { *cy = (*cy - 1) & hMask; *cz = (*cz - 1) & dMask; } // -Y, -Z

//        // --- CORNER MOVES (3 Axes Change) ---
//        else if (vectorId == 19) { *cx = (*cx + 1) & wMask; *cy = (*cy + 1) & hMask; *cz = (*cz + 1) & dMask; } // +X, +Y, +Z
//        else if (vectorId == 20) { *cx = (*cx - 1) & wMask; *cy = (*cy + 1) & hMask; *cz = (*cz + 1) & dMask; } // -X, +Y, +Z
//        else if (vectorId == 21) { *cx = (*cx + 1) & wMask; *cy = (*cy - 1) & hMask; *cz = (*cz + 1) & dMask; } // +X, -Y, +Z
//        else if (vectorId == 22) { *cx = (*cx - 1) & wMask; *cy = (*cy - 1) & hMask; *cz = (*cz + 1) & dMask; } // -X, -Y, +Z
//        else if (vectorId == 23) { *cx = (*cx + 1) & wMask; *cy = (*cy + 1) & hMask; *cz = (*cz - 1) & dMask; } // +X, +Y, -Z
//        else if (vectorId == 24) { *cx = (*cx - 1) & wMask; *cy = (*cy + 1) & hMask; *cz = (*cz - 1) & dMask; } // -X, +Y, -Z
//        else if (vectorId == 25) { *cx = (*cx + 1) & wMask; *cy = (*cy - 1) & hMask; *cz = (*cz - 1) & dMask; } // +X, -Y, -Z
//        else if (vectorId == 26) { *cx = (*cx - 1) & wMask; *cy = (*cy - 1) & hMask; *cz = (*cz - 1) & dMask; } // -X, -Y, -Z
//    }

//    [MethodImpl(MethodImplOptions.AggressiveInlining)]
//    public void GenerateAndSecureNewToken(ReadOnlySpan<byte> rawGeneratedVectors, Span<byte> outStoredVectors) {
//        // 1. Allocate a 10-byte buffer directly on the thread stack
//        Span<byte> packedBuffer = stackalloc byte[];

//        // 2. Compress your 16 vectors down into 10 bytes
//        Pack5BitVectors(rawGeneratedVectors, packedBuffer);

//        // 3. Mask the packed vectors instantly via a 64-bit XOR
//        unsafe {
//            fixed (byte* pPacked = packedBuffer) {
//                *(ulong*)pPacked ^= _currentVectorMask;
//            }
//        }

//        // 4. Copy the safe, compressed, and obfuscated 10 bytes to your out buffer/database payload
//        packedBuffer.CopyTo(outStoredVectors);
//    }

//    public unsafe void ProcessIncomingDecryption(
//    Span<byte> incomingMaskedKey,
//    ReadOnlySpan<byte> cipherText) {
//        // 1. Read the KeyIndex directly from the unmasked first 4 bytes of the token
//        // (An int fits perfectly inside the first 32 bits of your 256-bit index space)
//        int keyIndex = BinaryPrimitives.ReadInt32LittleEndian(incomingMaskedKey.Slice(0, 4));

//        // 2. Fetch the correct configuration instantly from the DI Registry
//        if (!_registry.Matrices.TryGetValue(keyIndex, out var settings)) {
//            throw new CryptographicException("Unknown or revoked KeyIndex.");
//        }

//        // 3. Unmask the key data using the retrieved settings
//        fixed (byte* pKey = incomingMaskedKey) {
//            // Advance past the 32-byte KeyIndex block
//            ulong* pKeyData64 = (ulong*)(pKey + 32);
//            int remainingUlongCount = (incomingMaskedKey.Length - 32) / 8;

//            for (int i = 0; i < remainingUlongCount; i++) {
//                pKeyData64[i] ^= settings.KeyMask;
//            }
//        }
//        [MethodImpl(MethodImplOptions.AggressiveInlining)]
//        public static unsafe void Unpack5BitVectors(ReadOnlySpan<byte> packed10Bytes, Span<byte> unpacked16Bytes) {
//            // Pin the 10 bytes to read them directly using CPU registers
//            fixed (byte* pPacked = packed10Bytes)
//            fixed (byte* pOut = unpacked16Bytes) {
//                // 1. Load the first 8 bytes (64 bits) directly into a register
//                ulong highRegister = *(ulong*)pPacked;

//                // Extract the first 12 vectors (0 to 11) from the 64-bit register
//                // (12 vectors * 5 bits = 60 bits used out of 64)
//                pOut[0] = (byte)(highRegister & 0x1F);
//                pOut[1] = (byte)((highRegister >> 5) & 0x1F);
//                pOut[2] = (byte)((highRegister >> 10) & 0x1F);
//                pOut[3] = (byte)((highRegister >> 15) & 0x1F);
//                pOut[4] = (byte)((highRegister >> 20) & 0x1F);
//                pOut[5] = (byte)((highRegister >> 25) & 0x1F);
//                pOut[6] = (byte)((highRegister >> 30) & 0x1F);
//                pOut[7] = (byte)((highRegister >> 35) & 0x1F);
//                pOut[8] = (byte)((highRegister >> 40) & 0x1F);
//                pOut[9] = (byte)((highRegister >> 45) & 0x1F);
//                pOut[10] = (byte)((highRegister >> 50) & 0x1F);
//                pOut[11] = (byte)((highRegister >> 55) & 0x1F);

//                // 2. Load the remaining 2 bytes plus trailing data as a 32-bit uint
//                // We read from offset 6 (bytes 6, 7, 8, 9) to capture the overlap smoothly
//                uint lowRegister = *(uint*)(pPacked + 6);

//                // Extract the remaining 4 vectors (12 to 15) from the overlapping 32-bit register
//                // Because offset 6 skips the first 48 bits, we adjust our shift math accordingly
//                pOut[12] = (byte)((lowRegister >> 12) & 0x1F); // (60 total bits - 48 offset = 12)
//                pOut[13] = (byte)((lowRegister >> 17) & 0x1F);
//                pOut[14] = (byte)((lowRegister >> 22) & 0x1F);
//                pOut[15] = (byte)((lowRegister >> 27) & 0x1F);
//            }
//        }
//        [MethodImpl(MethodImplOptions.AggressiveInlining)]
//        public void ProcessAndWalkVectors(ReadOnlySpan<byte> incomingMaskedVectors, int sx, int sy, int sz) {
//            // 1. Allocate a tiny 10-byte buffer on the stack for the masked vectors
//            Span<byte> localVectors = stackalloc byte[10];
//            incomingMaskedVectors.CopyTo(localVectors);

//            // 2. Clear the vector mask instantly via XOR using your retrieved configuration mask
//            unsafe {
//                fixed (byte* pVec = localVectors) {
//                    *(ulong*)pVec ^= _currentVectorMask;
//                }
//            }

//            // 3. Allocate a 16-byte buffer on the stack to hold the unpacked 5-bit IDs
//            Span<byte> unpackedVectorPath = stackalloc byte[16];

//            // 4. Run your ultra-fast unpacking logic
//            Unpack5BitVectors(localVectors, unpackedVectorPath);

//            // 5. Allocate the final key result placeholder on the stack
//            Span<byte> keyResult = stackalloc byte[128];

//            // 6. Execute the unrolled matrix walk using the unpacked 1-byte aligned data
//            int bytesWritten = WalkMatrixUnsafe(_flatMatrix, sx, sy, sz, unpackedVectorPath, keyResult);

//            // Continue onward to your EncryptionManager components...
//        }


//        // 4. Pass the unmasked key and raw ciphertext to your server-side EncryptionType handlers
//        // The incoming metadata successfully routed the cryptographic execution!
//    }


//    //    var builder = WebApplication.CreateBuilder(args);

//    //    // 1. Bind the configuration block to your settings class
//    //    builder.Services.Configure<KeyMatrixSettings>(
//    //        builder.Configuration.GetSection(KeyMatrixSettings.SectionName));

//    //// 2. Register the custom validation rules and force validation immediately on boot
//    //builder.Services.AddSingleton<IValidateOptions<KeyMatrixSettings>, KeyMatrixSettingsValidator>();
//    //builder.Services.AddOptions<KeyMatrixSettings>()
//    //    .Bind(builder.Configuration.GetSection(KeyMatrixSettings.SectionName))
//    //    .ValidateOnStart(); // Bails out instantly if appsettings.json has invalid dimensions

//    //    // 3. Register your optimized Key Walker as a Singleton
//    //    builder.Services.AddSingleton<OptimizedKeyWalker>();

//}


//public unsafe partial class OptimizedKeyWalker {
//    //private readonly int _widthMask;
//    //private readonly int _heightMask;
//    //private readonly int _depthMask;
//    //private readonly int _strideY;
//    //private readonly int _strideZ;

//    public OptimizedKeyWalker(IOptions<KeyMatrixSettings> options) {
//        // Extract the strictly validated values
//        KeyMatrixSettings settings = options.Value;

//        // Create masks (e.g., if width is 64, mask becomes 63)
//        _widthMask = settings.Width - 1;
//        _heightMask = settings.Height - 1;
//        _depthMask = settings.Depth - 1;

//        // Precalculate strides for your flat 1D matrix
//        _strideY = settings.Width * 8;
//        _strideZ = settings.Width * settings.Height * 8;
//    }
//    [MethodImpl(MethodImplOptions.AggressiveInlining)]
//    public unsafe int WalkMatrixUnsafe(
//    byte[] flatMatrix,
//    int sx, int sy, int sz,
//    ReadOnlySpan<byte> unpackedVectors,
//    Span<byte> keyResult) {
//        int cx = sx; int cy = sy; int cz = sz;
//        int bytesWritten = 0;

//        // Cache masks in local CPU registers for maximum hardware throughput
//        int wMask = _widthMask;
//        int hMask = _heightMask;
//        int dMask = _depthMask;
//        int sY = _strideY;
//        int sZ = _strideZ;

//        fixed (byte* pMatrix = flatMatrix)
//        fixed (byte* pResult = keyResult) {
//            // Addresses of local variables so the inlined method can update them directly
//            int* pX = &cx; int* pY = &cy; int* pZ = &cz;
//            byte v;

//            // ==========================================
//            // STEP 1
//            // ==========================================
//            v = unpackedVectors[0];
//            if (v != 0) {
//                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
//                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
//                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
//                bytesWritten += 8;
//            }

//            // ==========================================
//            // STEP 2
//            // ==========================================
//            v = unpackedVectors[1];
//            if (v != 0) {
//                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
//                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
//                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
//                bytesWritten += 8;
//            }

//            // [ REPEAT THIS EXACT UNROLLED BLOCK PATTERN FOR STEPS 2 TO 15 ]
//            // Indices scale up cleanly: unpackedVectors[2] through unpackedVectors[15]
//        }

//        return bytesWritten;
//    }
//    [MethodImpl(MethodImplOptions.AggressiveInlining)]
//    public unsafe int WalkMatrixWithStopMarker(
//    byte[] flatMatrix,
//    int sx, int sy, int sz,
//    ReadOnlySpan<byte> unpackedVectors,
//    Span<byte> keyResult,
//    int maxTargetBytes) // e.g., 32 for AES256, 64 for AES512
//{
//        int cx = sx; int cy = sy; int cz = sz;
//        int bytesWritten = 0;

//        int wMask = _widthMask; int hMask = _heightMask; int dMask = _depthMask;
//        int sY = _strideY; int sZ = _strideZ;

//        fixed (byte* pMatrix = flatMatrix)
//        fixed (byte* pResult = keyResult) {
//            int* pX = &cx; int* pY = &cy; int* pZ = &cz;
//            byte v;

//            // ==========================================
//            // STEP 1
//            // ==========================================
//            v = unpackedVectors[0];
//            if (v == 31 || bytesWritten >= maxTargetBytes) goto EndOfWalk; // Explicit fast-exit conditions
//            if (v != 0) {
//                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
//                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
//                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
//                bytesWritten += 8;
//            }

//            // ==========================================
//            // STEP 2
//            // ==========================================
//            v = unpackedVectors[1];
//            if (v == 31 || bytesWritten >= maxTargetBytes) goto EndOfWalk;
//            if (v != 0) {
//                EvaluateVectorStep(v, pX, pY, pZ, wMask, hMask, dMask);
//                int offset = (cx << 3) + (cy * sY) + (cz * sZ);
//                *(ulong*)(pResult + bytesWritten) = *(ulong*)(pMatrix + offset);
//                bytesWritten += 8;
//            }

//            // [ REPEAT THIS UNROLLED PATTERN FOR STEPS 2 TO 15... ]

//        EndOfWalk:; // The jump target for early truncation
//        }

//        return bytesWritten; // Returns the exact truncated length to the caller
//    }

//    // Your ultra-fast WalkMatrixUnsafe method sits below...
//}

////{
////  "KeyMatrixSettings": {
////    "Width": 64,
////    "Height": 64,
////    "Depth": 32
////  }
////}





//// This class automatically runs during program startup to validate your rules
//public class KeyMatrixSettingsValidator : IValidateOptions<KeyMatrixSettings> {
//    public ValidateOptionsResult Validate(string? name, KeyMatrixSettings options) {
//        // 1. Check if values are zero or negative
//        if (options.Width <= 0 || options.Height <= 0 || options.Depth <= 0) {
//            return ValidateOptionsResult.Fail("Matrix dimensions must be greater than zero.");
//        }

//        // 2. Validate that each dimension is a strict Power of Two using fast bit math
//        if ((options.Width & (options.Width - 1)) != 0)
//            return ValidateOptionsResult.Fail($"Configuration Error: Width ({options.Width}) is not a power of 2.");

//        if ((options.Height & (options.Height - 1)) != 0)
//            return ValidateOptionsResult.Fail($"Configuration Error: Height ({options.Height}) is not a power of 2.");

//        if ((options.Depth & (options.Depth - 1)) != 0)
//            return ValidateOptionsResult.Fail($"Configuration Error: Depth ({options.Depth}) is not a power of 2.");

//        return ValidateOptionsResult.Success;
//    }
//}

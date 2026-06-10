# Mrbr.Service.KeyManager

A high-performance .NET key management service supporting dual key generation strategies: **Block** (1D contiguous extraction) and **Matrix** (3D vector-based navigation).

## Features

- **256 Key Slots**: Supports key IDs from 0 to 255
- **Dual Key Generation Modes**:
  - **Block Mode**: Fast 1D contiguous substring extraction with position/length encoding
  - **Matrix Mode**: Advanced 3D vector-based key walking through matrix space
- **Configurable Key Derivation**: SHA-256, SHA-384, SHA-512 with optional salting and iterations
- **Type-Safe Configuration**: Strong validation for Block and Matrix settings
- **High Performance**: `AggressiveInlining`, unsafe code, and zero-allocation patterns where possible

---

## Architecture Overview

### Block Keys (1D Contiguous Extraction)

Block mode extracts contiguous substrings from source text and encodes the extraction metadata into a 32-bit integer (`keyResult`):

```
Block keyResult Format (28 bits used):
┌─────────────┬──────────────────┬──────────────┐
│  KeyId:8    │  KeyPosition:10  │  KeyLength:10│
│  (0-255)    │  (0-1023)        │  (0-1023)    │
└─────────────┴──────────────────┴──────────────┘
```

**Key Properties**:
- Direct substring slice from source text
- Position and length stored in `keyResult` for reproducibility
- Optional KeyIdMask for obfuscation (must not modify lowest 8 bits)

**Configuration** (`KeyBlockSettings`):
- `MinLength` (default 64): Minimum key length
- `MaxLength` (default 128): Maximum key length
- Source text must be at least `MinLength + MaxLength` bytes

---

### Matrix Keys (3D Vector-Based Navigation)

Matrix mode builds a flat 3D byte matrix from source text and walks through it using 16 random vector steps:

```
Matrix Metadata (19 bytes):
┌─────────┬─────────────────┬──────────────────────────┐
│ KeyId:8 │ StartPosition:16│ Vectors:128 (16×8 bits)  │
│ (0-255) │ (10 bits used)  │ (16 vector steps)        │
└─────────┴─────────────────┴──────────────────────────┘
```

**Key Properties**:
- 3D matrix layout: `[x + (y * width) + (z * width * height)] * 8 bytes per cell`
- Each vector is a 5-bit direction code (0=no-op, 1-26=move, 31=stop)
- Random start position and vectors ensure unique key paths
- `MatrixKeyResult` preserves full walk state for key recreation

**Configuration** (`KeyMatrixSettings`):
- `Width`, `Height`, `Depth`: Matrix dimensions (must be powers of 2, range 8-2048)
- `VectorMask`: 64-bit obfuscation mask for vectors
- `KeyMask`: 64-bit obfuscation mask for output keys

**3D Vector Directions** (OptimizedKeyWalker):
```
0: No-op (stay in place)
1-26: 3D movement vectors (combinations of ±X, ±Y, ±Z)
31: Stop marker (ends walk early)
```

---

## Configuration

### appsettings.json Structure

```json
{
  "KeyServiceConfig": [
    {
      "Key": 0,
      "Value": "{{your_very_long_source_text_here}}",
      "KeyIdMask": "256",
      "Type": "Block",
      "BlockSettings": {
        "MinLength": 64,
        "MaxLength": 128
      }
    },
    {
      "Key": 1,
      "Value": "{{your_very_long_source_text_here}}",
      "KeyIdMask": "512",
      "Type": "Matrix",
      "MatrixSettings": {
        "Width": 16,
        "Height": 16,
        "Depth": 8,
        "VectorMask": 0,
        "KeyMask": 0
      }
    }
  ]
}
```

**Field Descriptions**:
- `Key`: Key ID (0-255)
- `Value`: Source text for key generation (UTF-8 encoded)
- `KeyIdMask`: Additional obfuscation mask (must not set lowest 8 bits; minimum value: 256)
- `Type`: `"Block"` or `"Matrix"`
- `BlockSettings`: Required for Block keys
- `MatrixSettings`: Required for Matrix keys

---

## Usage

### Dependency Injection Setup

```csharp
using Microsoft.Extensions.DependencyInjection;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.Services;

var services = new ServiceCollection();

// Bind configuration
services.Configure<KeyServiceConfig>(configuration.GetSection(KeyServiceConfig.SectionName));
services.AddSingleton<KeyServiceOptions>();
services.AddSingleton<IKeyService, KeyService>();

var serviceProvider = services.BuildServiceProvider();
var keyService = serviceProvider.GetRequiredService<IKeyService>();
```

### Generate Keys

```csharp
// Generate a 256-bit key (Block or Matrix, chosen randomly from available keys)
byte[] key256 = keyService.GenerateKey256(out int keyResult);

// Generate a 128-bit key
byte[] key128 = keyService.GenerateKey128(out keyResult);

// Generate a variable-length key
byte[] customKey = keyService.GenerateKeyBytes(keySizeInBytes: 32, out keyResult);
```

### Retrieve Keys

```csharp
// Retrieve using the keyResult from generation
byte[] retrievedKey = keyService.GetKey256(keyResult);

// Retrieve with key derivation options
var options = new KeyDerivationOptions {
    Algorithm = KeyDerivationAlgorithm.Sha512,
    Salt = Encoding.UTF8.GetBytes("my-salt"),
    Iterations = 100000
};
byte[] derivedKey = keyService.GetKey256(keyResult, options);
```

### Matrix Key Persistence

For Matrix keys, the `keyResult` only contains the Key ID. To recreate the exact key, you must preserve the full `MatrixKeyResult`:

```csharp
using Mrbr.Service.KeyManager.Matrices;

var matrixGenerator = new MatrixKeyGenerator(matrixSettings);
var result = matrixGenerator.GenerateKey(sourceText, keyId: 42, maxTargetBytes: 32);

// Encode for storage
byte[] encoded = result.EncodeToBytes(); // 19 bytes: [keyId:1][startPos:2][vectors:16]

// Decode for recreation
var decoded = MatrixKeyResult.DecodeFromBytes(encoded);
var recreated = matrixGenerator.RegenerateKey(
    sourceText, 
    decoded.KeyId, 
    decoded.StartPosition, 
    decoded.Vectors, 
    maxTargetBytes: 32
);
```

---

## Key Derivation Options

```csharp
public enum KeyDerivationAlgorithm {
    Sha256,   // Default
    Sha384,
    Sha512
}

public record KeyDerivationOptions {
    public KeyDerivationAlgorithm Algorithm { get; init; } = KeyDerivationAlgorithm.Sha256;
    public byte[]? Salt { get; init; }
    public int Iterations { get; init; } = 10000;
}
```

---

## Performance Considerations

### Block Keys
- **Best for**: High-throughput scenarios where simple substring extraction suffices
- **Performance**: <1μs per key generation (no hashing)
- **Space**: 28 bits of metadata in `keyResult`

### Matrix Keys
- **Best for**: Maximum entropy and unpredictability
- **Performance**: ~5-10μs per key generation (includes 16-step 3D walk)
- **Space**: 19 bytes of metadata per key (not stored in `keyResult`)
- **Note**: Metadata must be persisted separately for key recreation

---

## Validation Rules

### Block Keys
- Source text must be ≥ `MinLength + MaxLength` characters
- `MinLength` ≤ `MaxLength`
- `MaxLength` ≤ source text length

### Matrix Keys
- `Width`, `Height`, `Depth` must be powers of 2
- Dimensions range: 8-2048
- Total matrix size: `Width × Height × Depth × 8 bytes` ≥ 128 bytes
- Source text must provide enough UTF-8 bytes to fill the matrix

### Common Rules
- Key ID: 0-255
- KeyIdMask: Must not modify lowest 8 bits (minimum value: 256)
- Only one settings type per key (Block or Matrix, not both)

---

## Testing

Run the integration test suite:

```bash
dotnet test Mrbr.Service.KeyManager.Tests
```

**Test Coverage**:
- MatrixBuilder flat matrix creation and dimension validation
- MatrixKeyGenerator key generation and regeneration consistency
- MatrixKeyResult encoding/decoding round-trips
- KeyBlockSettings constraint validation
- KeyServiceEntry type-specific settings enforcement
- Key ID range validation (0-255)

---

## License

This project is licensed under the MIT License.

---

## Contributing

Contributions are welcome! Please ensure:
- All tests pass
- Code follows existing patterns (aggressive inlining, nullable annotations, XML docs)
- New features include corresponding tests

---

## Roadmap

- [ ] Add benchmarking suite for Block vs Matrix performance comparison
- [ ] Support for custom vector direction mappings
- [ ] Matrix walk result caching for frequently-used keys
- [ ] Integration with hardware security modules (HSM)
# Mrbr.Service.KeyManager

A high-performance .NET key management service supporting dual key generation strategies: **Block** (1D contiguous extraction) and **Matrix** (3D vector-based navigation).

## Project Details

- **Target Framework**: `net11.0`
- **Package Version**: `1.0.2`
- **Assembly/File Version**: `1.0.2.0`

### Dependencies

- `Mrbr.Extensions.Configuration` (`1.0.8`)
- `Mrbr.SourceGenerators.Common` (`1.0.0`)
- `System.Configuration.ConfigurationManager` (`11.0.0-preview.4.26230.115`)
- Framework reference: `Microsoft.AspNetCore.App`

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

Matrix mode builds a flat one-byte-per-cell 3D matrix from source text and walks through it using compact 5-bit vectors. The key handle stores the start position and walk seed; the requested key length is supplied by the caller's destination span.

```
Matrix key handle payload:
[KeySourceId:8][Format:8][StartPosition:N][WalkSeed:48-N]
```

**Key Properties**:
- 3D matrix layout: `x + (y * width) + (z * width * height)`
- Powers-of-two dimensions allow offset packing with shifts and wrap-around with bit masks
- Each vector is a 5-bit value; values `1-26` map to the valid 3D movement directions
- Values `0` and `27-31` are reserved and remapped, not treated as stop markers
- Each vector leg emits up to 8 bytes; the final leg is truncated to the requested key size
- Matrix handles do not store key length; replay writes into the caller-provided destination length

**Configuration** (`KeyMatrixSettings`):
- `Width`, `Height`, `Depth`: Matrix dimensions (must be powers of 2, range 8-2048)
- Source text must contain at least `Width * Height * Depth` UTF-8 bytes
- Matrix dimensions must leave at least 16 walk-seed bits in the 64-bit key handle

**3D Vector Directions**:
```
1-26: 3D movement vectors (all combinations of -1, 0, +1 across X/Y/Z except 0,0,0)
0, 27-31: Reserved values remapped to valid directions
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
        "Depth": 8
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

For Matrix keys, the returned `keyHandle` contains the unmasked `KeySourceId` plus masked replay metadata for the matrix start position and walk seed. The requested key length is not stored in the handle; replay into the same destination length to reproduce the same key material.

```csharp
Span<byte> generated = stackalloc byte[32];
keyService.GenerateKey(generated, out ulong keyHandle);

Span<byte> replayed = stackalloc byte[32];
keyService.GetKey(keyHandle, replayed);
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
- **Performance**: Span-based replay with cached matrix source and fixed 8-byte legs
- **Space**: Replay metadata is stored in the 64-bit `KeyHandle`
- **Note**: Callers must supply the desired destination length when replaying Matrix keys

---

## Validation Rules

### Block Keys
- Source text must be ≥ `MinLength + MaxLength` characters
- `MinLength` ≤ `MaxLength`
- `MaxLength` ≤ source text length

### Matrix Keys
- `Width`, `Height`, `Depth` must be powers of 2
- Dimensions range: 8-2048
- Total matrix size: `Width * Height * Depth` bytes must be at least 128 bytes
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
- Matrix key handle replay and 5-bit vector behavior
- KeyBlockSettings constraint validation
- KeyServiceEntry type-specific settings enforcement
- Key ID range validation (0-255)

---

## License

This project is licensed under the MIT License.

---



## Roadmap

- [ ] Add benchmarking suite for Block vs Matrix performance comparison
- [ ] Support for custom vector direction mappings
- [ ] Matrix walk result caching for frequently-used keys
- [ ] Integration with hardware security modules (HSM)

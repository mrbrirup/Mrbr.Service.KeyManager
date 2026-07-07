# 2019 Called and Wants its Authentication Back
Or: How do you make Copilots Copy Lots

If I'm developing something I'm responsible for it. Curious as to how well the hype met reality I optimistically asked Copilot to create the Authentication for a Web Api application. 

It created the ASP.Net Core Identity scaffolding for me. Decades of software and systems development below my belt, and this was my first 'vibe coding' experience.
It did what I asked. It didn't include Passkeys, so the model matched the schema from 2019. Copilot said I could use from .Net 8, still nearly three years old. It was effectively a carbon copy of code from Microsoft's documentation. Quality code, but the bare minimum.

Even a few years ago I would have been happy with that. But now, more than half way through 2026, Copilot does not understand the world it's living in. How often hacks and breaches occur, and when developers are expected to implement post-quantum security. It's behind the times and leaving users open to attacks.

I'm writing a sustainability and circularity app that this was going to be part of. It doesn't feel right implementing that which would leave my users vulnerable and myself open to liability.

Copilot was enthusiastic and complementary when I made suggestions, but that meant it didn't understand the implications of what was missing.
Unique per datum encryption keys, post-quantum security, data-at-rest encryption, hashed searches, to me essential, to Copilot a new world of wonders and delights. Not useful discourse.

These features I have to put in from the get go. I didn't like the idea of a retrofit, do the work, undo the work, do the new work, test it and update every piece of PII and financial data that had gone before, no thanks.

My priority was designing a system that can generate unique cryptographic keys for each piece of data. This means that even if one key is compromised, the rest of the data remains secure. A Key Manager that works on cryptographic blocks of text and 3D matrices.

Presented with the architecture, Copilot - bless its heart - tried its best, but eventually churned through a month's worth of tokens in an afternoon and simply gave up.
I couldn't untangle what it had done. GitHub saved me from the sad fate that had befallen my code.

I described the system to ChatGPT, create keys from a large block of text, a random start, random length, and Base 94 encoding. It understood my request and when I asked how many possible permutations, such as through a brute force attack, would be required to guess a key, it informed me that it would be a very large number. Who wouldn't want to use a system knowing that. ChatGPT has got better, I'll drop its latest response below.

Still, I'm implementing this myself. I'll let the AIs help and join in occasionally, but if some of the oddities I've seen from them are generated from known functionality, I'm reluctant to let them try on something they'd never seen nor heard of.

The deeper I go, the more I realise I have to pull these core structural layers out of my primary application entirely. Before I can touch the business logic of my sustainability app, I must bolster the security with a fellowship of dependency-injected managers: Keys, Encryption, Database Encryption, Hashing, Authentication, and Authorisation.

tl;dr: I'm writing a Key Manager

## The Key Manager

`Mrbr.Service.KeyManager` is a .NET service for generating replayable key material from configured key sources.

I designed this to provide unique keys for each piece of data, so that if one key is compromised, the rest of the data remains secure. Keys can be generated from a 1d block of text or a 3d matrix of bytes. The service generates key bytes on demand, returns a handle that can be stored with the protected data, and can later regenerate the same key bytes from the handle.

## Key Space

Passing the algorithm to ChatGPT to check my maths to assess the number of keys that can be generated per MB produced the following:

***That number is absurdly large. Not “large” in normal cryptographic terms, but “the universe gives up first” large.***

Absurd in a complement, new to me, but I'll go with it. There's enough unique keys for one per datum. That was for Block Source. For Matrix Source, we're into multiverse ending territory. The number of possible keys is so large that it is effectively impossible to brute-force them all... touch wood.
Post-Quantum Cryptography is not impossible to crack, it's about the attacker getting bored before they can get through the key space.


The numbers returned from ChatGPT per 1MB of Source text for the Block Keywere:

Source text of Base94 ASCII, then each source character has:
```
log2(94) = ~6.55 bits of entropy per char
```
1 MiB of Base94 source text
```
1,048,576 chars
94 ^ 1,048,576 possible source texts
~ 10 ^ 2,068,000
~ 6.86 million bits of source entropy
```
For a single extracted key of length L Base94 chars, the possible key space is:
```
94 ^ L
```
Examples:

| Key length | Possibilities | Entropy |
|---:|---:|---:|
| 16 chars | ~3.7e31  | ~105 bits |
| 24 chars | ~1.3e47  | ~157 bits |
| 32 chars | ~4.7e63  | ~210 bits |
| 64 chars | ~2.2e127 |  ~419 bits |


The service does not perform any cryptographic work. It only handles the keys.

For encryption, signing, verification, or decrypting data-at-rest, I need three things:

- Key material for the cryptographic operation.
- A compact reference that can be stored with the protected data.
- A way to regenerate the same key material without storing that key material directly.


Why are there two Source options, Block and Matrix?
I needed to see that the simplest approach, Block, was feasible, fast and practical. I'm not going to remove the Block option, it's a possible path to improvements I've not yet thought of.


## Performance

The performance of the Key Manager is measured in two scenarios: Block and Matrix Source used in cryptographic operations. There's an extract below.

For small payloads (128 bytes), the classic single key, is 4x faster, around 500ns, than the Key Manager-generated keys.
For larger payloads (4 KB), the performance difference is negligible, indicating that the overhead of key generation and retrieval is amortized over larger data sizes.

It's a good trade off. I want this to be highly performant, but security is the first consideration.

**Block Source**

| Operation | Payload | Cached Static | KeyManager | Difference |
|---|---:|---:|---:|---|
| AES-GCM Encrypt | 128 B | 171 ns | 685 ns | cached static ~4.0x faster |
| AES-GCM Decrypt | 128 B | 177 ns | 696 ns | cached static ~3.9x faster |
| AES-GCM Encrypt | 4 KB | 1,773 ns | 1,735 ns | effectively the same |
| AES-GCM Decrypt | 4 KB | 1,795 ns | 1,738 ns | effectively the same |


**Matrix Source**

| Operation | Payload | Baseline | Matrix KeyManager | Delta | Ratio |
|---|---:|---:|---:|---:|---:|
| AES-GCM Encrypt | 128 B | 170.9 ns | 734.1 ns | +563.2 ns | 4.30x |
| AES-GCM Decrypt | 128 B | 174.6 ns | 738.5 ns | +563.9 ns | 4.23x |
| AES-GCM Encrypt | 4 KB | 1,772.7 ns | 1,768.4 ns | -4.3 ns | 1.00x |
| AES-GCM Decrypt | 4 KB | 1,773.7 ns | 1,774.3 ns | +0.6 ns | 1.00x |
| HMAC-SHA256 | 128 B | 1,655.4 ns | 1,730.0 ns | +74.6 ns | 1.05x |
| HMAC-SHA256 | 4 KB | 15,427.2 ns | 15,568.8 ns | +141.6 ns | 1.01x |


The tests and benchmarks check:

- Matrix builders validate power-of-two dimensions.
- Matrix generation and replay produce identical bytes.
- Matrix handles reject layouts that leave too few seed bits.
- Reserved vector values are remapped rather than treated as stop markers.
- Block keys replay the expected wrapped source bytes.
- Key source IDs stay inside the `0` to `255` range.
- Block and Matrix settings are mutually exclusive.

There is also a BenchmarkDotNet project comparing:

- Static key copy.
- Key Manager generation.
- Key Manager replay.
- HMAC-SHA256 using static and replayed keys.
- AES-GCM encrypt and decrypt using static and replayed keys.

The source text can be any length that C# can handle. Caveats of powers of 2 apply to the Matrix Source for binary calculations reasons. 
It supports up to 256 key sources. Depending on your application, you may want to use a different source for each Encryption, Signing, and Hashing type employed or per service, PII, HIPAA, Financial.
The Key Sources need to be treated as secrets. The source text is not stored in the database, only the handle is stored with the protected data. The source text is configured in the application configuration, and should be protected using a secrets management system.

## Configuration

The runtime shape is intentionally small. A key source has an ID, source text, a handle mask, and a generation type.

```json
{
  "KeyService": [
    {
      "KeySourceId": 0,
      "Value": "{{long_secret_source_text}}",
      "KeyHandleMask": "256",
      "Type": "Block"
    },
    {
      "KeySourceId": 1,
      "Value": "{{long_secret_source_text}}",
      "KeyHandleMask": "512",
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

Registration follows the usual options and dependency injection pattern:

```csharp
builder.ConfigureKeyService();

var keyService = app.Services.GetRequiredService<IKeyService>();
```

The useful API is the span-based path:

```csharp
Span<byte> signingKey = stackalloc byte[32];
keyService.GenerateKey(signingKey, out ulong keyHandle);

Span<byte> replayedKey = stackalloc byte[32];
keyService.GetKey(keyHandle, replayedKey);
```

The first call writes 32 bytes into `signingKey` and returns a `keyHandle`.

The second call uses the handle to replay the same 32 bytes.

That is the core contract.

## The Handle

Every generated key has a `ulong` handle. The handle is not the key. It is a recipe for finding the key material again.

From the low bits upward, the handle is arranged like this:

```text
[KeySourceId:8][Format:8][Payload:48]
```

The `KeySourceId` is deliberately left readable. The service needs to know which configured source to use before it can decode the rest of the payload.

The format byte identifies the generation strategy:

```text
1 = Block
2 = Matrix
```

The remaining 48 bits are strategy-specific replay data.

```text
Block payload:  [Start:32][Length:16]
Matrix payload: [StartPosition:N][Seed:48-N]
```

The bits above `KeySourceId` can be masked with `KeyHandleMask`, but the lowest 8 bits must remain clear. If the mask modifies the source ID, the service rejects it. This is not theatrical obfuscation. It is a practical boundary: find the source first, then decode the replay data for that source.

A handle should still be treated as security-sensitive metadata. If someone has the handle, the source material, and the mask, they can recreate the key bytes. If someone only has the handle, they have an incomplete recipe. If someone loses the source material, old protected data cannot be replayed.

## Block Keys

Block mode is the fast path.

It treats the source as a byte sequence, picks a random start position, copies the requested number of bytes, and wraps around the end of the source if needed.

The handle stores:

- The key source ID.
- The fact that this is a Block key.
- The start position.
- The requested length.

Replay is direct. Decode the handle, find the same source, copy the same bytes.

This makes Block mode easy to reason about. There is no ceremony, no extra structure, it is not the random, drunken walk the Matrix performs. It is useful where throughput matters and where the source material is already large enough to provide a meaningful key space.

The implementation also keeps the allocation-heavy convenience APIs separate from the hot path. If the caller provides a `Span<byte>`, the service writes into that span. If the caller asks for a byte array, the service allocates one.

That distinction matters once the key manager sits inside encryption and signing paths. A cryptographic layer is already doing enough work. It does not need extra allocations sprinkled over it for decoration.

## Matrix Keys

Matrix mode is the more interesting version.

It takes the configured source bytes and treats them as a flat one-byte-per-cell 3D matrix. The conceptual layout is:

```text
offset = x + (y * width) + (z * width * height)
```

The configured dimensions must be powers of two. That is not an aesthetic preference. It means coordinate wrapping can be done with bit masks, and offsets can be packed with shifts:

```text
offset = x | (y << widthBits) | (z << zShift)
```

The service chooses a random start position in that matrix and a random seed. The seed drives a deterministic stream of movement vectors. Each vector is one of the 26 possible directions in 3D space:

- X, Y, or Z movement.
- Diagonal movement across two axes.
- Diagonal movement across all three axes.
- Never the zero vector, because standing still is not much of a walk.

Each vector leg emits up to 8 bytes. For a 32-byte key, that is four legs. For a 16-byte key, two legs. If the requested length does not divide neatly into 8, the final leg is truncated to fit the caller's destination span.

The important part is that Matrix mode is still deterministic once the handle exists.

Generation:

- Pick a start position.
- Pick a seed.
- Walk the matrix.
- Write bytes into the caller's span.
- Pack the start position and seed into the handle.

Replay:

- Decode the handle.
- Recreate the same vector stream from the seed.
- Start at the same matrix position.
- Walk the same path.
- Write the same bytes into the caller's span.

Matrix handles do not store output length. The 48-bit payload is split between start position and seed, and the dimensions decide how many bits the start position needs. The caller supplies the destination length during replay.

## The Security Boundary

The Key Manager is not the whole security system. It's the first member of the followship of the security components. They will be joined shortly by encryption, database encryption, hashing, authentication, and authorisation. Each of those is a separate service with its own API and configuration.

The boundary here is narrower:

- Source material is configured and protected outside the database.
- Key handles are stored with protected data.
- Key bytes are generated only when needed for a cryptographic operation.
- The raw generated key is not the thing I want to persist.

For per-datum encryption, that means each value can carry its own replay handle. If one datum's key material is exposed, the rest of the system is not automatically reduced to rubble by a single shared key.

With a unique key for each datum key rotation is not the same as it is for a single key. If a key source is compromised then each datum that used that source needs to be re-encrypted or hashed with a new key.

The security has become a distraction from what I wanted to build, but I thought enough of the issues and how it could affect people that it needed to be a core prinicple of my development.

## It's Not all Doom

It's a bit late in the post, but the existing Authentication is not a bad one. The issue is that hacks and breaches are becoming data harvests. Get the data, store it, wait until you can afford your quantum computer, then hack your ill gotten gains.

NIST and NCSC have their recommendations for post-quantum cryptography. Algorythms have been developed, agreed and being implemented. The next few years sees some classic encryption and signing algorithms slated for deprecation. The world is moving on, and I need to move with it.

I felt that support and direction from those that supply the frameworks were lacking. If anyone has any feedback on this subject I'm all ears. First version may not be perfect, but do the right thing, then do the right thing in the right way. As bad actors become more sophisticated, I'll adapt this system to meet the new threats.

The repository is here:

[https://github.com/mrbrirup/Mrbr.Service.KeyManager](https://github.com/mrbrirup/Mrbr.Service.KeyManager)

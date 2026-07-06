using Microsoft.Extensions.Options;
using Mrbr.Service.KeyManager.Matrices;
using Mrbr.Service.KeyManager.Services;
using System.Globalization;
using System.Text;
using static Mrbr.Service.KeyManager.Services.KeyService;

namespace Mrbr.Service.KeyManager.Configuration;

/// <summary>
/// Wraps the configured key set and projects it into the static runtime cache used by <see cref="KeyService"/>.
/// This class manages thread-safe initialization and provides high-performance key lookup through static arrays.
/// </summary>
/// <remarks>
/// This sealed class implements the options pattern and maintains a static cache of key service records
/// for fast key lookup operations. The cache is initialized once from configuration and remains in memory
/// for the lifetime of the application.
/// </remarks>
public sealed class KeyServiceOptions : IOptions<KeyServiceConfig> {
    /// <summary>
    /// Static array cache of key service records indexed by key ID for fast lookup.
    /// </summary>
    /// <remarks>
    /// This shared state is cached once during initialization so key lookup stays fast after configuration is loaded.
    /// </remarks>
    private static KeyServiceRecord?[] _keys = default!;

    /// <summary>
    /// Static array cache of key values as <see cref="ReadOnlyMemory{T}"/> for efficient memory access.
    /// </summary>
    private static ReadOnlyMemory<char>[] _keyMemory = default!;

    /// <summary>
    /// Static array cache of UTF-8 source bytes indexed by key source ID.
    /// </summary>
    private static ReadOnlyMemory<byte>[] _keyBytes = default!;

    /// <summary>
    /// Dense list of configured key source IDs for random selection.
    /// </summary>
    private static int[] _keySourceIds = default!;

    /// <summary>
    /// The total number of keys currently loaded in the cache.
    /// </summary>
    private static int _keyCount = 0;

    /// <summary>
    /// Flag indicating whether the static cache has been initialized.
    /// </summary>
    private static bool _initialised = false;

    /// <summary>
    /// Lock object used to ensure thread-safe initialization and modification of the static cache.
    /// </summary>
    private static readonly Lock lockObject = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyServiceOptions"/> class.
    /// </summary>
    /// <param name="options">The configuration options containing key service entries.</param>
    /// <remarks>
    /// <para>
    /// This constructor processes the configuration and applies type-specific normalization where needed.
    /// Block keys are currently passed through unchanged, preserving the place where type-specific
    /// normalization can be applied without changing the configured values.
    /// </para>
    /// <para>
    /// If this is the first instance, the static cache is initialized with all configured keys.
    /// </para>
    /// </remarks>
    public KeyServiceOptions(IOptions<KeyServiceConfig> options) {
        this.Value = options.Value;

        // Block keys are currently passed through unchanged; this preserves the place where
        // type-specific normalization can be applied without changing the configured values.
        foreach (var keyServiceEntry in Value) {
            if (keyServiceEntry.Type == KeyType.Block) {
                //var blockSettings = keyServiceEntry.BlockSettings ?? throw new InvalidOperationException($"BlockSettings must be provided for key {keyServiceEntry.KeySourceId} of type Block.");
                //keyServiceEntry.Value = keyServiceEntry.Value.ParseConfig();
                keyServiceEntry.Value = keyServiceEntry.Value;
                keyServiceEntry.KeyHandleMask = keyServiceEntry.KeyHandleMask;
            }
        }


        if (_initialised == false) { Initialise(); }
    }

    /// <summary>
    /// Gets the static array of key service records indexed by key ID.
    /// </summary>
    /// <value>
    /// An array of nullable <see cref="KeyServiceRecord"/> objects where the index represents the key ID.
    /// </value>
    public static KeyServiceRecord?[] Keys => _keys;

    /// <summary>
    /// Gets the static array of key values as <see cref="ReadOnlyMemory{T}"/> for efficient memory access.
    /// </summary>
    /// <value>
    /// An array of <see cref="ReadOnlyMemory{T}"/> containing the key values indexed by key ID.
    /// </value>
    public static ReadOnlyMemory<char>[] KeyMemory => _keyMemory;

    /// <summary>
    /// Gets the static array of UTF-8 key source bytes indexed by key source ID.
    /// </summary>
    public static ReadOnlyMemory<byte>[] KeyBytes => _keyBytes;

    /// <summary>
    /// Gets the dense configured key source ID list used for random source selection.
    /// </summary>
    public static int[] KeySourceIds => _keySourceIds;

    /// <summary>
    /// Gets the total number of keys currently loaded in the cache.
    /// </summary>
    /// <value>
    /// The count of non-null keys in the cache.
    /// </value>
    public static int KeyCount => _keyCount;

    /// <summary>
    /// Deletes a key from the static cache by its key ID.
    /// </summary>
    /// <param name="keyId">The ID of the key to delete (0-255).</param>
    /// <returns>
    /// <c>true</c> if the key was found and deleted; <c>false</c> if the key does not exist.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="keyId"/> is outside the valid range (0 to <see cref="KeyService.MaxKeyCount"/> - 1).
    /// </exception>
    /// <remarks>
    /// This method is thread-safe and removes the key from both the record array and memory cache
    /// while keeping the key count synchronized.
    /// </remarks>
    public static bool DeleteKey(ulong keyId) {
        lock (lockObject) {
            if (keyId >= KeyService.MaxKeyCount) {
                throw new ArgumentOutOfRangeException(nameof(keyId), $"Key Id must be between 0 and {KeyService.MaxKeyCount - 1} (0-255)");
            }
            int keySourceId = (int)keyId;
            if (_keys[keySourceId] == null) return false; // Key does not exist

            // Keep the record array, memory cache, and count in sync.
            _keys[keySourceId] = null;
            _keyMemory[keySourceId] = default;
            _keyBytes[keySourceId] = default;

            for (int i = 0; i < _keyCount; i++) {
                if (_keySourceIds[i] == keySourceId) {
                    _keySourceIds[i] = _keySourceIds[_keyCount - 1];
                    _keySourceIds[_keyCount - 1] = 0;
                    break;
                }
            }

            _keyCount--;
        }
        return true;
    }

    /// <summary>
    /// Deletes all keys from the static cache.
    /// </summary>
    /// <returns>
    /// <c>true</c> if keys were deleted; <c>false</c> if the cache was already empty.
    /// </returns>
    /// <remarks>
    /// This method is thread-safe and clears both the key records and memory cache arrays,
    /// ensuring no stale key data remains reachable. The key count is reset to zero.
    /// </remarks>
    public static bool DeleteAllKeys() {
        lock (lockObject) {
            if (_keyCount > 0) {
                // Reset both caches together so no stale key data remains reachable.
                Array.Clear(_keys, 0, _keys.Length);
                Array.Clear(_keyMemory, 0, _keyMemory.Length);
                Array.Clear(_keyBytes, 0, _keyBytes.Length);
                Array.Clear(_keySourceIds, 0, _keySourceIds.Length);
                _keyCount = 0;
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Initializes the static cache with keys from the configuration.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method uses double-checked locking to ensure thread-safe initialization.
    /// It allocates fixed-size backing arrays once, with entries indexed directly by key ID.
    /// </para>
    /// <para>
    /// The initialization process:
    /// <list type="number">
    /// <item><description>Allocates arrays sized to <see cref="KeyService.MaxKeyCount"/>.</description></item>
    /// <item><description>Validates each key configuration entry.</description></item>
    /// <item><description>Parses and validates the key ID mask.</description></item>
    /// <item><description>Creates type-specific <see cref="KeyServiceRecord"/> objects (Block or Matrix).</description></item>
    /// <item><description>Populates both the record array and memory cache.</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when a key ID is outside the valid range (0 to <see cref="KeyService.MaxKeyCount"/> - 1).
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an unknown <see cref="KeyType"/> is encountered or when validation fails.
    /// </exception>
    void Initialise() {
        if (_initialised) return;
        lock (lockObject) {
            if (_initialised) return;
            // Allocate the fixed-size backing arrays once; entries are indexed directly by key id.
            _keys = new KeyServiceRecord?[KeyService.MaxKeyCount];
            _keyMemory = new ReadOnlyMemory<char>[KeyService.MaxKeyCount];
            _keyBytes = new ReadOnlyMemory<byte>[KeyService.MaxKeyCount];
            _keySourceIds = new int[KeyService.MaxKeyCount];
            _keyCount = 0;

            foreach (var keyServiceItem in this.Value) {
                var keyIndex = keyServiceItem.KeySourceId;
                if (keyIndex < 0 || keyIndex >= KeyService.MaxKeyCount) {
                    throw new ArgumentOutOfRangeException(nameof(keyServiceItem.KeySourceId), $"KeySourceId must be between 0 and {KeyService.MaxKeyCount - 1} (0-255)");
                }

                // Validate the entry (type-specific settings)
                keyServiceItem.Validate();

                var parsedKeyHandleMask = ParseKeyHandleMask(keyServiceItem.KeyHandleMask, keyIndex);
                var sourceBytes = Encoding.UTF8.GetBytes(keyServiceItem.Value!);

                // Build the runtime record according to the configured key type.
                KeyServiceRecord keyServiceRecord;
                if (keyServiceItem.Type == KeyType.Block) {
                    keyServiceRecord = new KeyServiceRecord(
                        keyIndex,
                        keyServiceItem.Value!,
                        sourceBytes,
                        parsedKeyHandleMask,
                        KeyType.Block,
                        keyServiceItem.BlockSettings,
                        null,
                        null
                    );
                }
                else if (keyServiceItem.Type == KeyType.Matrix) {
                    // Matrix keys carry their own matrix-specific validation and settings.
                    keyServiceItem.MatrixSettings!.Validate(sourceBytes.Length);
                    var matrixWalker = new MatrixKeyWalker(keyServiceItem.MatrixSettings, sourceBytes);

                    keyServiceRecord = new KeyServiceRecord(
                        keyIndex,
                        keyServiceItem.Value!,
                        sourceBytes,
                        parsedKeyHandleMask,
                        KeyType.Matrix,
                        null,
                        keyServiceItem.MatrixSettings,
                        matrixWalker
                    );
                }
                else {
                    throw new InvalidOperationException($"Unknown KeyType {keyServiceItem.Type} for key {keyIndex}.");
                }

                _keys[keyIndex] = keyServiceRecord;
                _keyMemory[keyIndex] = keyServiceRecord.Value.AsMemory();
                _keyBytes[keyIndex] = keyServiceRecord.SourceBytes;
                _keySourceIds[_keyCount] = keyIndex;
                _keyCount++;
            }
            _initialised = true;
        }
    }

    /// <summary>
    /// Parses and validates the configured key-id mask before the runtime cache is created.
    /// </summary>
    /// <param name="keyIdMaskText">The string representation of the key ID mask to parse.</param>
    /// <param name="keyId">The ID of the key this mask belongs to, used for error reporting.</param>
    /// <returns>
    /// The parsed integer value of the key ID mask.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when:
    /// <list type="bullet">
    /// <item><description>The <paramref name="keyIdMaskText"/> cannot be parsed as an integer.</description></item>
    /// <item><description>The parsed value is outside the valid range (0 to <see cref="KeyService.MaxKeyIdMaskValue"/>).</description></item>
    /// <item><description>The mask sets any of the reserved key-id bits (lowest bits defined by <see cref="KeyService.keyPositionSize"/>).</description></item>
    /// </list>
    /// </exception>
    /// <remarks>
    /// The key ID mask must not overlap with the bits reserved for the key ID itself to prevent conflicts.
    /// </remarks>
    private static ulong ParseKeyHandleMask(string keyHandleMaskText, int keySourceId) {
        if (ulong.TryParse(keyHandleMaskText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedKeyHandleMask) == false) {
            throw new InvalidOperationException($"Invalid KeyHandleMask value '{keyHandleMaskText}' for key source '{keySourceId}'.");
        }

        if ((parsedKeyHandleMask & KeyService.keySourceIdMask) != 0) {
            throw new InvalidOperationException($"KeyHandleMask value '{keyHandleMaskText}' for key source '{keySourceId}' must not set the lowest 8 KeySourceId bits.");
        }

        return parsedKeyHandleMask;
    }

    /// <summary>
    /// Gets the key service configuration value.
    /// </summary>
    /// <value>
    /// The <see cref="KeyServiceConfig"/> instance containing all configured key entries.
    /// </value>
    public KeyServiceConfig Value { get; }
}

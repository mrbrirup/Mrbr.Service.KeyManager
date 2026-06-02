using Microsoft.Extensions.Options;
using Mrbr.Service.KeyManager.Services;
using Mrbr.Extensions.Configuration.Text;
using System.Globalization;
using static Mrbr.Service.KeyManager.Services.KeyService;

namespace Mrbr.Service.KeyManager.Configuration;
public sealed class KeyServiceOptions : IOptions<KeyServiceConfig> {
    private static KeyServiceRecord?[] _keys = default!;
    private static ReadOnlyMemory<char>[] _keyMemory = default!;
    private static int _keyCount = 0;
    private static bool _initialised = false;
    private static readonly Lock lockObject = new();
    public KeyServiceOptions(IOptions<KeyServiceConfig> options) {
        this.Value = options.Value;

        foreach (var keyServiceEntry in Value) {
            keyServiceEntry.Value = keyServiceEntry.Value.ParseConfig();
            keyServiceEntry.KeyIdMask = (keyServiceEntry.KeyIdMask ?? "0").ParseConfig();
        }


        if (_initialised == false) { Initialise(); }
    }

    public static KeyServiceRecord?[] Keys => _keys;
    public static ReadOnlyMemory<char>[] KeyMemory => _keyMemory;
    public static int KeyCount => _keyCount;

    public static bool DeleteKey(int keyId) {
        lock (lockObject) {
            if (keyId < 0 || keyId >= KeyService.MaxKeyCount) {
                throw new ArgumentOutOfRangeException(nameof(keyId), $"Key Id must be between 0 and {KeyService.MaxKeyCount - 1}");
            }
            if (_keys[keyId] == null) return false; // Key does not exist

            _keys[keyId] = null;
            _keyMemory[keyId] = default;
            _keyCount--;
        }
        return true;
    }

    public static bool DeleteAllKeys() {
        lock (lockObject) {
            if (_keyCount > 0) {
                Array.Clear(_keys, 0, _keys.Length);
                Array.Clear(_keyMemory, 0, _keyMemory.Length);
                _keyCount = 0;
                return true;
            }
        }
        return false;
    }

    void Initialise() {
        if (_initialised) return;
        lock (lockObject) {
            if (_initialised) return;
            _keys = new KeyServiceRecord?[KeyService.MaxKeyCount];
            _keyMemory = new ReadOnlyMemory<char>[KeyService.MaxKeyCount];
            _keyCount = 0;

            foreach (var keyServiceItem in this.Value) {
                var keyIndex = keyServiceItem.Key;
                if (keyIndex < 0 || keyIndex >= KeyService.MaxKeyCount) {
                    throw new ArgumentOutOfRangeException(nameof(keyServiceItem.Key), $"Key Id must be between 0 and {KeyService.MaxKeyCount - 1}");
                }
                var parsedKeyIdMask = ParseKeyIdMask(keyServiceItem.KeyIdMask, keyIndex);
                var keyServiceRecord = new KeyServiceRecord(keyIndex, keyServiceItem.Value!, keyServiceItem.Value.Length - KeyService.MaxMaskLength, parsedKeyIdMask);
                _keys[keyIndex] = keyServiceRecord;
                _keyMemory[keyIndex] = keyServiceRecord.Value.AsMemory();
                _keyCount++;
            }
            _initialised = true;
        }
    }

    private static int ParseKeyIdMask(string keyIdMaskText, int keyId) {
        if (int.TryParse(keyIdMaskText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedKeyIdMask) == false) {
            throw new InvalidOperationException($"Invalid KeyIdMask value '{keyIdMaskText}' for key '{keyId}'.");
        }

        if (parsedKeyIdMask < 0 || parsedKeyIdMask > KeyService.MaxKeyIdMaskValue) {
            throw new InvalidOperationException($"KeyIdMask value '{keyIdMaskText}' for key '{keyId}' must be between 0 and {KeyService.MaxKeyIdMaskValue}.");
        }

        if ((parsedKeyIdMask & KeyService.keyIdMask) != 0) {
            throw new InvalidOperationException($"KeyIdMask value '{keyIdMaskText}' for key '{keyId}' must not set key-id bits (lowest {KeyService.keyPositionSize} bits). ");
        }

        return parsedKeyIdMask;
    }
    public KeyServiceConfig Value { get; }
}
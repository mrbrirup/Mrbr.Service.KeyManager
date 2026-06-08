#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
namespace Mrbr.Service.KeyManager.Configuration;

public sealed class KeyServiceEntry {
    public KeyServiceEntry() {

    }
    public KeyServiceEntry(int key, string value, string keyIdMask = "0") {
        Key = key;
        Value = value;
        KeyIdMask = keyIdMask;
    }
    public int Key { get; set; }
    public string Value { get; set; }
    public string KeyIdMask { get; set; } = "0";
}
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.



public class Rootobject {
    public Keyserviceentry[] KeyServiceEntries { get; set; }
}

public class Keyserviceentry {
    public int KeyIndex { get; set; }
    public Keymatrixsettings KeyMatrixSettings { get; set; } = default!;
}

public class Keymatrixsettings {
    public Keymatrixsetting KeyMatrixSetting { get; set; } = default!;
}

public class Keymatrixsetting {
    public int Width { get; set; }
    public int Height { get; set; }
    public int Depth { get; set; }
    public long VectorMask { get; set; }
    public long KeyMask { get; set; }
}

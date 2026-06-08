using System;
using System.Collections.Generic;
using System.Text;

namespace Mrbr.Service.KeyManager.Configuration;

public class KeyMatrixSettings {
    public const string SectionName = "KeyMatrixSettings";

    public int Width { get; set; }
    public int Height { get; set; }
    public int Depth { get; set; }

    // 64-bit mask for the vectors (covers up to 8 packed 8-bit or 5-bit numbers)
    public ulong VectorMask { get; set; }

    // 64-bit mask applied across the output keys
    public ulong KeyMask { get; set; }
}

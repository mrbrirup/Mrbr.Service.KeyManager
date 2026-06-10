using System.Reflection;
using Xunit.Sdk;

namespace Mrbr.Service.KeyManager.Tests;

/// <summary>
/// Provides repeated data rows for xUnit theory tests.
/// Each row passes the current iteration index (0-based).
/// </summary>
public sealed class RepeatDataAttribute(int count) : DataAttribute {
    private readonly int _count = count;

    public override IEnumerable<object[]> GetData(MethodInfo testMethod) {
        if (_count <= 0) {
            throw new ArgumentOutOfRangeException(nameof(count), "Repeat count must be greater than zero.");
        }

        for (int i = 0; i < _count; i++) {
            yield return [i];
        }
    }
}

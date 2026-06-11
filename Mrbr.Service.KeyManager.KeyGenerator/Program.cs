using Mrbr.Service.KeyManager.Utilities;

Label:
Console.Clear();
Console.WriteLine("Key Generator!");
Console.WriteLine();
Console.WriteLine("Generate 1D or 3D keys");
Console.WriteLine("0. Exit");
Console.WriteLine("1. 1D Key (Block)");
Console.WriteLine("2. 3D Key (Cube)");
Console.WriteLine();
var key = Console.ReadKey().Key;
string outputText = "";
if (key == ConsoleKey.D1) {
EnterBlockSize:
    Console.WriteLine("Generating 1D Key (Block)");
    Console.WriteLine("Enter Size");
    var blockSize = Console.ReadLine();
    if (int.TryParse(blockSize, out var blockSizeValue) == false || blockSizeValue <= 0) {
        Console.WriteLine("Invalid input. Please enter a valid positive integer for block size.");
        goto EnterBlockSize;
    }
    outputText = KeyGenerator.GenerateRandomString(blockSizeValue);
}
else if (key == ConsoleKey.D2) {
EnterSize:
    Console.WriteLine("Generating 3D Key (Cube)");
    Console.WriteLine("Enter Width, Height, Depth");
    var sizes = Console.ReadLine() ?? "";
    var sizeArray = sizes.Split(',');
    if (sizeArray.Length != 3) {
        Console.WriteLine("Invalid input. Please enter three comma-separated values for width, height, and depth.");
        goto EnterSize;
    }
    var values = sizeArray.Select(x => int.TryParse(x.Trim(), out var result) ? result : -1).ToArray();
    if (values.Select(x => x > 0).Any() == false) {
        Console.WriteLine("Invalid input. Please enter valid positive integers for width, height, and depth.");
        goto EnterSize;
    }
    var outputSize = values.Aggregate(1, (acc, val) => acc * val);
    Console.WriteLine($"Total size: {outputSize}");
    outputText = KeyGenerator.GenerateRandomString(outputSize);
}
else if (key == ConsoleKey.D0) {
    Console.WriteLine("Exiting...");
    return;
}
else {
    goto Label;
}
Console.WriteLine(outputText);
Console.ReadLine();
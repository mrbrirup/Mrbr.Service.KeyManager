param(
    [Parameter(Position = 0)]
    [string]$ProjectFile,

    [Parameter(Position = 1)]
    [string]$NugetRoot = "C:\dev\nuget"
)

if ([string]::IsNullOrWhiteSpace($ProjectFile)) {
    $projectFiles = Get-ChildItem -Path (Get-Location) -Filter *.csproj -File -Recurse

    if ($projectFiles.Count -eq 1) {
        $ProjectFile = $projectFiles[0].FullName
    }
    else {
        throw "Expected exactly one project file when -ProjectFile is not supplied. Found $($projectFiles.Count)."
    }
}

if (-not (Test-Path -LiteralPath $ProjectFile)) {
    throw "Project file not found: $ProjectFile"
}

$projectName = [System.IO.Path]::GetFileNameWithoutExtension($ProjectFile)
$packageSource = Join-Path $NugetRoot $projectName

if (-not (Test-Path -LiteralPath $packageSource)) {
    New-Item -ItemType Directory -Path $packageSource -Force | Out-Null
}

# 1. Create a unique, randomized temporary folder name
$TmpDir = Join-Path $env:TEMP ([Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

try {
    # 2. Pack directly into the unique temporary folder
    dotnet pack "$ProjectFile" -c Release -o $TmpDir

    if ($LASTEXITCODE -ne 0) {
        throw "dotnet pack failed for project: $ProjectFile"
    }

    # 3. Push all packages found inside that temporary folder
    dotnet nuget push "$TmpDir\*.nupkg" -s "$packageSource"

    if ($LASTEXITCODE -ne 0) {
        throw "dotnet nuget push failed for source: $packageSource"
    }
}
finally {
    # 4. Completely clean up and remove the temporary folder
    if (Test-Path -LiteralPath $TmpDir) {
        Remove-Item -Path $TmpDir -Force -Recurse
    }
}

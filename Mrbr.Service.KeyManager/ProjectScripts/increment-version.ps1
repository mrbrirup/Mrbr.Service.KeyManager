param(
    [Parameter(Position = 0)]
    [string]$Version,

    [Parameter(Position = 1)]
    [string]$ProjectFile
)

$defaultVersion = "1.0.0"

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

[xml]$projectXml = Get-Content -LiteralPath $ProjectFile -Raw

$propertyGroup = $projectXml.Project.PropertyGroup | Where-Object { $_.TargetFramework } | Select-Object -First 1
if (-not $propertyGroup) {
    $propertyGroup = $projectXml.CreateElement("PropertyGroup")
    [void]$projectXml.Project.AppendChild($propertyGroup)
}

function Set-OrAddPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$Group,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName,

        [Parameter(Mandatory = $true)]
        [string]$PropertyValue
    )

    $node = $Group.SelectSingleNode($PropertyName)
    if ($node) {
        $node.InnerText = $PropertyValue
    }
    else {
        $newNode = $Group.OwnerDocument.CreateElement($PropertyName)
        $newNode.InnerText = $PropertyValue
        [void]$Group.AppendChild($newNode)
    }
}

$existingVersion = $propertyGroup.SelectSingleNode("Version")
$versionToUse = $Version

if ([string]::IsNullOrWhiteSpace($versionToUse)) {
    if ($existingVersion -and -not [string]::IsNullOrWhiteSpace($existingVersion.InnerText)) {
        $versionToUse = $existingVersion.InnerText
    }
    else {
        $versionToUse = $defaultVersion
    }
}

$coreVersion = ($versionToUse -split "[-+]", 2)[0]
$numericParts = [System.Collections.Generic.List[string]]::new()

foreach ($part in ($coreVersion -split "\.")) {
    if (-not [string]::IsNullOrWhiteSpace($part)) {
        $numericParts.Add($part)
    }
}

while ($numericParts.Count -lt 4) {
    $numericParts.Add("0")
}

if ($numericParts.Count -gt 4) {
    $numericParts = [System.Collections.Generic.List[string]]($numericParts[0..3])
}

$assemblyVersionToUse = ($numericParts -join ".")
$fileVersionToUse = $assemblyVersionToUse

Set-OrAddPropertyValue -Group $propertyGroup -PropertyName "Version" -PropertyValue $versionToUse
Set-OrAddPropertyValue -Group $propertyGroup -PropertyName "PackageVersion" -PropertyValue $versionToUse
Set-OrAddPropertyValue -Group $propertyGroup -PropertyName "AssemblyVersion" -PropertyValue $assemblyVersionToUse
Set-OrAddPropertyValue -Group $propertyGroup -PropertyName "FileVersion" -PropertyValue $fileVersionToUse

$settings = New-Object System.Xml.XmlWriterSettings
$settings.Indent = $true
$settings.OmitXmlDeclaration = $true

$writer = [System.Xml.XmlWriter]::Create($ProjectFile, $settings)
$projectXml.Save($writer)
$writer.Close()

Write-Host "Updated '$ProjectFile' with Version=$versionToUse PackageVersion=$versionToUse AssemblyVersion=$assemblyVersionToUse FileVersion=$fileVersionToUse"

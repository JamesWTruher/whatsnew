############################
# TODO LIST
# - write code to fixup URLs in docs
############################

# This will return the available versions found on the disk.
# Optionally, it will construct the objects used in the script
# to display the what's new document.
function Get-AvailableVersion {
    param ( [switch]$urihashtable )

    $versions = foreach($filename in Get-ChildItem "$PSScriptRoot/relnotes") {
        $fileVersion = $filename -replace ".*(\d)(\d).*",'$1.$2'
        # fix up version 5.0 to 5.1
        $fileVersion = $fileVersion -replace "5.0","5.1"
        $fileVersion
    }

    if ( $urihashtable ) {
        $filenameBase = "What-s-New-in-PowerShell"
        $urlBase = 'https://docs.microsoft.com/powershell/scripting/whats-new'
        foreach ( $version in $versions ) {
            $fileVersion = $version -replace "\." -replace "51","50"
            if ( $fileVersion -eq "50" ) {
                $fileBase = "What-s-New-in-Windows-PowerShell-${fileVersion}"
            }
            else {
                $fileBase = "${filenameBase}-${fileVersion}"
            }
            @{
                # construct the hashtable
                version = $version
                path = Join-Path -Path $PSScriptRoot -ChildPath relnotes -Additional "${fileBase}.md"
                url = "${urlBase}/$fileBase".ToLower()
            }
        }
    }
    else {
        $versions | Sort-Object
    }
}

function TestVersion {
    param ( $version )
    $allowedVersions = Get-AvailableVersion
    if ( $allowedVersions -contains $version ) {
        return $true
    }
    throw ("only " + ( $allowedVersions -join ", "))
}


function Get-WhatsNew {
    [CmdletBinding(DefaultParameterSetName = 'ByVersion')]
    param (
        [Parameter(Position=0,ParameterSetName='ByVersion')]
        [Parameter(Position=0,ParameterSetName='CompareVersion')]
        [ValidateScript({TestVersion $_})]
        [string]$Version,

        [Parameter(Mandatory,ParameterSetName='CompareVersion')]
        [ValidateScript({TestVersion $_})]
        [string]$CompareVersion,

        [Parameter(Mandatory,ParameterSetName='AllVersions')]
        [switch]$All,

        [Parameter(Position=0,ParameterSetName='ByVersion')]
        [Alias('MOTD')]
        [switch]$Daily,

        [Parameter(ParameterSetName='ByVersion')]
        [switch]$Online
    )


    $versions = Get-AvailableVersion -uriHashtable


    if (0 -eq $Version) {
        $Version = [double]('{0}.{1}' -f $PSVersionTable.PSVersion.Major,$PSVersionTable.PSVersion.Minor)
    }

    # Resolve parameter set
    $mdfiles = @()
    if ($PsCmdlet.ParameterSetName -eq 'CompareVersion') {
        if ($Version -gt $CompareVersion) {
            $tempver = $CompareVersion
            $CompareVersion = $Version
            $Version = $tempver
        }
        foreach ($ver in $versions) {
            if (($ver.version -ge $Version) -and ($ver.version -le $CompareVersion)) {
                $mdfiles += $ver.path
            }
        }
    } elseif ($PsCmdlet.ParameterSetName -eq 'AllVersions') {
        $mdfiles = ($versions).path
    } else {
        $mdfiles = ($versions | Where-Object version -eq $Version).path
    }

    # Scan release notes for H2 blocks
    $endMarker = '<!-- end of content -->'
    foreach ($file in $mdfiles) {
        $mdtext = Get-Content $file -Encoding utf8
        $mdheaders = Select-String -Pattern '^##\s',$endMarker -Path $file

        $blocklist = @()

        foreach ($hdr in $mdheaders) {
            if ($hdr.Line -ne $endMarker) {
                $block = [PSCustomObject]@{
                    Name      = $hdr.Line.Trim()
                    StartLine = $hdr.LineNumber - 1
                    EndLine   = -1
                }
                $blocklist += $block
            } else {
                $blocklist[-1].EndLine = $hdr.LineNumber - 2
            }
        }
        if ($blocklist.Count -gt 0) {
            for ($x = 0; $x -lt $blocklist.Count; $x++) {
                if ($blocklist[$x].EndLine -eq -1) {
                    $blocklist[$x].EndLine = $blocklist[($x + 1)].StartLine - 1
                }
            }
        }

        if ($Daily) {
            $block = $blocklist | Get-Random -SetSeed (get-date -UFormat '%s')
            $mdtext[$block.StartLine..$block.EndLine]
            <# - Alternate ANSI output
            $mdtext[$block.StartLine..$block.EndLine] |
                ConvertFrom-Markdown -AsVT100EncodedString |
                Select-Object -ExpandProperty VT100EncodedString
            #>
        } elseif ($Online) {
            Start-Process ($versions | Where-Object version -eq $Version).url
        } else {
            foreach ($block in $blocklist) {
                $mdtext[$block.StartLine..$block.EndLine]
                <# - Alternate ANSI output
                $mdtext[$block.StartLine..$block.EndLine] |
                    ConvertFrom-Markdown -AsVT100EncodedString |
                    Select-Object -ExpandProperty VT100EncodedString
                #>
            }
        }
    }
}

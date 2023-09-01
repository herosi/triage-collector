@echo off

set indir=%~1
set outdir=%~2
set inifile=%~3
set codepage=%~4
set driveletter=%~5

set regindir=%indir%\Registry
set regoutdir=%outdir%\Registry
set recmdoutdir=%regoutdir%\EZTools
set rroutdir=%regoutdir%\RegRipper

setlocal enabledelayedexpansion

mkdir "%outdir%" 2> nul

if x"%inifile%" == x"" (
    set inifile=.\artifact_parser_helper.ini
)

:: parsers
call :GET_INI_VALUE "!inifile!" Parser MFTECmd_MFT
call :GET_INI_VALUE "!inifile!" Parser MFTECmd_MFT_TL
call :GET_INI_VALUE "!inifile!" Parser MFTECmd_Log
call :GET_INI_VALUE "!inifile!" Parser MFTECmd_J
call :GET_INI_VALUE "!inifile!" Parser MFTECmd_SDS
call :GET_INI_VALUE "!inifile!" Parser NLT_Log
call :GET_INI_VALUE "!inifile!" Parser NLT_J
call :GET_INI_VALUE "!inifile!" Parser EvtxECmd
call :GET_INI_VALUE "!inifile!" Parser HAYABUSA
call :GET_INI_VALUE "!inifile!" Parser RECmd
call :GET_INI_VALUE "!inifile!" Parser RegRipper
call :GET_INI_VALUE "!inifile!" Parser AmcacheParser
call :GET_INI_VALUE "!inifile!" Parser AppCompatCacheParser
call :GET_INI_VALUE "!inifile!" Parser SBECmd
call :GET_INI_VALUE "!inifile!" Parser SumECmd
call :GET_INI_VALUE "!inifile!" Parser SrumECmd
call :GET_INI_VALUE "!inifile!" Parser srumdump
call :GET_INI_VALUE "!inifile!" Parser PECmd
call :GET_INI_VALUE "!inifile!" Parser JLECmd
call :GET_INI_VALUE "!inifile!" Parser LECmd
call :GET_INI_VALUE "!inifile!" Parser RBCmd
call :GET_INI_VALUE "!inifile!" Parser WxTCmd
call :GET_INI_VALUE "!inifile!" Parser BrowsingHistoryView
call :GET_INI_VALUE "!inifile!" Parser WMI
call :GET_INI_VALUE "!inifile!" Parser THUMBCACHE
call :GET_INI_VALUE "!inifile!" Parser TASKS
call :GET_INI_VALUE "!inifile!" Parser BmcTools
call :GET_INI_VALUE "!inifile!" Parser Rdpieces

echo [*] Parser settings
echo                                     MFT with MFTECmd: %MFTECmd_MFT%
echo                         MFT with MFTECmd as timeline: %MFTECmd_MFT_TL%
echo                                $Logfile with MFTECmd: %MFTECmd_Log%
echo                              UsnJrnl:$J with MFTECmd: %MFTECmd_J%
echo                            $Secure:$SDS with MFTECmd: %MFTECmd_SDS%
echo                       $Logfile with NTFS Log Tracker: %NLT_Log%
echo                     UnsJrnl:$J with NTFS Log Tracker: %NLT_J%
echo                              Event log with EvtxECmd: %EvtxECmd%
echo                              Event log with hayabusa: %HAYABUSA%
echo                                  Registry with RECmd: %RECmd%
echo                             Registry with RegRipper3: %RegRipper%
echo                           AmCache with AmcacheParser: %AmcacheParser%
echo Shimcache (AppCompatCache) with AppCompatCacheParser: %AppCompatCacheParser%
echo                                 Shellbag with SBECmd: %SBECmd%
echo                                     Sum with SumECmd: %SumECmd%
echo                                   SRUM with SrumECmd: %SrumECmd%
echo                                 SRUM with srum-dump2: %srumdump%
echo                                  Prefetch with PECmd: %PECmd%
echo                                 Jumplist with JLECmd: %JLECmd%
echo                                    Recnet with LECmd: %LECmd%
echo                              $Recycle.bin with RBCmd: %RBCmd%
echo                         Windows Timeline with WxTCmd: %WxTCmd%
echo         Web Browser History with BrowsingHistoryView: %BrowsingHistoryView%
echo                WMI Event Subscription with flare-wmi: %WMI%
echo     Thumbcache and Icon cache with Thumbcache viewer: %THUMBCACHE%
echo                    Tasks folders with task_parser.py: %TASKS%
echo                          RDP cache with bmc-tools.py: %BmcTools%
echo                bmc-tools.py results with rdpieces.pl: %Rdpieces%
echo.

echo [*] RECmd settings
call :GET_INI_VALUE "!inifile!" RECmd REBatchFolder
call :GET_INI_VALUE "!inifile!" RECmd REBatches
echo RECmd's batch folder: %REBatchFolder%
echo RECmd's batch files: %REBatches%
echo.

call :GET_INI_VALUE "!inifile!" Common codepage
if x"%codepage%" == x"" (
    call :CMDRESULT "chcp" chcpresult
    :: get the last integer
    for %%c in (!chcpresult!) do (
        set codepage=%%c
    )
)

echo [*] codepage = %codepage%
echo.

if x"%codepage%" == x"" (
    call :CMDRESULT "chcp" chcpresult
    :: get the last integer
    for %%c in (!chcpresult!) do (
        set codepage=%%c
    )
)

if x"%driveletter%" == x"" (
    set driveletter=C
)

set CP_OPT=
for /F "tokens=* USEBACKQ" %%l in (`lecmd`) do (
    echo "%%l"|findstr /i /C:"--cp <cp>">nul
    if !errorlevel! equ 0 (
        set CP_OPT=--cp %codepage%
    )
)

set CP_OPT_JLECMD=
for /F "tokens=* USEBACKQ" %%l in (`jlecmd`) do (
    echo "%%l"|findstr /i /C:"--cp <cp>">nul
    if !errorlevel! equ 0 (
        set CP_OPT_JLECMD=--cp %codepage%
    )
)


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Parsing Artifacts with Analysis Tools

if exist "%indir%\Evtx" (
    mkdir "%outdir%\Evtx" 2> nul
    if /I x"%EvtxECmd%" == x"true" (
        echo [+] Parse event logs with EvtxECmd
        dir /b "%outdir%\Evtx" | findstr /i /l "_EvtxECmd_Output.csv">nul
        if !errorlevel! neq 0 (
            echo EvtxECmd -d "%indir%\Evtx" --csv "%outdir%\Evtx"
            EvtxECmd -d "%indir%\Evtx" --csv "%outdir%\Evtx" > nul
        ) else (
            echo [-] Skipped parsing event logs with EvtxECmd
        )
        echo.
    )

    echo [+] Parse event logs with hayabusa
    if /I x"%HAYABUSA%" == x"true" (
        if not exist "%outdir%\Evtx\hayabusa_default.csv" (
            echo hayabusa.exe csv-timeline -d "%indir%\Evtx" -o "%outdir%\Evtx\hayabusa_default.csv"
            hayabusa.exe csv-timeline -d "%indir%\Evtx" -o "%outdir%\Evtx\hayabusa_default.csv"
        ) else (
            echo [-] Skipped parsing event logs with hayabusa
        )
        if not exist "%outdir%\Evtx\hayabusa_IIJ.csv" (
            echo hayabusa.exe csv-timeline -d "%indir%\Evtx" -r C:\tools\hayabusa_rules_by_IIJ -o "%outdir%\Evtx\hayabusa_IIJ.csv"
            hayabusa.exe csv-timeline -d "%indir%\Evtx" -r C:\tools\hayabusa_rules_by_IIJ -o "%outdir%\Evtx\hayabusa_IIJ.csv"
        )
        echo.
    )
)

if exist "%indir%\Prefetch" (
    if /I x"%PECmd%" == x"true" (
        echo [+] Parse Prefetch files with PECmd
        dir /b "%outdir%" | findstr /i /l "_PECmd_Output.csv">nul
        if !errorlevel! neq 0 (
            echo PECmd -d "%indir%\Prefetch" --csv "%outdir%"
            PECmd -d "%indir%\Prefetch" --csv "%outdir%" > nul
        ) else (
            echo [-] Skipped parsing Prefetch files with PECmd
        )
        echo.
    )
)

if exist "%indir%\recent" (
    if /I x"%LECmd%" == x"true" (
        echo [+] Parse Recent folders with LECmd
        dir /b "%outdir%" | findstr /i /l "_LECmd_Output.csv">nul
        if !errorlevel! neq 0 (
            echo LECmd -d "%indir%\recent" --csv "%outdir%
            LECmd -d "%indir%\recent" --csv "%outdir%" %CP_OPT% > nul
        ) else (
            echo [-] Skipped parsing Recent folders with LECmd
        )
        echo.
    )

    if /I x"%JLECmd%" == x"true" (
        echo [+] Parse Jump list with JLECmd
        dir /b "%outdir%" | findstr /i /l "_AutomaticDestinations.csv _CustomDestinations.csv">nul
        if !errorlevel! neq 0 (
            echo JLECmd -d "%indir%\recent" --csv "%outdir% %CP_OPT_JLECMD%
            JLECmd -d "%indir%\recent" --csv "%outdir%" %CP_OPT_JLECMD% > nul
        ) else (
            echo [-] Skipped parsing Jump list with JLECmd
        )
        echo.
    )
)

if exist "%indir%\RecycleBin" (
    if /I x"%RBCmd%" == x"true" (
        echo [+] Parse $Recycle.Bin with RBCmd
        dir /b "%outdir%" | findstr /i /l "_RBCmd_Output.csv">nul
        if !errorlevel! neq 0 (
            echo RBCmd -d "%indir%\RecycleBin" --csv "%outdir%
            RBCmd -d "%indir%\RecycleBin" --csv "%outdir%" > nul
        ) else (
            echo [-] Skipped parsing $Recycle.Bin with RBCmd
        )
        echo.
    )
)

if exist "%indir%\sum" (
    if /I x"%SumECmd%" == x"true" (
        echo [+] Parse SUM with SumECmd
        if not exist "%outdir%\sum" (
            echo [+] Backup SUM related files first to fix the database up
            ROBOCOPY "%indir%\sum" "%outdir%\sum" /E /COPY:DT /DCOPY:T > nul
            attrib -r "%outdir%\sum\*.*" /s
            pushd "%outdir%\sum"
            esentutl.exe /r svc /i > nul
            for /R "%outdir%\sum" %%f in (*) do (
                echo %%f|findstr /i /l ".mdb">nul
                if !errorlevel! equ 0 (
                    esentutl.exe /p "%%~nxf" /o > nul
                )
            )
            popd

            echo [+] Parse SUM with SumECmd
            echo SumECmd -d "%outdir%\sum" --csv "%outdir%\sum"
            SumECmd -d "%outdir%\sum" --csv "%outdir%\sum" > nul
        ) else (
            echo [-] Skipped parsing SUM with SumECmd
        )
        echo.
    )
)

if exist "%indir%\tasks" (
    if /I x"%TASKS%" == x"true" (
        echo [+] Parse tasks
        if not exist "%outdir%\tasks.csv" (
            echo task_parser.py "%indir%\tasks" ^> "%outdir%\tasks.csv"
            task_parser.py "%indir%\tasks" > "%outdir%\tasks.csv"
        ) else (
            echo [-] Skipped parsing tasks
        )
        echo.
    )
)

if exist "%indir%\tasksWow64" (
    if /I x"%TASKS%" == x"true" (
        echo [+] Parse tasks on SysWoW64
        if not exist "%outdir%\tasksWow64.csv" (
            echo task_parser.py "%indir%\tasksWow64" ^> "%outdir%\tasksWow64.csv"
            task_parser.py "%indir%\tasksWow64" > "%outdir%\tasksWow64.csv"
        ) else (
            echo [-] Skipped parsing tasks on SysWoW64 
        )
        echo.
    )
)

if exist "%indir%\Web" (
    if /I x"%BrowsingHistoryView%" == x"true" (
        set i=0
        for /R "%indir%\Web" %%b in (.) do (
            set WEBBROWSER[!i!]=%%~nxb
            set /a i=i+1
        )
        if !i! gtr 0 (
            echo [+] Parse Web browser histories with BrowsingHisotryView
            mkdir "%outdir%\Web"  2> nul
        )
        for /l %%n in (1,1,!i!) do (
            if not x"!WEBBROWSER[%%n]!" == x"" (
                set WBPATH=%indir%\Web\!WEBBROWSER[%%n]!
                set WB=!WEBBROWSER[%%n]!
                for %%f in ("!WBPATH!"\*) do (
                    echo %%~nxf|findstr /i /l "_WebCacheV01.dat _History _places.sqlite">nul
                    if !errorlevel! equ 0 (
                        echo [+] Parse %%~nxf for !WB! with BrowsingHisotryView
                        if not exist "%outdir%\Web\!WB!_%%~nxf.csv" (
                            if x"!WB!" == x"IE10_Edge" (
                                set WBOPT=/CustomFiles.IE10Files
                            ) else if x"!WB!" == x"Edge" (
                                set WBOPT=/CustomFiles.ChromeFiles
                            ) else if x"!WB!" == x"Chrome" (
                                set WBOPT=/CustomFiles.ChromeFiles
                            ) else if x"!WB!" == x"Firefox" (
                                set WBOPT=/CustomFiles.FirefoxFiles
                            )
                            echo browsinghistoryview.exe /stab "%outdir%\Web\!WB!_%%~nxf.csv" /VisitTimeFilterType 1 !WBOPT! "%%f"
                            browsinghistoryview.exe /stab "%outdir%\Web\!WB!_%%~nxf.csv" /VisitTimeFilterType 1 !WBOPT! "%%f"
                        ) else (
                            echo [-] Skipped parsing %%~nxf for !WB! with BrowsingHisotryView
                        )
                        echo.
                    )
                )
            )
        )
        echo.
    )
)

if exist "%indir%\iconcache" if /I x"%THUMBCACHE%" == x"true" (
    for /R "%indir%\iconcache" %%f in (.) do (
        if not "%%~nxf" == "iconcache" if not "%%~nxf" == "NotifyIcon" (
            if not exist "%outdir%\iconcache\%%~nxf" (
                echo [+] Parse thumbnail and icon caches for %%~nxf with Thumbcache Viewer CMD
                mkdir "%outdir%\iconcache\%%~nxf" 2> nul
                echo thumbcache_viewer_cmd.exe -c -d "%%f" -o "%outdir%\iconcache\%%~nxf"
                thumbcache_viewer_cmd.exe -c -d "%%f" -o "%outdir%\iconcache\%%~nxf" > nul
            ) else (
                echo [-] Skipped parsing thumbnail and icon caches for %%~nxf with Thumbcache Viewer CMD
            )
            echo.
        )
    )
)

if exist "%indir%\WMI" if /I x"%WMI%" == x"true" (
    echo [+] Parse WMI Event Subscription with flare-wmi
    if not exist "%outdir%\WMI_Binding.txt" (
        echo python dump_class_instance.py win7 "%indir%\WMI" "root\subscription" "__FilterToConsumerBinding" ^> "%outdir%\WMI_Binding.txt"
        python dump_class_instance.py win7 "%indir%\WMI" "root\subscription" "__FilterToConsumerBinding" > "%outdir%\WMI_Binding.txt"
    ) else (
        echo [-] Skipped parsing WMI Event Subscription for __FilterToConsumerBinding
    )
    if not exist "%outdir%\WMI_EventFilter.txt" (
        echo python dump_class_instance.py win7 "%indir%\WMI" "root\subscription" "__EventFilter" ^> "%outdir%\WMI_EventFilter.txt"
        python dump_class_instance.py win7 "%indir%\WMI" "root\subscription" "__EventFilter" > "%outdir%\WMI_EventFilter.txt"
    ) else (
        echo [-] Skipped parsing WMI Event Subscription for __EventFilter
    )
    if not exist "%outdir%\WMI_CmdLineEventConsumer.txt" (
        echo python dump_class_instance.py win7 "%indir%\WMI" "root\subscription" "CommandLineEventConsumer" ^> "%outdir%\WMI_CmdLineEventConsumer.txt"
        python dump_class_instance.py win7 "%indir%\WMI" "root\subscription" "CommandLineEventConsumer" > "%outdir%\WMI_CmdLineEventConsumer.txt"
    ) else (
        echo [-] Skipped parsing WMI Event Subscription for CommandLineEventConsumer
    )
    if not exist "%outdir%\WMI_ActScriptEventConsumer.txt" (
        echo python dump_class_instance.py win7 "%indir%\WMI" "root\subscription" "ActiveScriptEventConsumer" ^> "%outdir%\WMI_ActScriptEventConsumer.txt"
        python dump_class_instance.py win7 "%indir%\WMI" "root\subscription" "ActiveScriptEventConsumer" > "%outdir%\WMI_ActScriptEventConsumer.txt"
    ) else (
        echo [-] Skipped parsing WMI Event Subscription for ActiveScriptEventConsumer
    )
    echo.
)

if exist "%indir%\WinTimeline" if /I x"%WxTCmd%" == x"true" (
    if not exist "%outdir%\WinTimeline" (
        mkdir "%outdir%\WinTimeline" 2> nul
        for /R "%indir%\WinTimeline" %%f in (.) do (
            if exist "%%f\ActivitiesCache.db" (
                echo [+] Parse Windows Timeline for %%~nxf with WxTCmd
                echo WxTCmd -f "%%f\ActivitiesCache.db" --csv "%outdir%\WinTimeline"
                WxTCmd -f "%%f\ActivitiesCache.db" --csv "%outdir%\WinTimeline" > nul
                echo.
            )
        )
    )
)

if exist "%indir%\Registry" (
    echo [*] Processing registry hives

    mkdir "%regoutdir%" 2> nul
    mkdir "%rroutdir%" 2> nul
    mkdir "%recmdoutdir%" 2> nul

    if /I x"%RECmd%" == x"true" (
        echo [+] Process all registry hives with RECmd
        for %%b in (%REBatches%) do (
            dir /b "%recmdoutdir%" | findstr /i /l "_RECmd_Batch_%%b_Output.csv">nul
            if !errorlevel! neq 0 (
                echo [+] Parse all registry hives with %%b.reb with RECmd
                echo recmd --recover true --bn "%REBatchFolder%\%%b.reb" -d "%regindir%" --csv "%recmdoutdir%"
                recmd --recover true --bn "%REBatchFolder%\%%b.reb" -d "%regindir%" --csv "%recmdoutdir%" > nul
            ) else (
                echo [-] Skipped parsing all registry hives with %%b.reb with RECmd
            )
            echo.
        )
    )

    if /I x"%SBECmd%" == x"true" (
        echo [+] Process all registry hives with SBECmd
        if not exist "%recmdoutdir%\shellbag" (
            echo [+] Parse all registry hives with SBECmd
            mkdir "%recmdoutdir%\shellbag" 2> nul
            echo SBECmd -d "%regindir%" --csv "%recmdoutdir%\shellbag"
            SBECmd -d "%regindir%" --csv "%recmdoutdir%\shellbag" > nul
        ) else (
            echo [-] Skipped parsing all registry hives with SBECmd
        )
        echo.
    )

    echo [+] Process each registry hive
    for /R "%regindir%" %%f in (*) do (
        echo "%%f"|findstr /i /R "\\txr\\ \.log[0-9]">nul
        if !errorlevel! neq 0 (
            if /I x"%RegRipper%" == x"true" (
                :: execute regripper
                if not exist "%rroutdir%\%%~nxf_rip.txt" (
                    echo [+] Parse %%~nxf with RegRipper
                    echo rip -r "%%f" -a ^> "%rroutdir%\%%~nxf_rip.txt"
                    rip -r "%%f" -a > "%rroutdir%\%%~nxf_rip.txt" 2>nul
                    echo rip -r "%%f" -aT ^> "%rroutdir%\%%~nxf_rip_tn.csv"
                    rip -r "%%f" -aT > "%rroutdir%\%%~nxf_rip_tn.csv" 2>nul
                ) else (
                    echo [-] Skipped parsing %%~nxf with RegRipper
                )
                echo.
            )

            if /I x"%RECmd%" == x"true" (
                echo "%%~nxf"|findstr /i /R ".*ntuser.dat .*usrclass.dat">nul
                if !errorlevel! equ 0 (
                    :: execute recmd
                    echo "%%~nxf"|findstr /i /l "_">nul
                    if !errorlevel! equ 0 (
                        call :SPLIT "%%~nxf" _ 1 user
                        set useroutdir=%recmdoutdir%\users\!user!
                        mkdir "!useroutdir!" 2> nul
                    ) else (
                        set useroutdir=%recmdoutdir%\users
                        mkdir "!useroutdir!" 2> nul
                    )
                    for %%b in (%REBatches%) do (
                        dir /b "!useroutdir!" | findstr /i /l "%%~nxf_%%b.finished"
                        echo dir /b "!useroutdir!" | findstr /i /l "%%~nxf_%%b.finished"
                        dir /b "!useroutdir!" | findstr /i /l "%%~nxf_%%b.finished">nul
                        if !errorlevel! neq 0 (
                            echo [+] Parse %%~nxf with %%b.reb with RECmd
                            echo recmd --recover true --bn "%REBatchFolder%\%%b.reb" -f "%%f" --csv "!useroutdir!"
                            recmd --recover true --bn "%REBatchFolder%\%%b.reb" -f "%%f" --csv "!useroutdir!" > nul
                            type nul > "!useroutdir!\%%~nxf_%%b.finished"
                        ) else (
                            echo [-] Skipped parsing %%~nxf with %%b.reb with RECmd
                        )
                        echo.
                    )
                )

                echo "%%~nxf"|findstr /i /l "software">nul
                if !errorlevel! equ 0 (
                    mkdir "%recmdoutdir%\software" 2> nul
                    for %%b in (%REBatches%) do (
                        dir /b "%recmdoutdir%\software" | findstr /i /l "_RECmd_Batch_%%b_Output.csv">nul
                        if !errorlevel! neq 0 (
                            echo [+] Parse %%~nxf with %%b.reb with RECmd
                            echo recmd --recover true --bn "%REBatchFolder%\%%b.reb" -f "%%f" --csv "%recmdoutdir%\software"
                            recmd --recover true --bn "%REBatchFolder%\%%b.reb" -f "%%f" --csv "%recmdoutdir%\software" > nul
                        ) else (
                            echo [-] Skipped parsing %%~nxf with %%b.reb with RECmd
                        )
                        echo.
                    )
                )

                echo "%%~nxf"|findstr /i /l "system">nul
                if !errorlevel! equ 0 (
                    mkdir "%recmdoutdir%\system" 2> nul
                    for %%b in (%REBatches%) do (
                        dir /b "%recmdoutdir%\system" | findstr /i /l "_RECmd_Batch_%%b_Output.csv">nul
                        if !errorlevel! neq 0 (
                            echo [+] Parse %%~nxf with %%b.reb with RECmd
                            echo recmd --recover true --bn "%REBatchFolder%\%%b.reb" -f "%%f" --csv "%recmdoutdir%\system"
                            recmd --recover true --bn "%REBatchFolder%\%%b.reb" -f "%%f" --csv "%recmdoutdir%\system" > nul
                        ) else (
                            echo [-] Skipped parsing %%~nxf with %%b.reb with RECmd
                        )
                        echo.
                    )

                    dir /b "%recmdoutdir%" | findstr /i /l "_SYSTEM_AppCompatCache.csv">nul
                    if !errorlevel! neq 0 (
                        echo [+] Parse %%~nxf with AppCompatCacheParser
                        echo AppCompatCacheParser -f "%%f" --csv "%recmdoutdir%"
                        AppCompatCacheParser -f "%%f" --csv "%recmdoutdir%" > nul
                    ) else (
                        echo [-] Skipped parsing %%~nxf with AppCompatCacheParser
                    )
                    echo.
                )

                echo "%%~nxf"|findstr /i /l "amcache.hve">nul
                if !errorlevel! equ 0 (
                    dir /b "%recmdoutdir%" | findstr /i /r "_Amcache_.*\.csv">nul
                    if !errorlevel! neq 0 (
                        echo [+] Parse %%~nxf with AmcacheParser
                        echo AmcacheParser -f "%%f" --csv "%recmdoutdir%"
                        AmcacheParser -f "%%f" --csv "%recmdoutdir%" > nul
                    ) else (
                        echo [-] Skipped parsing %%~nxf with AmcacheParser
                    )
                    echo.
                )
            )
        ) else (
            echo [-] Skipped parsing %%f
        )
    )
    echo.
)

if exist "%indir%\srum" (
    if exist "%indir%\srum\SRUDB.dat" (
        if not exist "%outdir%\srum" (
            set res=F
            if /I x"%srumdump%" == x"true" rest=T
            if /I x"%SrumECmd%" == x"true" rest=T
            if "!res!"=="T" (
                echo [+] Parse SRUM
                echo [+] Backup SRUM related files first to fix the database up
                ROBOCOPY "%indir%\srum" "%outdir%\srum" /E /COPY:DT /DCOPY:T > nul
                attrib -r "%outdir%\srum\*.*" /s
                pushd "%outdir%\srum"
                esentutl.exe /r sru /i > nul
                esentutl.exe /p SRUDB.dat /o > nul
                popd
            )

            if /I x"%srumdump%" == x"true" (
                echo [+] Parse SRUM with srum-dump2

                set SOFT_HIVE=
                if exist "%indir%\Registry\SOFTWARE" (
                    set SOFT_HIVE=-r "%indir%\Registry\SOFTWARE"
                )
                echo srum_dump2 -i "%outdir%\srum\SRUDB.dat" -o "%outdir%\srum.xlsx" -t "SRUM_TEMPLATE3.xlsx" !SOFT_HIVE!
                srum_dump2 -i "%outdir%\srum\SRUDB.dat" -o "%outdir%\srum.xlsx" -t "SRUM_TEMPLATE3.xlsx" !SOFT_HIVE! > nul
                echo.
            )

            if /I x"%SrumECmd%" == x"true" (
                echo [+] Parse SRUM with SrumECmd
                echo SrumECmd -f "%outdir%\srum\SRUDB.dat" --csv "%outdir%" !SOFT_HIVE!
                SrumECmd -f  "%outdir%\srum\SRUDB.dat" --csv "%outdir%" !SOFT_HIVE! > nul
                echo.
            )
        ) else (
            echo [-] Skipped parsing SRUM
        )
    )
)

if exist "%indir%\NTFS" (
    echo [*] Processing NTFS related artifacts
    mkdir "%outdir%\NTFS" 2> nul

    :: find MFT for $J
    set MFT_FILE=
    set MFT_OPT=
    for /R "%indir%\NTFS" %%f in (*) do (
        echo %%~nxf|findstr /i /l "$MFT">nul
        if !errorlevel! equ 0 (
            set MFT_OPT=-m "%%f"
            set MFT_FILE=%%f
        )
    )

    for /R "%indir%\NTFS" %%f in (*) do (
        echo [+] Processing %%~nxf

        :: process MFT
        echo %%~nxf|findstr /i /l "$MFT">nul
        if !errorlevel! equ 0 (
            set MFT_FILE=%%f
            if /I x"%MFTECmd_MFT%" == x"true" (
                echo [+] Parse %%~nxf with MFTECmd
                dir /b "%outdir%\NTFS" | findstr /i /l "_MFTECmd_$MFT_Output.csv">nul
                if !errorlevel! neq 0 (
                    echo MFTECmd -f "%%f" --at true --rs true --csv "%outdir%\NTFS"
                    MFTECmd -f "%%f" --at true --rs true --csv "%outdir%\NTFS" > nul
                    echo.
                ) else (
                    echo [-] Skipped parsing %%~nxf with MFTECmd
                )
            )

            if /I x"%MFTECmd_MFT_TL%" == x"true" (
                dir /b "%outdir%\NTFS" | findstr /i /l "_MFTECmd_$MFT_Output.body">nul
                if !errorlevel! neq 0 (
                    echo MFTECmd -f "%%f" --bdl %driveletter% --rs true --body "%outdir%\NTFS"
                    MFTECmd -f "%%f" --bdl %driveletter% --rs true --body "%outdir%\NTFS" > nul
                    echo.
                ) else (
                    echo [-] Skipped parsing %%~nxf as a body format with MFTECmd
                )

                :: covert body to csv
                set BODY_FOUND=0
                for /R "%outdir%\NTFS" %%m in (*) do (
                    echo %%~nxm|findstr /i /l "_MFTECmd_$MFT_Output.body"|findstr /v /i /l "_MFTECmd_$MFT_Output.body.csv">nul
                    if !errorlevel! equ 0 if !BODY_FOUND! equ 0 (
                        if not exist "%outdir%\NTFS\%%~nxm.csv" (
                            echo [+] Convert %%~nxm into a timeline format
                            echo mactime.pl -b "%%m" -d -y ^> "%outdir%\NTFS\%%~nxm.csv"
                            mactime.pl -b "%%m" -d -y > "%outdir%\NTFS\%%~nxm.csv"
                            set BODY_FOUND=1
                            echo.
                        ) else (
                            echo [-] Skipped converting %%~nxm into a timeline format
                        )
                    )
                )
            )
        )

        :: parse $J and $SDS
        echo %%~nxf|findstr /i /l "$UsnJrnl-$J $SECURE-$SDS">nul
        if !errorlevel! equ 0 (
            echo [+] Parse %%~nxf with MFTECmd
            echo %%~nxf|findstr /i /l "$SECURE-$SDS">nul
            if !errorlevel! equ 0 (
                dir /b "%outdir%\NTFS" | findstr /i /l "_MFTECmd_$SDS_Output.csv">nul
                if !errorlevel! neq 0 (
                    if /I x"%MFTECmd_SDS%" == x"true" (
                        echo MFTECmd -f "%%f" --rs true --csv "%outdir%\NTFS"
                        MFTECmd -f "%%f" --rs true --csv "%outdir%\NTFS" > nul
                        echo.
                    ) else (
                        echo [-] Skipped parsing %%~nxf with MFTECmd
                    )
                ) else (
                    echo [-] Skipped parsing %%~nxf with MFTECmd
                )
            ) else (
                dir /b "%outdir%\NTFS" | findstr /i /l "_MFTECmd_$J_Output.csv">nul
                if !errorlevel! neq 0 (
                    if /I x"%MFTECmd_J%" == x"true" (
                        echo MFTECmd -f "%%f" !MFT_OPT! --rs true --csv "%outdir%\NTFS"
                        MFTECmd -f "%%f" !MFT_OPT! --rs true --csv "%outdir%\NTFS" > nul
                       echo.
                    ) else (
                        echo [-] Skipped parsing %%~nxf with MFTECmd
                    )
                ) else (
                    echo [-] Skipped parsing %%~nxf with MFTECmd
                )
            )
        )

        :: parse $J
        if /I x"%NLT_J%" == x"true" (
            echo %%~nxf|findstr /i /l "$UsnJrnl-$J">nul
            if !errorlevel! equ 0 if not exist "%outdir%\NTFS\%%~nxf_nlt.finished" (
                echo [+] Parse %%~nxf with NTFS log tracker
                echo NTFS_Log_Tracker_CMD -u "%%f" !MFT_OPT! -o "%outdir%\NTFS"
                NTFS_Log_Tracker_CMD -u "%%f" !MFT_OPT! -o "%outdir%\NTFS" > nul
                type nul > "%outdir%\NTFS\%%~nxf_nlt.finished"
                echo.
            ) else (
                echo [-] Skipped parsing %%~nxf with NTFS log tracker
            )
        )

        :: parse $Logfile
        if /I x"%NLT_Log%" == x"true" (
            echo %%~nxf|findstr /i /l "$Logfile">nul
            if !errorlevel! equ 0 if not exist "%outdir%\NTFS\%%~nxf_nlt.finished" (
                echo [+] Parse %%~nxf with NTFS log tracker
                echo NTFS_Log_Tracker_CMD -l "%%f" !MFT_OPT! -o "%outdir%\NTFS"
                NTFS_Log_Tracker_CMD -l "%%f" !MFT_OPT! -o "%outdir%\NTFS" > nul
                type nul > "%outdir%\NTFS\%%~nxf_nlt.finished"
                echo.
            )
        )
    )
)

if exist "%indir%\rdpcache" (
    for /R "%indir%\rdpcache" %%f in (.) do (
        if not "%%~nxf" == "rdpcache" (
            if /I x"%BmcTools%" == x"true" (
                if not exist "%outdir%\rdpcache\%%~nxf" (
                    echo [+] Parse rdp cache for %%~nxf with bmc-tools.py
                    mkdir "%outdir%\rdpcache\%%~nxf" 2> nul
                    echo bmc-tools.py -s "%%f" -d "%outdir%\rdpcache\%%~nxf"
                    bmc-tools.py -s "%%f" -d "%outdir%\rdpcache\%%~nxf" > nul 2>&1
                ) else (
                    echo [-] Skipped parsing rdp cache for %%~nxf with bmc-tools.py
                )
                echo.
            )

            if /I x"%Rdpieces%" == x"true" (
                if not exist "%outdir%\rdpcache\%%~nxf_rdpieces" (
                    echo [+] Parse rdp cache for %%~nxf with rdpieces.pl
                    echo rdpieces.pl -source "%outdir%\rdpcache\%%~nxf" -output "%outdir%\rdpcache\%%~nxf_rdpieces"
                    rdpieces.pl -source "%outdir%\rdpcache\%%~nxf" -output "%outdir%\rdpcache\%%~nxf_rdpieces" > nul 2>&1
                ) else (
                    echo [-] Skipped parsing rdp cache for %%~nxf with rdpieces.pl
                )
                echo.
            )
        )
    )
)

endlocal

goto :EOF

:::::: Functions

:CMDRESULT
setlocal
set COMMAND=%~1
for /F "tokens=* USEBACKQ" %%f in (`%COMMAND%`) do (
    set RESULT=%%f
)
endlocal & (
  set %2=%RESULT%
)
exit /b

:SPLIT
setlocal
set STRING=%~1
for /f "tokens=%3 delims=%2" %%a in ("%STRING%") do (
  set SPLIT_RESULT=%%a
)
endlocal & (
  set %4=%SPLIT_RESULT%
)
exit /b

setlocal enableextensions enabledelayedexpansion
set file=%~1
set area=[%~2]
set key=%~3
set result=%4

set currarea=
for /f "usebackq delims=" %%a in ("!file!") do (
    set ln=%%a
    if "x!ln:~0,1!"=="x[" (
        set currarea=!ln!
    ) else (
        for /f "tokens=1,2 delims==" %%b in ("!ln!") do (
            set currkey=%%b
            set currval=%%c
            if "x!area!"=="x!currarea!" if "x!key!"=="x!currkey!" (
                echo !currval!
                set result=!currval!
            )
        )
    )
)
endlocal & (
  set %4=!result!
)
exit /b


:GET_INI_VALUE
setlocal enableextensions enabledelayedexpansion
set file=%~1
set area=[%~2]
set key=%~3

set currarea=
for /f "usebackq delims=" %%a in ("!file!") do (
    set ln=%%a
    if "x!ln:~0,1!"=="x[" (
        set currarea=!ln!
    ) else (
        for /f "tokens=1,2 delims==" %%b in ("!ln!") do (
            set currkey=%%b
            set currval=%%c
            if /I "x!area!"=="x!currarea!" if /I "x!key!"=="x!currkey!" (
                set result=!currval!
            )
        )
    )
)
endlocal & (
  set %3=%result%
)
exit /b
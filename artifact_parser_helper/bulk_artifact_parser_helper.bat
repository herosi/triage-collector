@echo off

set indir=%~1
set outdir=%~2
set inifile=%~3


if x"%inifile%" == x"" (
    set inifile=.\artifact_parser_helper.ini
)


for /f "delims=" %%f in ('dir /b "%indir%"') do (
    echo %%f
    if exist "%indir%\%%f\triage-collector" (
        artifact_parser_helper.bat "%indir%\%%f\triage-collector" "%outdir%\%%f\parsed_artifacts" "%inifile%"
    )
)

@ECHO OFF
CD /D "%~DP0"

WHERE pythonw.exe >NUL 2>NUL
IF %ERRORLEVEL% EQU 0 (
    START "" pythonw.exe "%~DP0simple-awg-decoder.py"
    EXIT /B
)

python "%~DP0simple-awg-decoder.py"
PAUSE

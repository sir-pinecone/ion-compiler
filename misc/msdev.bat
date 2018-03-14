@echo off
REM First time setup:
REM 1. Uncomment the devenv that opens the exe.
REM 2. Save the sln to your repo.
REM 3. Create a folder for code then add existing code files.
REM 4. Right-click the exe in MSVC. Edit the Application Executable path and set it to "run_tree\name_of_exe.exe" without the quotes.
REM 5. Edit the Working Directory path and add "run_tree" to it without the quotes.
REM 6. Comment out the devenv command.
REM 7. Uncomment the other devenv that opens the solution.


REM devenv run_tree/study_opengl.exe
devenv project/ion_compiler.sln

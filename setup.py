import sys
from cx_Freeze import setup, Executable

build_exe_options = {
   „excludes“: [„tkinter“, „unittest“],
   „zip_include_packages“: [„encodings“, „PySide6“],
}

# base=“Win32GUI“ sollte nur mit der Windows GUI App verwendet werden
base = „Win32GUI“ if sys.platform == „win32“ else None

setup(
   name=“Log-Analyse“,
   version=“0.1″,
   description=“Log-Analyser for Logs“,
   options={„build_exe“: build_exe_options},
   executables=[Executable(„Loganalyse.py“, base=base)],
)
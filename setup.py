import sys
from cx_Freeze import setup, Executable

# Optionen für den Build-Prozess
build_exe_options = {
   "excludes": ["tkinter", "unittest"],  # Module, die explizit ausgeschlossen werden sollen
   "zip_include_packages": ["encodings", "PySide6"], # Pakete, die in das Zip-Archiv aufgenommen werden sollen
}

# Basis für die ausführbare Datei bestimmen
# "Win32GUI" wird für Windows GUI-Anwendungen verwendet, um das Konsolenfenster zu unterdrücken
base = "Win32GUI" if sys.platform == "win32" else None

setup(
   name="Log-Analyse",        # Name der Anwendung
   version="0.1",             # Version der Anwendung
   description="Log-Analyser for Logs", # Beschreibung
   options={"build_exe": build_exe_options}, # Übergabe der Build-Optionen
   executables=[Executable("Loganalyse.py", base=base)], # Definition der zu erstellenden ausführbaren Datei
)
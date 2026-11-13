
import PyInstaller.__main__
import os

repo_path = "C:/Users/yahye/fikrado-security-final"
os.chdir(repo_path)

PyInstaller.__main__.run([
    'main.py',
    '--name=FikradoSecurity',
    '--onefile',
    '--windowed',
    '--icon=assets/logo.ico',
    '--add-data=assets;assets',
    '--add-data=config;config',
    '--add-data=core;core',
    '--add-data=plugins;plugins',
    '--add-data=scanners;scanners',
    '--add-data=tools;tools',
    '--add-data=ui;ui',
])

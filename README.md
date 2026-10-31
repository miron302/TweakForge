TweakForge - build iOS jailbreak tweaks from a source .zip (Arch Linux)

1. Unzip this folder anywhere
2. Open a terminal in it and run:   ./start.sh
   - First run offers to install Theos, the iOS SDKs and ldid (sudo password once)
3. Use the menu:
     Up/Down  move      Left/Right  change a setting      Enter  select
     B  build           Q  quit
   Set: Source ZIP (built-in file browser, or press / to paste a path),
        Package scheme, Architectures, iOS version, Debug build, Output folder.
   Then pick BUILD TWEAK. Your choices are remembered for next time.
   The .deb is saved to ~/TweakForge-Output (or the folder you chose).

Prefer a browser?     ./tweakforge.py web
Prefer one command?   ./tweakforge.py build MyTweak.zip -o ~/debs -s rootless -a arm64 -t 15.0

Notes
- The zip needs a Theos Makefile in it.
- "Auto detect" keeps whatever the tweak's Makefile says; if it says nothing, Theos defaults apply (rootful).
- Roothide needs the roothide fork of Theos.
- Only build source you trust: a Makefile can run any command.

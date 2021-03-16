# COFFInjector

A Proof of Concept code - loading and injecting MSVC object file.

Blog post with explanation: https://0xpat.github.io/Malware_development_part_8/

# Usage

Download the repo (`git clone --recursive`), compile x64 Release and run like this:

`(.\COFFInjector\bin\x64\Release\COFFInjector.exe COFFObject\obj\x64\Release\COFFObject.obj`

Currently works for x64 only.
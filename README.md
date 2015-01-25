scripts_for_RE
==============

Python scripts for reverse engineering.

parse_ARM_SEH.py
----------------------------
(IDA Only) Locates SEH try blocks, exception filters and handlers for Windows RT.

merge_functions.py
----------------------------
(IDA Only) Merges a given function with the next function.

visualize_binary.py
----------------------------
Generates a PNG image file that represents the contents of a specified file.

![example](/img/visualized_files.png)

apply_all_signatures.py
----------------------------
(IDA Only) Applies all FLIRT signatures in a <IDA DIR>/sig directory.

color_as_default.py
----------------------------
(IDA Only) Changes all instructions color to default.

find_ARMB_prologue.py
----------------------------
(IDA Only) Finds function-prologue-like byte sequences for ARMB.

highlight_all_CALLs.py
----------------------------
(IDA Only) Highlights all function call instructions in a given binary file.

show_SEH_chain.py
----------------------------
(IDA Only) Shows SEH chains (stack and handlers) for all threads.

rotate.py
----------------------------
Provides \__ROR4__, \__ROR8__, \__ROL4__ and \__ROL8__ functions.


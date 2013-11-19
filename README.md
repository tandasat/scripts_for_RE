scripts_for_RE
==============

Python scripts for reverse engineering.

win_ioctl.py
----------------------------
Decodes a given 32-Bit Windows Device I/O control code.

    > python win_ioctl.py 0x220086
    Device   : FILE_DEVICE_UNKNOWN (0x22)
    Function : 0x21
    Method   : METHOD_OUT_DIRECT (2)
    Access   : FILE_ANY_ACCESS (0)

visualize_binary.py
----------------------------
Generates a PNG image file that represents the contents of a specified file.

![example](/img/visualized_files.png)

apply_all_signatures.py
----------------------------
(IDA Pro Only) Applies all FLIRT signatures in a <IDA DIR>/sig directory.

color_as_default.py
----------------------------
(IDA Pro Only) Changes all instructions color to default.

find_ARMB_prologue.py
----------------------------
(IDA Pro Only) Finds function-prologue-like byte sequences for ARMB.

highlight_all_CALLs.py
----------------------------
(IDA Pro Only) Highlights all CALL instructions in a given binary file.

show_SEH_chain.py
----------------------------
(IDA Pro Only) Shows SEH chains (stack and handlers) for all threads.

# Relayne application icon

`relayne.png` is the source artwork: a turquoise R on a dark navy background,
generated for Relayne with OpenAI Imagegen. The main egui viewport embeds it at
compile time.

`relayne.ico` contains 16, 24, 32, 48, 64, 128 and 256 pixel PNG frames, converted
from the source artwork. `build.rs` embeds this icon in the Windows executable
using `winresource`, for Explorer, shortcuts and the taskbar.

When replacing the artwork, regenerate all ICO frames as well as the PNG and
rebuild the executable. Windows may cache icons for existing shortcuts.

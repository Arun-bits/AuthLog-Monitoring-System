import ctypes

ctypes.windll.user32.MessageBoxW(
    0,
    "POP-UP SYSTEM WORKS",
    "TEST",
    0x10
)
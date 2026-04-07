from win10toast import ToastNotifier
import time

toaster = ToastNotifier()
toaster.show_toast(
    "Test Notification",
    "Popup is working successfully!",
    duration=5,
    threaded=True
)

time.sleep(6)
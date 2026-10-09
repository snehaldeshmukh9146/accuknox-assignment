#!/usr/bin/env python3

import ctypes
import os
import socket
import time

# Set Linux process name to targetapp
libc = ctypes.CDLL("libc.so.6")
libc.prctl(15, b"targetapp", 0, 0, 0)

print("Process name: targetapp")
print("PID:", os.getpid())
print("")
print("IMPORTANT: Put this PID into the cgroup before testing.")
print("")
print("Command:")
print("echo", os.getpid(),
      "| sudo tee /sys/fs/cgroup/unified/accuknox_demo/cgroup.procs")
print("")
print("Waiting 60 seconds...")
print("")


# Give us time to move this process into the cgroup.
time.sleep(60)


def test_port(port):

    print("Testing TCP port", port, "...")

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(3)

    try:

        sock.connect(("127.0.0.1", port))

        print("RESULT:", port, "CONNECTED")

    except Exception as e:

        print(
            "RESULT:",
            port,
            "BLOCKED",
            "(" + str(e) + ")"
        )

    finally:

        sock.close()


print("Testing allowed port...")
test_port(4040)

print("")

print("Testing blocked port...")
test_port(5050)

print("")
print("Tests completed.")
print("Keeping process alive.")
print("Press Ctrl+C to stop.")

while True:
    time.sleep(1)

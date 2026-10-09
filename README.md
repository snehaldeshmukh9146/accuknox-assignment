# AccuKnox Technical Assignment

## Overview

This repository contains solutions and demonstrations for three technical tasks.

### Problem 1: eBPF TCP Port Blocker

* Uses BCC and XDP to inspect IPv4 TCP traffic.
* Drops traffic targeting a configurable TCP destination port.
* Uses a BPF map to configure the blocked port from userspace.

Example:

```bash
sudo python3 problem1.py 4040
```

### Problem 2: Process-Level TCP Port Filtering

* Uses a cgroup eBPF egress program.
* Allows TCP traffic to destination port 4040.
* Drops other TCP traffic for processes placed in the controlled cgroup.
* Uses userspace to place the target process into the cgroup.

Run the filter:

```bash
sudo python3 problem2.py
```

In another terminal, start the test application:

```bash
python3 targetapp.py
```

Move the displayed PID into the cgroup during the application's 60-second waiting period:

```bash
echo <PID> | sudo tee /sys/fs/cgroup/unified/accuknox_demo/cgroup.procs
```

Verify membership:

```bash
cat /proc/<PID>/cgroup
```

### Problem 3: Go Channels and Goroutines

The Go example demonstrates function values sent through a buffered channel, worker goroutines, and synchronization using `sync.WaitGroup`.

Run:

```bash
go run problem3.go
```

Expected output:

```text
HERE1
Hello
```

## Requirements and Environment

The implementation was developed and tested on Ubuntu 18.04 with a Linux 4.15 kernel, BCC, Python 3, and Go.

Problem 2 uses a cgroup v2 egress hook and requires suitable kernel support and root privileges.

## Notes

* Run the eBPF programs only on systems where you have permission to administer networking.
* Check the interface name and cgroup path for your own environment.
* The target process is selected and placed into the cgroup by userspace; the eBPF program enforces the network policy on traffic from that cgroup.
* See the accompanying demonstration video for execution and test results.


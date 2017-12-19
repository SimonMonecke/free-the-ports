# free-the-ports

Use free-the-ports to kill processes running on a specified port.

## Installation
```
go get -u github.com/smonecke/free-the-ports
```

## Requirements
*free-the-ports* is only for linux. It reads the content of the following files:
- /proc/net/tcp
- /proc/net/tcp6
- /proc/net/udp
- /proc/net/udp6
- /proc/\*/fd/\*
- /etc/passwd

## Usage
Run `free-the-ports` without any arguments to enter the interactive mode:
![Interactive Mode 1](/screenshot_interactive_mode-1.png?raw=true "Interactive Mode 1")
Enter a port number to send a SIGTERM to all processes running on this port:


![Interactive Mode 2](/screenshot_interactive_mode-2.png?raw=true "Interactive Mode 2")


Run `free-the-ports 8000` to skip the interactive mode and send immediately a SIGTERM to all processes running on this port:

![Non-Interactive Mode 1](/screenshot_non_interactive_mode-1.png?raw=true "Non-Interactive Mode 1")

## License

Copyright © 2017 Simon Monecke

Distributed under MIT License

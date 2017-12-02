package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var states = []string{
	"ESTABLISHED",
	"SYN_SENT",
	"SYN_RECV",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"TIME_WAIT",
	"CLOSE",
	"CLOSE_WAIT",
	"LAST_ACK",
	"LISTEN",
	"CLOSING",
}

func convertAddress(addressHex string) string {
	addressDecPartOne, err := strconv.ParseInt(addressHex[0:1], 16, 0)
	if err != nil {
		log.Fatal(err)
	}
	addressDecPartTwo, err := strconv.ParseInt(addressHex[0:1], 16, 0)
	if err != nil {
		log.Fatal(err)
	}
	addressDecPartThree, err := strconv.ParseInt(addressHex[0:1], 16, 0)
	if err != nil {
		log.Fatal(err)
	}
	addressDecPartFour, err := strconv.ParseInt(addressHex[0:1], 16, 0)
	if err != nil {
		log.Fatal(err)
	}
	return strings.Join([]string{
		fmt.Sprintf("%d", addressDecPartOne),
		fmt.Sprintf("%d", addressDecPartTwo),
		fmt.Sprintf("%d", addressDecPartThree),
		fmt.Sprintf("%d", addressDecPartFour),
	}, ".")
}

func convertPort(portHex string) string {
	portDec, err := strconv.ParseInt(portHex, 16, 0)
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%d", portDec)
}

func convertState(stateHex string) string {
	stateDec, err := strconv.ParseInt(stateHex, 16, 0)
	if err != nil {
		log.Fatal(err)
	}
	if stateDec-1 < int64(0) || stateDec-1 > int64(len(states)) {
		log.Fatal(fmt.Sprintf("unknown state: %d", stateDec))
	}
	return states[stateDec-1]
}

func findPid(inode string) string {
	procDir := "/proc"
	linkDest := "socket:[" + inode + "]"

	files, err := ioutil.ReadDir(procDir)
	if err != nil {
		log.Fatal(err)
	}
	files[0].IsDir()
	processDirRegexp, err := regexp.Compile(`\d*`)
	if err != nil {
		log.Fatal(err)
	}

	processDirs := files[:0]
	for _, file := range files {
		if file.IsDir() && processDirRegexp.MatchString(file.Name()) {
			processDirs = append(processDirs, file)
		}
	}

	for _, dir := range processDirs {
		links, err := ioutil.ReadDir(procDir + "/" + dir.Name() + "/fd")
		if err == nil {
			for _, link := range links {
				dest, err := os.Readlink(procDir + "/" + dir.Name() + "/fd/" + link.Name())
				if err == nil && dest == linkDest {
					commFile, err := os.Open(procDir + "/" + dir.Name() + "/comm")
					if err == nil {
						defer commFile.Close()
						scanner := bufio.NewScanner(commFile)
						scanner.Scan()
						processName := scanner.Text()
						return dir.Name() + "/" + string(processName)
					}
				}
			}
		}
	}
	return "-"
}

func main() {
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // skip headline

	fmt.Println("TCP")
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		localAddressAndPortHex := strings.Split(fields[1], ":")
		localAddress := convertAddress(localAddressAndPortHex[0])
		localPort := convertPort(localAddressAndPortHex[1])

		remoteAddressAndPortHex := strings.Split(fields[2], ":")
		remoteAddress := convertAddress(remoteAddressAndPortHex[0])
		remotePort := convertPort(remoteAddressAndPortHex[1])

		state := convertState(fields[3])

		uid := fields[7]
		inode := fields[9]
		pid := findPid(inode)

		fmt.Printf("%s:%s -> %s:%s %s %s %s\n", localAddress, localPort, remoteAddress, remotePort, state, uid, pid)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

// cat /proc/net/tcp | grep -e "^\s*[[:digit:]]*:" | sed 's/^\s*[[:digit:]]*:\s*[^:]*:\([^ ]*\).*$/0x\1/' | xargs printf "%d\n"

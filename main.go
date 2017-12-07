package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/gosuri/uitable"
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

type row struct {
	proto  string
	local  string
	remote string
	state  string
	uid    string
	inode  string
}

func convertAddressIpV4(addressHex string) string {
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

func findPidsAndProgramnames(rows []row) map[string]string {
	procDir := "/proc"
	linkDests := []string{}
	for _, r := range rows {
		linkDests = append(linkDests, `(socket:\[`+r.inode+`\])`)
	}
	linkDestRegexp := regexp.MustCompile(strings.Join(linkDests, "|"))
	inodePidProgramnameMapping := map[string]string{}
	inodeRegexp := regexp.MustCompile(`socket:\[([^\]]*)\]`)

	files, err := ioutil.ReadDir(procDir)
	if err != nil {
		log.Fatal(err)
	}
	files[0].IsDir()
	processDirRegexp := regexp.MustCompile(`\d*`)

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
				if err == nil && linkDestRegexp.MatchString(dest) {
					commFile, err := os.Open(procDir + "/" + dir.Name() + "/comm")
					if err == nil {
						defer commFile.Close()
						scanner := bufio.NewScanner(commFile)
						scanner.Scan()
						processName := scanner.Text()
						inode := inodeRegexp.FindStringSubmatch(dest)[1]
						inodePidProgramnameMapping[inode] = dir.Name() + "/" + string(processName)
						if len(inodePidProgramnameMapping) == len(rows) {
							return inodePidProgramnameMapping
						}
					}
				}
			}
		}
	}
	return inodePidProgramnameMapping
}

func createUidUsernameMapping() map[string]string {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	uidUsernameMapping := map[string]string{}
	for scanner.Scan() {
		line := scanner.Text()
		lineSplitted := strings.Split(line, ":")
		username := lineSplitted[0]
		uid := lineSplitted[2]
		uidUsernameMapping[uid] = username
	}
	return uidUsernameMapping
}

func convertAddressIpV6(addressHex string) string {
	var result []string
	for i := 0; i < 4; i++ {
		addressPart := addressHex[i*8 : (i+1)*8]
		var subresult string
		for j := 0; j < 4; j++ {
			subresult = subresult + addressPart[6-j*2:8-j*2]
			if j == 1 {
				subresult = subresult + ":"
			}
		}
		result = append(result, subresult)
	}
	return "[" + net.ParseIP(strings.Join(result, ":")).String() + "]"
}

func scanProcFile(proto string, rows *[]row, table *uitable.Table) {
	file, err := os.Open("/proc/net/" + proto)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // skip headline
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	udpRegexp := regexp.MustCompile(`udp.*`)
	ipV6Regexp := regexp.MustCompile(`.*6`)

	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
		line := scanner.Text()
		fields := strings.Fields(line)

		localAddressAndPortHex := strings.Split(fields[1], ":")
		var localAddress string
		if ipV6Regexp.MatchString(proto) {
			localAddress = convertAddressIpV6(localAddressAndPortHex[0])
		} else {
			localAddress = convertAddressIpV4(localAddressAndPortHex[0])
		}
		localPort := convertPort(localAddressAndPortHex[1])

		remoteAddressAndPortHex := strings.Split(fields[2], ":")
		var remoteAddress string
		if ipV6Regexp.MatchString(proto) {
			remoteAddress = convertAddressIpV6(remoteAddressAndPortHex[0])
		} else {
			remoteAddress = convertAddressIpV4(remoteAddressAndPortHex[0])
		}
		remotePort := convertPort(remoteAddressAndPortHex[1])

		var state string
		if udpRegexp.MatchString(proto) {
			state = "-"
		} else {
			state = convertState(fields[3])
		}

		uid := fields[7]
		inode := fields[9]

		*rows = append(*rows, row{
			proto:  proto,
			local:  localAddress + ":" + localPort,
			remote: remoteAddress + ":" + remotePort,
			state:  state,
			uid:    uid,
			inode:  inode,
		})
	}
}

func main() {
	table := uitable.New()
	table.AddRow("#", "Proto", "Local Address", "Foreign Address", "State", "UID/Username", "PID/Programname")
	rows := []row{}
	scanProcFile("tcp", &rows, table)
	scanProcFile("tcp6", &rows, table)
	scanProcFile("udp", &rows, table)
	scanProcFile("udp6", &rows, table)

	inodePidProgramnameMapping := findPidsAndProgramnames(rows)
	uidUsernameMapping := createUidUsernameMapping()

	for i, r := range rows {
		username := uidUsernameMapping[r.uid]
		if username == "" {
			panic("unknown uid: " + r.uid)
		}
		pidAndProgramname := inodePidProgramnameMapping[r.inode]
		if pidAndProgramname == "" {
			pidAndProgramname = "-"
		}
		table.AddRow(i+1, r.proto, r.local, r.remote, r.state, r.uid+"/"+username, pidAndProgramname)
	}

	fmt.Println(table)
}

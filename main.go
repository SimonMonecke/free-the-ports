package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gosuri/uitable"
)

type row struct {
	proto string
	port  int
	uid   string
	inode string
}

type pidAndProgramName struct {
	pid         string
	programName string
}

func convertPort(portHex string) int {
	portDec, err := strconv.ParseInt(portHex, 16, 0)
	if err != nil {
		log.Fatal(err)
	}
	return int(portDec)
}

func findPidsAndProgramNames(rows []row) map[string]pidAndProgramName {
	procDir := "/proc"
	inodes := map[string]bool{}
	for _, r := range rows {
		inodes[r.inode] = true
	}
	inodePidProgramnameMapping := map[string]pidAndProgramName{}
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
		commFile, err := os.Open(procDir + "/" + dir.Name() + "/comm")
		if err != nil {
			continue
		}
		defer commFile.Close()
		scanner := bufio.NewScanner(commFile)
		scanner.Scan()
		processName := scanner.Text()
		links, err := ioutil.ReadDir(procDir + "/" + dir.Name() + "/fd")
		if err != nil {
			continue
		}
		for _, link := range links {
			dest, err := os.Readlink(procDir + "/" + dir.Name() + "/fd/" + link.Name())
			if err != nil {
				continue
			}
			inodeRegexpMatches := inodeRegexp.FindStringSubmatch(dest)
			if len(inodeRegexpMatches) >= 1 && inodes[inodeRegexpMatches[1]] {
				inodePidProgramnameMapping[inodeRegexpMatches[1]] = pidAndProgramName{pid: dir.Name(), programName: string(processName)}
				if len(inodePidProgramnameMapping) == len(rows) {
					return inodePidProgramnameMapping
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

	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
		line := scanner.Text()
		fields := strings.Fields(line)

		addressAndPortHex := strings.Split(fields[1], ":")
		port := convertPort(addressAndPortHex[1])

		uid := fields[7]
		inode := fields[9]

		*rows = append(*rows, row{
			proto: proto,
			port:  port,
			uid:   uid,
			inode: inode,
		})
	}
}

func uniqueRows(rows []row, inodePidProgramnameMapping map[string]pidAndProgramName) []row {
	uRows := rows[:0]
	for i := 0; i < len(rows); i++ {
		currentPid := inodePidProgramnameMapping[rows[i].inode].pid
		foundSameEntry := false
		for j := 0; j < i; j++ {
			otherPid := inodePidProgramnameMapping[rows[j].inode].pid
			if currentPid != "" && currentPid == otherPid && rows[j].port == rows[i].port && rows[j].proto == rows[i].proto {
				foundSameEntry = true
				break
			}
		}
		if !foundSameEntry {
			uRows = append(uRows, rows[i])
		}
	}
	return uRows
}

func main() {
	currentUser, err := user.Current()
	if err != nil {
		panic("cannot identify current user")
	}
	if currentUser.Uid != "0" {
		fmt.Println("Not all processes could be identified, non-owned process info will not be shown, you would have to be root to see it all.")
	}
	table := uitable.New()
	table.AddRow("Port", "Proto", "Username", "PID", "Program name")
	rows := []row{}
	scanProcFile("tcp", &rows, table)
	scanProcFile("tcp6", &rows, table)
	scanProcFile("udp", &rows, table)
	scanProcFile("udp6", &rows, table)

	inodePidProgramnameMapping := findPidsAndProgramNames(rows)
	uidUsernameMapping := createUidUsernameMapping()

	rows = uniqueRows(rows, inodePidProgramnameMapping)

	sort.Slice(rows, func(i, j int) bool { return rows[i].port < rows[j].port })

	var lastSeenPort int

	for i := 0; i < len(rows); i++ {
		r := rows[i]
		username := uidUsernameMapping[r.uid]
		if username == "" {
			panic("unknown uid: " + r.uid)
		}
		pidAndProgramName := inodePidProgramnameMapping[r.inode]
		if pidAndProgramName.pid == "" {
			pidAndProgramName.pid = "-"
			pidAndProgramName.programName = "-"
		}
		var portCell string
		if r.port == lastSeenPort {
			if i < len(rows)-1 && rows[i+1].port == r.port {
				portCell = "├"
			} else {
				portCell = "└"
			}
		} else {
			portCell = strconv.Itoa(r.port)
		}
		lastSeenPort = r.port
		table.AddRow(portCell, r.proto, username, pidAndProgramName.pid, pidAndProgramName.programName)
	}

	fmt.Println(table)
}

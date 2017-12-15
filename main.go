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

type runningProcess struct {
	proto       string
	port        int
	uid         string
	inode       string
	pid         int
	programName string
}

type pidAndProgramName struct {
	pid         int
	programName string
}

func convertPort(portHex string) int {
	portDec, err := strconv.ParseInt(portHex, 16, 0)
	if err != nil {
		log.Fatal(err)
	}
	return int(portDec)
}

func findPidsAndProgramNames(rows []runningProcess) map[string]pidAndProgramName {
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
				pid, err := strconv.Atoi(dir.Name())
				if err != nil {
					panic(err)
				}
				inodePidProgramnameMapping[inodeRegexpMatches[1]] = pidAndProgramName{pid: pid, programName: string(processName)}
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

func scanProcFile(proto string, rows *[]runningProcess) {
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

		*rows = append(*rows, runningProcess{
			proto: proto,
			port:  port,
			uid:   uid,
			inode: inode,
		})
	}
}

func filterDuplicateEntries(rows []runningProcess) []runningProcess {
	uRows := rows[:0]
	for i := 0; i < len(rows); i++ {
		foundSameEntry := false
		for j := 0; j < i; j++ {
			if rows[i].pid != 0 && rows[i].pid == rows[j].pid && rows[j].port == rows[i].port && rows[j].proto == rows[i].proto {
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

func printWarningIfRunningAsNonRoot() *user.User {
	currentUser, err := user.Current()
	if err != nil {
		panic("cannot identify current user")
	}
	if currentUser.Uid != "0" {
		fmt.Println("Not all processes could be identified, non-owned process info will not be shown, you would have to be root to see it all.")
	}
	return currentUser
}

func getRunningProcesses() []runningProcess {
	runningProcesses := []runningProcess{}
	scanProcFile("tcp", &runningProcesses)
	scanProcFile("tcp6", &runningProcesses)
	scanProcFile("udp", &runningProcesses)
	scanProcFile("udp6", &runningProcesses)

	inodePidProgramnameMapping := findPidsAndProgramNames(runningProcesses)
	runningProcessesWithPidAndProgramNames := runningProcesses[:0]
	for _, process := range runningProcesses {
		if pidAndProgramNameEntry, ok := inodePidProgramnameMapping[process.inode]; ok {
			process.pid = pidAndProgramNameEntry.pid
			process.programName = pidAndProgramNameEntry.programName
		}
		runningProcessesWithPidAndProgramNames = append(runningProcessesWithPidAndProgramNames, process)
	}
	uniqRunningProcesses := filterDuplicateEntries(runningProcesses)
	sort.Slice(uniqRunningProcesses, func(i, j int) bool { return uniqRunningProcesses[i].port < uniqRunningProcesses[j].port })
	return uniqRunningProcesses

}

func printRunningProcessesTable(runningProcesses []runningProcess) {
	table := uitable.New()
	table.AddRow("Port", "Proto", "Username", "PID", "Program name")
	uidUsernameMapping := createUidUsernameMapping()

	var lastSeenPort int
	for i := 0; i < len(runningProcesses); i++ {
		r := runningProcesses[i]
		username := uidUsernameMapping[r.uid]
		if username == "" {
			panic("unknown uid: " + r.uid)
		}
		pidAsString := "-"
		if runningProcesses[i].pid != 0 {
			pidAsString = strconv.Itoa(runningProcesses[i].pid)
		}
		var portCell string
		if r.port == lastSeenPort {
			if i < len(runningProcesses)-1 && runningProcesses[i+1].port == r.port {
				portCell = "├"
			} else {
				portCell = "└"
			}
		} else {
			portCell = strconv.Itoa(r.port)
		}
		lastSeenPort = r.port
		table.AddRow(portCell, r.proto, username, pidAsString, runningProcesses[i].programName)
	}

	fmt.Println(table)
}

func sendSigtermToRunningProcessesOnPort(runningProcesses []runningProcess, port int) {
	filteredRunningProcesses := []runningProcess{}
	for _, r := range runningProcesses {
		if r.port == port && r.pid != 0 {
			filteredRunningProcesses = append(filteredRunningProcesses, r)
		}
	}
	if len(filteredRunningProcesses) == 0 {
		fmt.Printf("No killable process is running on port %d\n", port)
	}

	for _, process := range filteredRunningProcesses {
		processInstance, err := os.FindProcess(process.pid)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Send SIGTERM to %s - %d\n", process.programName, process.pid)
		err = processInstance.Signal(os.Interrupt)
		if err != nil {
			panic(err)
		}
	}
}

func readPortToBeFreed() int {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Free the port: ")
	text, _ := reader.ReadString('\n')
	textWithoutNewLine := strings.Replace(text, "\n", "", -1)
	port, err := strconv.Atoi(textWithoutNewLine)
	if err != nil {
		fmt.Printf("\"%s\" is no valid port\n", textWithoutNewLine)
		os.Exit(1)
	}
	return port
}

func main() {
	printWarningIfRunningAsNonRoot()

	runningProcesses := getRunningProcesses()

	printRunningProcessesTable(runningProcesses)

	port := readPortToBeFreed()

	sendSigtermToRunningProcessesOnPort(runningProcesses, port)
}

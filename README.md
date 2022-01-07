<img src="images/logo-svg.svg#gh-light-mode-only" width="62%">
<img src="images/logo-svg-dark.svg#gh-dark-mode-only" width="62%">

# A Log4J2 CVE-2021-44228 Vulnerability Scanner and Patcher

Links to download the latest version:

| Linux x64 with glibc2.17+ (RHEL7+)                                                                   | Windows & all other platforms                                                                             |
|------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| [Download Linux binary](https://github.com/sassoftware/loguccino/releases/latest/download/loguccino) | [Download Java .jar](https://github.com/sassoftware/loguccino/releases/latest/download/loguccino-all.jar) |  

> 🚑 Note: SAS customers looking to patch their SAS 9.4 or SAS Viya 3.x deployments should **follow the specific instructions provided in the [SAS Help Center documentation](https://go.documentation.sas.com/doc/en/log4j/1.0/p1pymcg1f06injn10rho5mkmmhe4.htm).**

## What is this

This project is an early fork of [logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner), initially modified to recursively inspect archives and to add support for tar/gz compression. Since the fork, the project has evolved in parallel to the original and implements many similar features, even though the majority of the code has been rewritten. While the original 'fix' functionality has been replaced with a `patch` method that supports some deep nested edge cases and is more tolerant to failure & rollback, the detection mechanism (the `scan` command) continues to work in a very similar way to the original.

## How do I get it

You can download a version of the tool from the [Releases page](https://github.com/sassoftware/loguccino/releases/latest) or by following the links at the top of this page. The [native image](https://github.com/sassoftware/loguccino/releases/latest/download/loguccino) is a standalone executable that will run on EL7 and later. The [jar file](https://github.com/sassoftware/loguccino/releases/latest/download/loguccino-all.jar) can be run with `java -jar` on JRE 1.8+. This is currently the best way to run this on other platforms and older releases of glibc (including Windows, AIX, Solaris, etc).

After downloading the native image it's necessary to `chmod +x` the file before it can be run.

## How do I use it

The command syntax is the same regardless of whether you call the .jar or the native executable. For example, this:

```
./loguccino help
```

is functionally identical to this

```
java -jar ./loguccino-all.jar help
```

The `loguccino help` command provides documentation on commands that are available.

### Scanning for vulnerable .jars

```
./loguccino scan /path/to/approot 
```

This will traverse all subdirectories in `/path/to/approot`, including recursively traversing all nested .tar.gz, .tgz, .tar, .zip, .ear, .war and .jar archives.

A .csv file by the name of `loguccino-scan-[datetime].csv` will be created in the working directory, containing the following data:

- **AffectedFile** is the full path on the filesystem to the file that was found to contain the vulnerability. Example value:
  `/opt/sas/config/Lev1/Web/Staging/sas.webreportstudio4.4.21w47AIX.ear/install/deploy/21w47SASConfig/Lev5/Web/Staging/sas.webreportstudio4.4.21w47AIX.ear`
- **NestedPath** is the path within the archived file where the vulnerability was found. For example, here the log4j-core-2.1.jar file was found in the WRS .war archive, packaged inside the .ear archive (AffectedFile above)
  `opt/sas/config/Lev1/Web/Staging/sas.webreportstudio4.4.21w47AIX.ear::sas.webreportstudio.war::WEB-INF/lib/log4j-core-2.1.jar`
- **AffectedVersion** is the version of Log4J that was found within the affected file  on the nested path.
- **Patched** signifies whether this instance of this vulnerable Log4J jar within this archive has already been patched.

More information about the scan command is available via `./loguccino help scan`.

### Patching vulnerable .jars

If vulnerabilities are found, the `loguccino-scan-[datetime].csv` is used as an input to the patch command:

```
./loguccino patch ./loguccino-scan-23122021003311.csv
```

This removes each vulnerability that was found, and creates a `loguccino-patch-[timestamp]` directory containing a backup of each file that was patched. Where a file was patched for multiple vulnerabilities (such as a larger backup archive containing multiple tools or software releases), multiple versions of the patched file are backed up at each stage of the process to enable staged rollback in case of failure.

> **Note**:  
> Patching a file on disk does not patch the version of the program already running on the host. Remember that you must stop the relevant services / applications before patching and restart them after the patch for the changes to take effect.

More information about the patch command is available via `./loguccino help patch`.

### Demo

<img src="images/ux.svg" width="100%">


## Known issues

### Traversal of corrupted archives

When scanning for vulnerabilities, some archives may be reported as corrupted (this also happens with nested archives where compression methods don't match the extension of the archive). The scan command will print the path to these in the `logpresso-scan-[datetime].log`. If they're deemed significant, these archives should be decompressed and inspected (or scanned) manually to confirm that they are in fact corrupted.


## Unknown issues

If you encounter any bugs or unexpected behavior, please [open an issue](https://github.com/sassoftware/loguccino/issues/new) and attach any steps to reproduce the bug alongside other background information.

Pull requests and updates to the code are welcome and encouraged. 


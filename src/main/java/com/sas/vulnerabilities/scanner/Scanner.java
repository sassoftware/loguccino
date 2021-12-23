package com.sas.vulnerabilities.scanner;

import static com.sas.vulnerabilities.utils.Constants.*;

import com.opencsv.CSVWriter;
import com.sas.vulnerabilities.model.Version;
import com.sas.vulnerabilities.model.VulnerableArchive;
import com.sas.vulnerabilities.utils.ArchiveStreamUtils;
import com.sas.vulnerabilities.utils.Utils;
import lukfor.progress.tasks.monitors.ITaskMonitor;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.utils.IOUtils;
import org.tinylog.Logger;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Optional;
import java.util.Properties;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class Scanner extends AbstractScanner {
	public Scanner(Path root, CSVWriter output) {
		super(root, output);
	}

	@Override
	public void run(ITaskMonitor monitor) throws Exception {
		monitor.begin(String.format("Scanning %s", root.toAbsolutePath()));

		try {
			traverseFiles(root);
			writeReport(vulnerabilities);
		} finally {
			monitor.done();

			Logger.info("Scanned {} directories and {} files", scanDirCount, scanFileCount);

			Predicate<VulnerableArchive> isPatched = VulnerableArchive::isPatched;
			Logger.info("Found {} vulnerable files", vulnerabilities.stream().filter(isPatched.negate()).count());
			Logger.info("Found {} patched files", vulnerabilities.stream().filter(isPatched).count());

			if (failedToReadArchives.size() > 0) {
				Logger.error(
						"Failed to read {} files:\n{}",
						failedToReadArchives.size(),
						IntStream.range(0, failedToReadArchives.size()).mapToObj(i -> String.format("%d -> %s", i + 1, failedToReadArchives.get(i))).collect(Collectors.joining("\n")));
			}
		}
	}


	private void traverseFiles(Path baseDir) {
		try {
			Files.walkFileTree(baseDir, new FileVisitor<Path>() {
				@Override
				public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult visitFile(Path path, BasicFileAttributes attrs) throws IOException {
					scanFileCount++;
					if (Utils.isArchiveTarget(path.toString())) {
						scanArchiveFile(path.toString());
					} else {
						Logger.trace("Skipping file (not an archive): " + path);
					}

					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult visitFileFailed(Path path, IOException exc) throws IOException {
					scanFileCount++;
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
					scanDirCount++;
					return FileVisitResult.CONTINUE;
				}
			});
		} catch (IOException e) {
			Logger.error("Could not scan base directory " + baseDir + ". " + e);
		}
	}

	private void scanArchiveFile(String path) {
		ArchiveInputStream archiveInputStream = null;

		try {
			Logger.debug("Scanning file: " + path);

			Optional<ArchiveInputStream> archiveInputStreamOpt = ArchiveStreamUtils.createArchiveInputStream(path, new FileInputStream(path));

			if (!archiveInputStreamOpt.isPresent()) {
				Logger.trace("Not a nested archive file (or not supported archive), skipping: " + path);
			}

			if (archiveInputStreamOpt.isPresent()) {
				archiveInputStream = archiveInputStreamOpt.get(); // make sure this is closed when traversal is done
				traverseArchiveFile(path, path, archiveInputStream);
			}
		} catch (IOException | ArchiveException e) {
			Logger.error("Could not scan file: " + path + ". The exception was " + e);
			failedToReadArchives.add(path);
		} finally {
			IOUtils.closeQuietly(archiveInputStream);
		}
	}

	private void traverseArchiveFile(String rootFile, String currentFile, ArchiveInputStream in) throws IOException {
		ArchiveEntry entry;
		boolean foundJNDILookup = false;
		Optional<VulnerableArchive> vulnerabilityOpt = Optional.empty();

		while ((entry = in.getNextEntry()) != null) {
			String entryName = entry.getName();

			// visiting entry
			if (entryName.endsWith(POM_PROPERTIES)) {
				Logger.debug("Found potentially vulnerable archive. {}", entryName);
				vulnerabilityOpt = checkVulnerability(rootFile, currentFile, in);
			} else if (entryName.endsWith(LOG4J_JNDI_LOOKUP)) {
				foundJNDILookup = true;
			} else {
				String fileLocation = currentFile + NESTED_PATH_SEPARATOR + entryName;

				try {
					Optional<ArchiveInputStream> archiveInputStreamOpt = ArchiveStreamUtils.createArchiveInputStream(entryName, in);
					if (archiveInputStreamOpt.isPresent()) {
						Logger.debug("Entering nested archive {} in {}", fileLocation, rootFile);
						traverseArchiveFile(rootFile, fileLocation, archiveInputStreamOpt.get());
					}
				} catch (ArchiveException e) {
					Logger.error("Could not scan inner archive file: " + entryName + ". The exception was " + e);
				}
			}
		}

		if (vulnerabilityOpt.isPresent()) {
			VulnerableArchive vulnerability = vulnerabilityOpt.get();
			if (!foundJNDILookup) vulnerability.setPatched(true);
			printDetection(vulnerability);
			vulnerabilities.add(vulnerability);
		}
	}

	private Optional<VulnerableArchive> checkVulnerability(String rootFile,
																   String path,
																   InputStream zis) throws IOException {
		Optional<Version> version = loadLog4jVersion(zis);
		if (version.isPresent()) {
			if (VulnerableArchive.isVulnerable(version.get())) {
				VulnerableArchive vulnerability = new VulnerableArchive(rootFile, path, version.get());
				return Optional.of(vulnerability);
			}
		}

		return Optional.empty();
	}

	private void printDetection(VulnerableArchive vulnerability) {
		boolean isPatched = vulnerability.isPatched();
		String msg = (isPatched ? "[PATCHED]" : "[*]") + " CVE-2021-44228 vulnerability in " +
				vulnerability.getNestedPath() + ", log4j " + vulnerability.getVersion();

		if (isPatched) {
			Logger.warn(msg);
		} else {
			Logger.error(msg);
		}
	}

	private Optional<Version> loadLog4jVersion(InputStream is) throws IOException {
		Properties props = new Properties();
		props.load(is);

		String groupId = props.getProperty("groupId");
		String artifactId = props.getProperty("artifactId");
		String version = props.getProperty("version");

		if (groupId.equals("org.apache.logging.log4j") && artifactId.equals("log4j-core")) {
			String[] tokens = version.split("\\.");
			int major = Integer.parseInt(tokens[0]);
			int minor = Integer.parseInt(tokens[1]);
			int patch = 0;

			// e.g. version 2.0 has only 2 tokens
			if (tokens.length > 2)
				patch = Integer.parseInt(tokens[2]);

			return Optional.of(new Version(major, minor, patch));
		}

		return Optional.empty();
	}

}

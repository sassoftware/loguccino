package com.sas.vulnerabilities.utils;

import com.opencsv.CSVReader;
import com.opencsv.CSVReaderBuilder;
import com.opencsv.RFC4180Parser;
import com.opencsv.RFC4180ParserBuilder;
import com.opencsv.exceptions.CsvException;
import com.sas.vulnerabilities.model.PatchedVulnerability;
import com.sas.vulnerabilities.model.VulnerableArchive;
import org.tinylog.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.sas.vulnerabilities.utils.Constants.INVENTORY_SKIP_LINES;
import static com.sas.vulnerabilities.utils.Constants.PATCH_RESULT_SKIP_LINES;
import static com.sas.vulnerabilities.utils.Constants.TIMESTAMP;

public class Utils {

	public static String withoutColon(String input) {
		if (OSValidator.isWindows()) {
			return input.replaceAll(":", "");
		}
		return input;
	}
	public static String toArchivePath(String input) {
		if (OSValidator.isWindows()) {
			return input.replaceAll("\\\\", "/");
		}
		return input;
	}

	public static List<VulnerableArchive> readAllVulnerabilities(String csvFile) throws IOException, CsvException {
		List<VulnerableArchive> all = new ArrayList<>();
		RFC4180Parser windowsFriendlyParser = new RFC4180ParserBuilder().build();
		try (CSVReader reader = new CSVReaderBuilder(new FileReader(csvFile))
				.withSkipLines(INVENTORY_SKIP_LINES)
				.withCSVParser(windowsFriendlyParser).build()) {

			all = reader.readAll().stream()
					.map(VulnerableArchive::fromCsvRow)
					.distinct()
					.collect(Collectors.toList());
		}
		return all;
	}

	public static List<PatchedVulnerability> readAllPatchedVulnerabilities(String csvFile) throws IOException, CsvException {
		List<PatchedVulnerability> all;
		RFC4180Parser windowsFriendlyParser = new RFC4180ParserBuilder().build();
		try (CSVReader reader = new CSVReaderBuilder(new FileReader(csvFile))
				.withSkipLines(PATCH_RESULT_SKIP_LINES)
				.withCSVParser(windowsFriendlyParser).build()) {

			all = reader.readAll().stream()
					.map(PatchedVulnerability::fromCsvRow)
					.collect(Collectors.toList());
		}
		return all;
	}

	@Deprecated
	public static String generateTimestamp() {
		DateTimeFormatter customFormatter = DateTimeFormatter.ofPattern("ddMMyyyyHHmmss");
		return customFormatter.format(ZonedDateTime.now());
	}

	@Deprecated
	public static Path modifyFileName(Path original, String slug) {
		String[] fn = original.getFileName().toString().split("\\.");
		fn[0] = fn[0] + "." + slug + "-" + TIMESTAMP;
		return original.resolveSibling(String.join(".", fn));
	}

	public static boolean isArchiveTarget(String name) {
		return isZipTarget(name) ||
				isTgzTarget(name) ||
				isTarTarget(name);
	}

	public static void deleteDirectory(Path dir) throws IOException {
		Files.walk(dir)
				.sorted(Comparator.reverseOrder())
				.map(Path::toFile)
				.forEach(File::delete);
	}

	@Deprecated
	public static void safeDelete(String file) {
		try {
			Files.delete(Paths.get(file));
		} catch (IOException e) {
			Logger.warn("Could not delete file " + file);
		}
	}

	public static boolean isZipTarget(String name) {
		String loweredName = name.toLowerCase();
		return loweredName.endsWith(".jar") ||
				loweredName.endsWith(".war") ||
				loweredName.endsWith(".ear") ||
				loweredName.endsWith(".zip") ||
				loweredName.endsWith(".aar");
	}

	@Deprecated
	public static String createPatchedFileName(String srcFile) {
		int lastDotIndex;

		if (isTarGzTarget(srcFile)) {
			lastDotIndex = srcFile.lastIndexOf(".tar.gz");
		} else if (isTarBz2Target(srcFile)) {
			lastDotIndex = srcFile.lastIndexOf(".tar.bz2");
		} else {
			lastDotIndex = srcFile.lastIndexOf(".");
		}

		long random = (long)(Math.random() * 10000);
		return srcFile.substring(0, lastDotIndex) + "-patched" + random + srcFile.substring(lastDotIndex);
	}

	public static boolean is7zTarget(String name) {
		return name.toLowerCase().endsWith(".7z");
	}

	public static boolean isCpioTarget(String name) {
		return name.toLowerCase().endsWith(".cpio");
	}

	public static boolean isArTarget(String name) {
		return name.toLowerCase().endsWith(".ar");
	}

	public static boolean isArjTarget(String name) {
		String loweredName = name.toLowerCase();
		return loweredName.endsWith(".arj");
	}

	public static boolean isTgzTarget(String name) {
		String loweredName = name.toLowerCase();
		return loweredName.endsWith(".tgz") || isTarGzTarget(name);
	}

	public static boolean isTarGzTarget(String name) {
		String loweredName = name.toLowerCase();
		return loweredName.endsWith(".tar.gz");
	}

	public static boolean isTarBz2Target(String name) {
		return name.toLowerCase().endsWith(".tar.bz2");
	}

	public static boolean isTarTarget(String name) {
		return name.toLowerCase().endsWith(".tar");
	}

	public static boolean isSymlink(Path pa) {
		return Files.isSymbolicLink(pa);
	}

	@Deprecated
	public static boolean shouldSkipDirectory(String path) {
		return (path.equals("/proc") || path.startsWith("/proc/")) || (path.equals("/sys") || path.startsWith("/sys/"))
				|| (path.equals("/dev") || path.startsWith("/dev/")) || (path.equals("/run") || path.startsWith("/run/"))
				|| (path.equals("/var/run") || path.startsWith("/var/run/"));
	}

	public static String checksumMd5(File file)
			throws IOException, NoSuchAlgorithmException {

		return checksum(MessageDigest.getInstance("MD5"), file);
	}

	public static String checksum(MessageDigest digest,
								  File file)
			throws IOException {

		FileInputStream fis = new FileInputStream(file);

		byte[] byteArray = new byte[1024];
		int bytesCount = 0;

		while ((bytesCount = fis.read(byteArray)) != -1) {
			digest.update(byteArray, 0, bytesCount);
		}

		fis.close();

		byte[] bytes = digest.digest();

		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < bytes.length; i++) {
			sb.append(Integer
					.toString((bytes[i] & 0xff) + 0x100, 16)
					.substring(1));
		}

		return sb.toString();
	}

	@Deprecated
	public static String updateNestedPath(String nestedPath, Path originalFileBackup) {
		String[] split = nestedPath.split(Constants.NESTED_PATH_SEPARATOR);
		split[0] = originalFileBackup.toString();
		return String.join(Constants.NESTED_PATH_SEPARATOR, split);
	}

	public static boolean isEmpty(Path path) throws IOException {
		if (Files.isDirectory(path)) {
			try (DirectoryStream<Path> directory = Files.newDirectoryStream(path)) {
				return !directory.iterator().hasNext();
			}
		}

		return false;
	}
}

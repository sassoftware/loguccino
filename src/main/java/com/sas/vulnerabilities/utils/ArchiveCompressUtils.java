package com.sas.vulnerabilities.utils;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveOutputStream;
import org.apache.commons.compress.utils.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Optional;

public class ArchiveCompressUtils {

	public static void compressArchive(String dstFile, String folderToZip) throws IOException {
		Optional<ArchiveOutputStream> archiveOutputStreamOpt = ArchiveStreamUtils
				.createArchiveOutputStream(dstFile, new FileOutputStream(dstFile));
		if (!archiveOutputStreamOpt.isPresent()) {
			throw new IOException("Could create appropriate archive output stream for " + dstFile);
		}

		ArchiveOutputStream o = archiveOutputStreamOpt.get();
		try {
			Path folderToZipPath = Paths.get(folderToZip);

			Files.walkFileTree(folderToZipPath, new FileVisitor<Path>() {
				@Override
				public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
					Path relativePath = folderToZipPath.relativize(dir);

					// skip root dir, track only contents
					if (relativePath.toString().equals("")) return FileVisitResult.CONTINUE;

					ArchiveEntry archiveEntry = o.createArchiveEntry(dir, relativePath.toString());
					o.putArchiveEntry(archiveEntry);
					o.closeArchiveEntry();

					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult visitFile(Path path, BasicFileAttributes attrs) throws IOException {
					Path relativePath = folderToZipPath.relativize(path);

					// skip root dir, track only contents
					if (relativePath.toString().equals("")) return FileVisitResult.CONTINUE;

					Path jndiPath = Paths.get(Constants.LOG4J_JNDI_LOOKUP);
					if (relativePath.equals(jndiPath)) {
						return FileVisitResult.CONTINUE;
					}

					File file = path.toFile();

					InputStream i = null;

					try {
						ArchiveEntry archiveEntry = o
								.createArchiveEntry(file, relativePath.toString());
						i = new FileInputStream(file.toString());

						if (!ArchiveStreamUtils.isCompress() && Utils.isZipTarget(archiveEntry.getName())) {
							// don't compress inner zips, especially for spring boot !
							// stored method will be used with crc32 precomputed
							// read all bytes for inner zip to calculate crc32 and sizes
							// todo: try to avoid reading whole inner zip file in memory by using CRC32OutputStream
							byte[] bytes = IOUtils.toByteArray(i);
							IOUtils.closeQuietly(i);
							ArchiveStreamUtils.updateStoredArchiveEntry(archiveEntry, bytes);
							i = new ByteArrayInputStream(bytes);
						}

						o.putArchiveEntry(archiveEntry);
						IOUtils.copy(i, o);
						o.closeArchiveEntry();
					} finally {
						IOUtils.closeQuietly(i);
					}

					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult visitFileFailed(Path path, IOException exc) throws IOException {
					// io exception should be propagated to the caller
					return FileVisitResult.TERMINATE;
				}

				@Override
				public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
					return FileVisitResult.CONTINUE;
				}
			});
		} finally {
			o.finish();
			o.close();
			IOUtils.closeQuietly(o);
		}
	}

	public static void extractArchive(String archivePath, String destDirectory) throws IOException, ArchiveException {

		InputStream inputStream = null;
		try {
			Path filePath = Paths.get(archivePath);
			inputStream = Files.newInputStream(filePath);
			Optional<ArchiveInputStream> archiveInputStreamOpt = ArchiveStreamUtils
					.createArchiveInputStream(archivePath, inputStream);
			if (!archiveInputStreamOpt.isPresent()) {
				throw new IOException("Could create appropriate archive input stream for " + archivePath);
			}

			ArchiveInputStream archiveInputStream = archiveInputStreamOpt.get();

			ArchiveEntry archiveEntry = null;
			while ((archiveEntry = archiveInputStream.getNextEntry()) != null) {
				Path path = Paths.get(destDirectory, archiveEntry.getName());
				File file = path.toFile();
				if (archiveEntry.isDirectory()) {
					if (!file.isDirectory()) {
						boolean mkdirs = file.mkdirs();
						if (!mkdirs) throw new IOException("Could not create directory " + file);
					}
				} else {
					File parent = file.getParentFile();
					if (!parent.isDirectory()) {
						boolean mkdirs = parent.mkdirs();
						if (!mkdirs) throw new IOException("Could not create directory " + file);
					}
					try (OutputStream outputStream = Files.newOutputStream(path)) {
						IOUtils.copy(archiveInputStream, outputStream);
					}
				}
			}
		} finally {
			IOUtils.closeQuietly(inputStream);
		}

	}
}

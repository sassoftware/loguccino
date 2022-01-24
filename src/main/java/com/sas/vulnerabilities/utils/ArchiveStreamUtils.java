package com.sas.vulnerabilities.utils;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveOutputStream;
import org.apache.commons.compress.archivers.ar.ArArchiveEntry;
import org.apache.commons.compress.archivers.ar.ArArchiveInputStream;
import org.apache.commons.compress.archivers.ar.ArArchiveOutputStream;
import org.apache.commons.compress.archivers.arj.ArjArchiveInputStream;
import org.apache.commons.compress.archivers.cpio.CpioArchiveEntry;
import org.apache.commons.compress.archivers.cpio.CpioArchiveInputStream;
import org.apache.commons.compress.archivers.cpio.CpioArchiveOutputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Optional;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipEntry;

public class ArchiveStreamUtils {

	private static boolean compress = false;

	public static Optional<ArchiveInputStream> createArchiveInputStream(String path,
																		InputStream in) throws IOException, ArchiveException {
		ArchiveInputStream archiveInputStream = null;
		if (Utils.isZipTarget(path)) {
			archiveInputStream = new ZipArchiveInputStream(in);
		} else if (Utils.isTgzTarget(path)) {
			InputStream bi = new BufferedInputStream(in);
			InputStream gzi = new GzipCompressorInputStream(bi);
			archiveInputStream = new TarArchiveInputStream(gzi);
		} else if (Utils.isTarTarget(path)) {
			archiveInputStream = new TarArchiveInputStream(in);
		} else if (Utils.isTarBz2Target(path)) {
			BZip2CompressorInputStream gzipInputStream = new BZip2CompressorInputStream(in);
			archiveInputStream = new TarArchiveInputStream(gzipInputStream);
		} else if (Utils.isArjTarget(path)) {
			archiveInputStream = new ArjArchiveInputStream(in);
		} else if (Utils.isCpioTarget(path)) {
			archiveInputStream = new CpioArchiveInputStream(in);
		} else if (Utils.isArTarget(path)) {
			archiveInputStream = new ArArchiveInputStream(in);
		}

		return Optional.ofNullable(archiveInputStream);
	}

	public static Optional<ArchiveOutputStream> createArchiveOutputStream(String path,
																		  OutputStream out) throws IOException {
		ArchiveOutputStream archiveOutputStream = null;
		if (Utils.isZipTarget(path)) {
			archiveOutputStream = new ZipArchiveOutputStream(out);
			if (!compress) {
				((ZipArchiveOutputStream) archiveOutputStream).setLevel(Deflater.NO_COMPRESSION);
			}
		} else if (Utils.isTgzTarget(path)) {
			GZIPOutputStream gzipInputStream = new GZIPOutputStream(out);
			archiveOutputStream = new TarArchiveOutputStream(gzipInputStream);
			((TarArchiveOutputStream) archiveOutputStream).setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_POSIX);
			((TarArchiveOutputStream) archiveOutputStream).setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
		} else if (Utils.isTarTarget(path)) {
			archiveOutputStream = new TarArchiveOutputStream(out);
			((TarArchiveOutputStream) archiveOutputStream).setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_POSIX);
			((TarArchiveOutputStream) archiveOutputStream).setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
		} else if (Utils.isTarBz2Target(path)) {
			BZip2CompressorOutputStream gzipInputStream = new BZip2CompressorOutputStream(out);
			archiveOutputStream = new TarArchiveOutputStream(gzipInputStream);
			((TarArchiveOutputStream) archiveOutputStream).setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_POSIX);
			((TarArchiveOutputStream) archiveOutputStream).setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
//		} else if (Utils.isArjTarget(path)) {
//			archiveOutputStream = new ArArchiveOutputStream(out);
		} else if (Utils.isCpioTarget(path)) {
			archiveOutputStream = new CpioArchiveOutputStream(out);
		} else if (Utils.isArTarget(path)) {
			archiveOutputStream = new ArArchiveOutputStream(out);
		}

		return Optional.ofNullable(archiveOutputStream);
	}

	public static ArchiveEntry copyArchiveEntry(String archiveName, ArchiveEntry inputEntry) throws IOException {
		String path = inputEntry.getName();

		if (Utils.isZipTarget(archiveName)) {
			ZipArchiveEntry archiveEntry = new ZipArchiveEntry(path);
			archiveEntry.setSize(inputEntry.getSize());
			return archiveEntry;

		} else if (Utils.isTgzTarget(archiveName)) {
			TarArchiveEntry archiveEntry = new TarArchiveEntry(path);
			archiveEntry.setSize(inputEntry.getSize());
			return archiveEntry;

		} else if (Utils.isTarTarget(archiveName)) {
			TarArchiveEntry archiveEntry = new TarArchiveEntry(path);
			archiveEntry.setSize(inputEntry.getSize());
			return archiveEntry;

		} else if (Utils.isTarBz2Target(archiveName)) {
			TarArchiveEntry archiveEntry = new TarArchiveEntry(path);
			archiveEntry.setSize(inputEntry.getSize());
			return archiveEntry;

//		} else if (Utils.isArjTarget(path)) {
//			archiveOutputStream = new ArArchiveOutputStream(out);
		} else if (Utils.isCpioTarget(archiveName)) {
			CpioArchiveEntry archiveEntry = new CpioArchiveEntry(path);
			archiveEntry.setSize(inputEntry.getSize());
			return archiveEntry;

		} else if (Utils.isArTarget(archiveName)) {
			ArArchiveEntry archiveEntry = new ArArchiveEntry(path, 0);
			return archiveEntry;
		}

		return null;
	}

	public static void updateStoredArchiveEntry(ArchiveEntry e, byte[] bytes) {
		if (!compress && e instanceof ZipArchiveEntry) {
			((ZipArchiveEntry) e).setMethod(ZipEntry.STORED);
			((ZipArchiveEntry) e).setCompressedSize(bytes.length);
			((ZipArchiveEntry) e).setSize(bytes.length);
			((ZipArchiveEntry) e).setCrc(computeCrc32(bytes));
		}
	}

	private static long computeCrc32(byte[] buf) {
		CRC32 crc = new CRC32();
		crc.update(buf, 0, buf.length);
		return crc.getValue();
	}

	public static void setCompress(boolean compress) {
		ArchiveStreamUtils.compress = compress;
	}

	public static boolean isCompress() {
		return compress;
	}
}

package com.sas.vulnerabilities.patcher;

import com.sas.vulnerabilities.utils.ArchiveCompressUtils;
import com.sas.vulnerabilities.utils.Utils;
import org.apache.commons.compress.archivers.ArchiveException;
import org.tinylog.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Set;

import static com.sas.vulnerabilities.utils.Constants.NESTED_PATH_SEPARATOR;
import static com.sas.vulnerabilities.utils.Utils.withoutColon;

/**
 * This patcher is designed to work only one row (one nested path) from csv file.
 * and should be coupled with SequentialPatcherInventoryService to run it multiple
 * times on the same file
 */
public class  SequentialPatcher extends AbstractPatcher {
	public SequentialPatcher(Path tempDir) {
		super(tempDir);
	}

	private void packageNextArchive(int i, Path tmpDir, String[] nestedList, String dstFile) throws IOException {
		String dstArchive;

		if (i == 0) {
			dstArchive = dstFile;
		} else {
			dstArchive = Paths.get(tmpDir.toString(), String.valueOf(i - 1), nestedList[i]).toString();
		}

		String folderToZip = Paths.get(tmpDir.toString(), String.valueOf(i)).toString();

		ArchiveCompressUtils.compressArchive(dstArchive, folderToZip);

		if (--i >= 0) {
			packageNextArchive(i, tmpDir, nestedList, dstFile);
		}
	}

	public void patchSingleCVE(String nestedPath, String srcFile, String dstFile, String tempDir) throws IOException, ArchiveException {
		Logger.info("Patching path: " + srcFile);

		Path srcFilePath = Paths.get(srcFile);
		Set<PosixFilePermission> filePermissions = Files.getPosixFilePermissions(srcFilePath);
		GroupPrincipal group = Files.readAttributes(srcFilePath, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS).group();
		UserPrincipal owner = Files.getOwner(srcFilePath);

		String[] nestedList = nestedPath.split(NESTED_PATH_SEPARATOR);
		if (nestedList.length == 0) {
			System.out.println("No nested path provided for patcher");
			return;
		}

		Path tmpDir = Paths.get(tempDir);

		try {
			extractNextArchive(0, tmpDir, tmpDir, nestedList);
			packageNextArchive(nestedList.length - 1, tmpDir, nestedList, dstFile);
		} finally {
			try {
				Utils.deleteDirectory(tmpDir);
			} catch (IOException e) {
				Logger.error("Could not delete temporary directory: " + tmpDir.toFile().getCanonicalPath() + ". " +
						"Try to delete it manually. The exception was: " + e);
			}
		}

		Path dstFilePath = Paths.get(dstFile);
		Files.setPosixFilePermissions(dstFilePath, filePermissions);
		Files.setOwner(dstFilePath, owner);
		Files.getFileAttributeView(dstFilePath, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).setGroup(group);

		Logger.info("Patched single cve {} to {} ", nestedPath, dstFilePath.toFile().getCanonicalPath());
	}

	private void extractNextArchive(int currentArchive,
									Path tmpDir,
									Path prevLevelDir,
									String[] nestedList) throws IOException, ArchiveException {

		Path currentDstDir = Files.createDirectories(Paths.get(tmpDir.toString(), String.valueOf(currentArchive)));
		String archive = nestedList[currentArchive];

		Path baseArchivePath = currentArchive == 0 ? Paths.get(archive) : Paths.get(prevLevelDir.toString(), withoutColon(archive)); // don't ask
		ArchiveCompressUtils.extractArchive(baseArchivePath.toString(), currentDstDir.toString());

		if (++currentArchive < nestedList.length) {
			extractNextArchive(currentArchive, tmpDir, currentDstDir, nestedList);
		}
	}

}


package com.sas.vulnerabilities.patcher;

import com.opencsv.CSVWriter;
import com.sas.vulnerabilities.model.VulnerableArchive;
import lukfor.progress.tasks.ITaskRunnable;
import lukfor.progress.tasks.monitors.ITaskMonitor;
import org.tinylog.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;

import static com.sas.vulnerabilities.utils.Utils.adapt;
import static com.sas.vulnerabilities.utils.Utils.checksum;

public class SequentialPatcherInventoryTask implements ITaskRunnable {
	private VulnerableArchive v;
	private SequentialPatcher patcher;
	private int current;
	private Path originalsDir;
	private Path tempsDir;
	private CSVWriter csvWriter;


	/**
	 *
	 * create patch dirs and logs:
	 *
	 * ./patch_[timestamp] as main patch container
	 * ./patch_[timestamp]/patch.log for the log
	 * ./patch_[timestamp]/temp as a tmp for intermediate unpacking and repacking, referred to ${temps_dir} from here
	 * ./patch_[timestamp]/originals as backup dir, referred to as ${origs_dir}
	 *
	 * @param v
	 * @param patcher
	 * @param current
	 * @param originalsDir
	 * @param tempsDir
	 * @param csvWriter
	 */
	public SequentialPatcherInventoryTask(VulnerableArchive v,
										  SequentialPatcher patcher,
										  int current,
										  Path originalsDir,
										  Path tempsDir,
										  CSVWriter csvWriter) {
		this.v = v;
		this.patcher = patcher;
		this.current = current;
		this.originalsDir = originalsDir;
		this.tempsDir = tempsDir;
		this.csvWriter = csvWriter;
	}

	public void runSingleCveInventoryPath() throws Exception {
		if (v.isPatched()) return;

		Path currentIterationOrig = Paths.get(originalsDir.toString(), String.valueOf(current)); // ${origs_dir}/1/ , 1 is current iteration number
		Path currentIterationTemp = Paths.get(tempsDir.toString(), String.valueOf(current)); //  {temps_dir}/1/
		String affectedFile = v.getAffectedFile();
		Path affectedFilePath = Paths.get(affectedFile);

		// create new {temps_dir}/1/pub/hyper_noJRE.tar.gz (single cve patch) by reading the original /pub/hyper_noJRE.tar.gz file and patching it
		// only for blah.jar vulnerability, using the tmp location ${temps_dir}/1 to unpack all intermediate temp files
		Path patchedSingleCve = Paths.get(currentIterationTemp.toString(), adapt(affectedFile));
		Files.createDirectories(patchedSingleCve.getParent());
		patcher.patchSingleCVE(
				v.getNestedPath(),
				affectedFile,
				patchedSingleCve.toString(),
				Paths.get(currentIterationTemp.toString(), "patcher-temp").toString());

		// if checksum fails, exception will be thrown and inventory patching will stop at current task (current csv row)
		String originalChecksum = checksum(MessageDigest.getInstance("MD5"), new File(affectedFile));
		String patchedChecksum = checksum(MessageDigest.getInstance("MD5"), new File(patchedSingleCve.toString()));

		// switch places. move original (affected) to backup location, and move patched (with single cve) to original location
		Path originalFileBackup = Paths.get(currentIterationOrig.toString(), adapt(affectedFile));
		Files.createDirectories(originalFileBackup.getParent());
		Files.move(affectedFilePath, originalFileBackup);
		Files.move(patchedSingleCve, affectedFilePath);

		try {
			csvWriter.writeNext(new String[]{originalFileBackup.toString(), affectedFilePath.toString(), originalChecksum, patchedChecksum});
			csvWriter.flush();
		} catch (IOException e) {
			Logger.error(e, "Error writing to csv output");
		}
	}

	@Override
	public void run(ITaskMonitor monitor) throws Exception {
		monitor.begin(String.format("Patching %s, path %s", v.getAffectedFile(), v.getNestedPath()));

		runSingleCveInventoryPath();

		monitor.done();
	}
}

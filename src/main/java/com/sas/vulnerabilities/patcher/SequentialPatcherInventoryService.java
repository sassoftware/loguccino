package com.sas.vulnerabilities.patcher;

import static lukfor.progress.Components.*;

import com.opencsv.CSVWriter;
import com.sas.vulnerabilities.model.PatchedVulnerability;
import com.sas.vulnerabilities.model.VulnerableArchive;
import com.sas.vulnerabilities.utils.Utils;
import lukfor.progress.TaskService;
import lukfor.progress.tasks.ITaskRunnable;
import lukfor.progress.tasks.Task;
import lukfor.progress.tasks.TaskFailureStrategy;
import org.tinylog.Logger;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Vector;

public class SequentialPatcherInventoryService {
	Path outputCsvFile;
	Path inventoryTempsDir;
	Path inventoryOriginalsDir;
	Path inventoryPatcherTempDirs;
	private Path patchStore;

	public SequentialPatcherInventoryService (Path patchStore) throws IOException {
		this.patchStore = patchStore;

		try {
			Files.createDirectories(patchStore);
		} catch (IOException e) {
			Logger.error("Could not create patcher working dir {} ", patchStore);
			Logger.info("Patch aborted");
			throw e;
		}

		this.inventoryTempsDir = patchStore.resolve("inventoryTemps");
		this.inventoryOriginalsDir = patchStore.resolve("inventoryOriginals");
		this.inventoryPatcherTempDirs = patchStore.resolve("patcherTemps");
	}

	public void patchInventory(List<VulnerableArchive> allVulnerabilities, boolean pretty, TaskFailureStrategy taskFailureStrategy) {
		this.outputCsvFile = patchStore.resolve("patch.csv");

		TaskService.setAnsiSupport(pretty);
		TaskService.setThreads(1);
		TaskService.setTarget(System.err);
		TaskService.setFailureStrategy(taskFailureStrategy);

		List<ITaskRunnable> tasks = new Vector<>();
		try (FileOutputStream fos = new FileOutputStream(outputCsvFile.toString());
			 OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
			 CSVWriter csvWriter = new CSVWriter(osw)) {

			csvWriter.writeNext(new String[]{"originalFileBackup", "affectedFilePath", "originalChecksum", "patchedChecksum"});
			csvWriter.flush();

			int i = 0;
			for (VulnerableArchive v : allVulnerabilities) {
				if (v.isPatched()) continue;

				// temp directory where single cve patch files are stored
				Path patcherWorkDir = Paths.get(inventoryPatcherTempDirs.toString(), "patcher", String.valueOf(i));
				Files.createDirectories(patcherWorkDir.getParent());
				SequentialPatcher patcher = new SequentialPatcher(patcherWorkDir);

				tasks.add(new SequentialPatcherInventoryTask(
						v, patcher, i, inventoryOriginalsDir, inventoryTempsDir, csvWriter));

				i++;
			}

			List<Task> futures = TaskService.monitor(SPINNER, TASK_NAME).run(tasks);
			for (Task task : futures) {
				if (task.getStatus().getThrowable() != null) {
					Logger.tag("SYSTEM").error(task.getStatus().getThrowable(), "Error while patching ");
				}
			}

			Logger.tag("SYSTEM").info("Patch results written to CSV file: " + outputCsvFile.toFile().getCanonicalPath());
		} catch (IOException e) {
			Logger.error(e, "Error while writing patch csv to output " + outputCsvFile);
		}
	}

	public void unpatchInventory(List<PatchedVulnerability> allPatches, boolean pretty, TaskFailureStrategy taskFailureStrategy) {
		this.outputCsvFile = patchStore.resolve("revert-patch.csv");

		TaskService.setAnsiSupport(pretty);
		TaskService.setThreads(1);
		TaskService.setTarget(System.err);
		TaskService.setFailureStrategy(taskFailureStrategy);

		List<ITaskRunnable> tasks = new Vector<>();
		try (FileOutputStream fos = new FileOutputStream(outputCsvFile.toString());
			 OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
			 CSVWriter csvWriter = new CSVWriter(osw)) {

			csvWriter.writeNext(new String[]{"originalFileBackup", "affectedFilePath", "originalChecksum", "patchedChecksum", "reverted"});
			csvWriter.flush();

			for (int i = allPatches.size() - 1; i >= 0; i--) {
				PatchedVulnerability lastPatch = allPatches.get(i);

				tasks.add(monitor -> {
					monitor.begin("Revert " + lastPatch.getOriginalFileBackup());
					Path target = Paths.get(lastPatch.getAffectedFilePath());

					String currentChecksum = Utils.checksumMd5(target.toFile());
					String lastPatchedChecksum = lastPatch.getPatchedChecksum();
					if (!lastPatchedChecksum.equals(currentChecksum)) {
						String message = "Checksums of current and patched files don't match. Current file " +
								lastPatch.getAffectedFilePath() + " checksum is " + currentChecksum + " and last recorded patched checksum was " +
								lastPatchedChecksum;
						// cancel task
						throw new IllegalStateException(message);
					}

					Files.delete(target);
					Files.move(Paths.get(lastPatch.getOriginalFileBackup()), target);

					// cancel task if exception occurs
					csvWriter.writeNext(new String[]{
							lastPatch.getOriginalFileBackup(),
							lastPatch.getAffectedFilePath(),
							lastPatch.getOriginalChecksum(),
							lastPatch.getPatchedChecksum(),
							Boolean.toString(true)});

					csvWriter.flush();
				});

			}

			List<Task> futures = TaskService.monitor(SPINNER, TASK_NAME).run(tasks);
			for (Task task : futures) {
				Throwable throwable = task.getStatus().getThrowable();
				if (throwable != null) {
					if (throwable instanceof IllegalStateException) {
						Logger.tag("SYSTEM").error("Error while reverting: " + throwable.getMessage());
					} else {
						Logger.tag("SYSTEM").error(throwable, "Error while reverting ");
					}
				}
			}

			Logger.tag("SYSTEM").info("Revert results written to CSV file: " + outputCsvFile.toFile().getCanonicalPath());
		} catch (IOException e) {
			Logger.error(e, "Error while writing revert csv to output " + outputCsvFile);
		}
	}
}

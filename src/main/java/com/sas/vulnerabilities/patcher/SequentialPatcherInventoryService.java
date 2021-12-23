package com.sas.vulnerabilities.patcher;

import static lukfor.progress.Components.*;

import com.opencsv.CSVWriter;
import com.sas.vulnerabilities.model.VulnerableArchive;
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
import java.util.Set;
import java.util.Vector;

public class SequentialPatcherInventoryService {
	Set<VulnerableArchive> allVulnerabilities;
	Path outputCsvFile;
	Path inventoryTempsDir;
	Path inventoryOriginalsDir;
	Path inventoryPatcherTempDirs;

	public SequentialPatcherInventoryService (Set<VulnerableArchive> allVulnerabilities, Path patchStore) throws IOException {
		this.allVulnerabilities = allVulnerabilities;

		try {
			Files.createDirectories(patchStore);
		} catch (IOException e) {
			Logger.error("Could not create patcher working dir {} ", patchStore);
			Logger.info("Patch aborted");
			throw e;
		}

		this.outputCsvFile = patchStore.resolve("patch.csv");
		this.inventoryTempsDir = patchStore.resolve("inventoryTemps");
		this.inventoryOriginalsDir = patchStore.resolve("inventoryOriginals");
		this.inventoryPatcherTempDirs = patchStore.resolve("patcherTemps");
	}

	public void start(boolean pretty, TaskFailureStrategy taskFailureStrategy) {
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

			Logger.tag("SYSTEM").info("Results written to CSV file: " + outputCsvFile.toFile().getCanonicalPath());
		} catch (IOException e) {
			Logger.error(e, "Error while writing csv to output " + outputCsvFile);
		}
	}
}

package com.sas.vulnerabilities;

import static com.sas.vulnerabilities.utils.Constants.TIMESTAMP;

import com.sas.vulnerabilities.model.VulnerableArchive;
import com.sas.vulnerabilities.patcher.SequentialPatcherInventoryService;
import com.sas.vulnerabilities.utils.ArchiveStreamUtils;
import com.sas.vulnerabilities.utils.Utils;
import com.opencsv.exceptions.CsvException;
import org.tinylog.Logger;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Spec.Target;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import java.util.concurrent.Callable;

@Command(name = "patch", description = "Patches identified vulnerabilities")
public class PatchCommand extends BaseSubcommand implements Callable<Integer> {
	private Path patchStore = Paths.get( "./loguccino-patch-" + TIMESTAMP);

	@Spec(Target.SELF) CommandSpec spec;

	@SuppressWarnings("unused")
	@Option(
			names = {"-s", "--patch-store"},
			description = {
					"Location where patch results and temporary files are stored.",
					"Default value: ./loguccino-patch-{date: ddMMyyyyHHmmss}"
			})
	public void setPatchStore(Path patchStore) {
		if (patchStore != null) {
			if (Files.isRegularFile(patchStore) || !Files.isWritable(patchStore)) {
				throw new ParameterException(spec.commandLine(),
						String.format("Invalid value '%s' for option '--patch-store': " +
								"value is not a writable directory path", patchStore));
			}
			this.patchStore = patchStore;
		}
	}

	@Option(names = "--no-compress", negatable = true, description = {"Enable/Disable compression for any zip file (including jar, war, ear, ...).", "Default value: --compress"})
	boolean compress = true;

	@Parameters(index = "0", description = "Path of inventory (csv file) produced by running loguccino scan")
	String inventory;

	@Override
	public Integer call() {
		return patchFromInventory();
	}

	public static void main(String[] args) {
		int exitCode = new CommandLine(new PatchCommand()).execute(args);
		System.exit(exitCode);
	}

	private int patchFromInventory() {
		ArchiveStreamUtils.setCompress(compress);
		Logger.tag("SYSTEM").info("Started patch from inventory using inventory scan results " + inventory);

		Path inventoryPath = Paths.get(inventory);
		if (Files.notExists(inventoryPath) || !Files.isRegularFile(inventoryPath)) {
			throw new ParameterException(spec.commandLine(), "Invalid patch path, expecting inventory Path file.");
		}

		Set<VulnerableArchive> allVulnerabilities;
		try {
			allVulnerabilities = Utils.readAllVulnerabilities(inventory);
		} catch (IOException | CsvException e) {
			throw new ParameterException(spec.commandLine(), e.getMessage());
		}

		if (allVulnerabilities.size() == 0) {
			Logger.tag("SYSTEM").info("Inventory contains no vulnerabilities.  Nothing to do.");
			return 0;
		}

		try {
			new SequentialPatcherInventoryService(allVulnerabilities, patchStore).start(pretty, taskFailureStrategy);
		} catch (IOException e) {
			Logger.tag("SYSTEM").error(e, "Error initializing patcher ");
		}
		return 0;
	}
}

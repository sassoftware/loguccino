package com.sas.vulnerabilities;

import static com.sas.vulnerabilities.utils.Constants.TIMESTAMP;

import com.sas.vulnerabilities.model.PatchedVulnerability;
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
import java.util.List;
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
		try {
			if (Utils.isEmpty(patchStore)) {
				this.patchStore = patchStore;
			} else if (Files.exists(patchStore)) {
				throw new ParameterException(spec.commandLine(),
						String.format("Invalid value %s for option '--patch-store': " +
								"not an empty directory", patchStore));
			} else {
				this.patchStore = patchStore;
			}
		} catch (IOException e) {
			throw new ParameterException(spec.commandLine(), "Invalid value %s for option '--patch-store': ", e);
		}
	}

	@Option(names = "--no-compress", negatable = true, description = {"Enable/Disable compression for any zip file (including jar, war, ear, ...).", "Default value: --compress"})
	boolean compress = true;

	@Option(names = {"-r", "--revert"}, description = {"Reverts previous patch provided by patch csv results."})
	boolean revert = false;

	@Parameters(index = "0", description = "Path of inventory (csv file) produced by running loguccino scan or patch to patch output csv if --revert specified.")
	String inventory;

	@Override
	public Integer call() {
		if (!revert) {
			return patchFromInventory();
		} else {
			return revertInventory();
		}
	}

	public static void main(String[] args) {
		int exitCode = new CommandLine(new PatchCommand()).execute(args);
		System.exit(exitCode);
	}

	private int patchFromInventory() {
		ArchiveStreamUtils.setCompress(compress);
		Logger.tag("SYSTEM").info("Started patch from inventory using inventory scan results " + inventory);

		List<VulnerableArchive> allVulnerabilities;
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
			new SequentialPatcherInventoryService(patchStore)
					.patchInventory(allVulnerabilities, pretty, taskFailureStrategy);
		} catch (IOException e) {
			Logger.tag("SYSTEM").error(e, "Error initializing patcher ");
		}
		return 0;
	}

	private Integer revertInventory() {
		ArchiveStreamUtils.setCompress(compress);
		Logger.tag("SYSTEM").info("Started revert from inventory using patch results " + inventory);

		List<PatchedVulnerability> all;
		try {
			all = Utils.readAllPatchedVulnerabilities(inventory);
		} catch (IOException | CsvException e) {
			throw new ParameterException(spec.commandLine(), e.getMessage());
		}

		if (all.size() == 0) {
			Logger.tag("SYSTEM").info("Patch results contain no vulnerabilities.  Nothing to do.");
			return 0;
		}

		try {
			new SequentialPatcherInventoryService(patchStore)
					.unpatchInventory(all, pretty, taskFailureStrategy);
		} catch (IOException e) {
			Logger.tag("SYSTEM").error(e, "Error initializing patcher");
		}
		return 0;
	}
}

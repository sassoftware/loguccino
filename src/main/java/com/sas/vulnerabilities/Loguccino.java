package com.sas.vulnerabilities;

import com.sas.vulnerabilities.utils.ManifestVersionProvider;
import com.sas.vulnerabilities.utils.ShortErrorMessageHandler;
import picocli.CommandLine;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Command;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

import java.util.concurrent.Callable;


@Command(
		name = "loguccino", versionProvider = ManifestVersionProvider.class, usageHelpAutoWidth = true,
		header = {
		"@|yellow                                       |@",
		"@|yellow  __                        _          |@",
		"@|yellow |  |   ___ ___ _ _ ___ ___|_|___ ___  |@",
		"@|yellow |  |__| . | . | | |  _|  _| |   | . | |@",
		"@|yellow |_____|___|_  |___|___|___|_|_|_|___| |@",
		"@|yellow           |___|                       |@",
		""
		},
		description = {
				"",
				"A utility to recursively scan and detect vulnerable jar files.",
				"",
		},
		footer = {
				"",
				"See 'loguccino help <command>' to read about a specific subcommand"
		},
		subcommands = {CommandLine.HelpCommand.class, PatchCommand.class, ScanCommand.class})
public class Loguccino implements Callable<Integer> {
	@Spec
	CommandSpec spec;

	@CommandLine.Mixin
	LoggingMixin loggingMixin;

	@Override
	public Integer call() {
		throw new ParameterException(spec.commandLine(), "Missing required subcommand");
	}

	@SuppressWarnings("unused")
	@Command(name = "version", description = "Displays version info")
	int version() {
		spec.commandLine().printVersionHelp(System.out);
		return 0;
	}

	public static void main(String... args) {
		int exitCode = new CommandLine(new Loguccino())
				.setParameterExceptionHandler(new ShortErrorMessageHandler())
				.setExecutionStrategy(LoggingMixin::executionStrategy)
				.execute(args);
		System.exit(exitCode);
	}
}
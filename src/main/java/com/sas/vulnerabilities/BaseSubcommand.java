package com.sas.vulnerabilities;

import lukfor.progress.tasks.TaskFailureStrategy;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

@Command(usageHelpAutoWidth = true)
public class BaseSubcommand {
    @SuppressWarnings("unused")
    @Mixin
    LoggingMixin loggingMixin;

    @Option(names = "--failure-strategy", description = {"How to proceed scanning additional directories if there is an error.", "Default value: ${DEFAULT-VALUE}", "Valid values: ${COMPLETION-CANDIDATES}"}, defaultValue = "CANCEL_TASKS")
    TaskFailureStrategy taskFailureStrategy;

    @Option(names = "--no-pretty", description = "Enable ansi console animations", negatable = true)
    boolean pretty = true;
}

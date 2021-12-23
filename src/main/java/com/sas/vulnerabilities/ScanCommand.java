package com.sas.vulnerabilities;

import static com.sas.vulnerabilities.utils.Constants.TIMESTAMP;
import static lukfor.progress.Components.*;

import com.opencsv.CSVWriter;
import com.sas.vulnerabilities.model.VulnerableArchive;
import com.sas.vulnerabilities.scanner.Scanner;
import lukfor.progress.TaskService;
import lukfor.progress.tasks.ITaskRunnable;
import org.tinylog.Logger;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.Callable;

@Command(name = "scan", description = "Scans for vulnerabilities")
public class ScanCommand extends BaseSubcommand implements Callable<Integer> {

    @Option(
            names = {"-o", "--output"}, fallbackValue = "./loguccino.csv",
            description = {
                    "The inventory file scan results will be recorded.",
                    "Default value: ./loguccino-scan-{date: ddMMyyyyHHmmss}.csv"
            })
    Path output = Paths.get("./loguccino-scan-" + TIMESTAMP + ".csv");

    @Parameters(arity = "1..*", description = "The directory to scan.", defaultValue = ".")
    List<Path> directoriesToScan;

    @Override
    public Integer call() {
        TaskService.setAnsiSupport(pretty);
        TaskService.setThreads(1);
        TaskService.setFailureStrategy(taskFailureStrategy);

        try (OutputStream os = Files.newOutputStream(output, StandardOpenOption.CREATE_NEW); OutputStreamWriter osw = new OutputStreamWriter(os, StandardCharsets.UTF_8); CSVWriter csv = new CSVWriter(osw)) {
            csv.writeNext(VulnerableArchive.HEADING);
            csv.flush();

            List<ITaskRunnable> tasks = new Vector<>();
            directoriesToScan.stream().map(d -> d.toAbsolutePath().normalize()).forEachOrdered(root -> tasks.add(createTask(root, csv)));
            TaskService.monitor(SPINNER, TASK_NAME).run(tasks);

            Logger.tag("SYSTEM").info("Results written to CSV file: " + output.toFile().getCanonicalPath());
        } catch (IOException e) {
            Logger.tag("SYSTEM").error(e, "Writing to output failed");
        }
        return 0;
    }

    public ITaskRunnable createTask(Path root, CSVWriter output) {
        return new Scanner(root, output);
    }
}
package com.sas.vulnerabilities.scanner;

import com.opencsv.CSVWriter;
import com.sas.vulnerabilities.model.VulnerableArchive;
import lukfor.progress.tasks.ITaskRunnable;
import org.tinylog.Logger;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public abstract class AbstractScanner implements ITaskRunnable {
    protected final Path root;
    protected final CSVWriter output;

    protected long scanDirCount = 0;
    protected long scanFileCount = 0;

    protected List<String> failedToReadArchives = new ArrayList<>();
    protected List<VulnerableArchive> vulnerabilities = new ArrayList<>();

    public AbstractScanner(Path root, CSVWriter output) {
        this.root = root;
        this.output = output;
    }

    protected void writeReport(List<VulnerableArchive> vulnerabilities) {
        List<String[]> results = new ArrayList<>();

        vulnerabilities.stream()
                .map(VulnerableArchive::toCsvRow)
                .forEach(results::add);

        try {
            output.writeAll(results);
            output.flush();
        } catch (IOException e) {
            Logger.error(e, "Failed to write vulnerabilities to report csv.");
        }
    }
}

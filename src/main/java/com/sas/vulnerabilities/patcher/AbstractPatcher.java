package com.sas.vulnerabilities.patcher;

import java.nio.file.Path;

public abstract class AbstractPatcher {
    protected final Path tempDir;

    public AbstractPatcher(Path tempDir) {
        this.tempDir = tempDir;
    }
}
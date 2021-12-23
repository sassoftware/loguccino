package com.sas.vulnerabilities;

import static com.sas.vulnerabilities.utils.Constants.TIMESTAMP;
import org.tinylog.Level;
import org.tinylog.configuration.Configuration;
import picocli.CommandLine;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParseResult;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Spec.Target;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * This is a mixin that adds a {@code --verbose} option to a command.
 * This class will configure Slf4j, using the specified verbosity:
 * <ul>
 *     <li>{@code -vv} : TRACE level is enabled</li>
 *     <li>{@code -v} : DEBUG level is enabled</li>
 *     <li>(not specified) : INFO level is enabled</li>
 * </ul>
 * <p>
 *     To add the {@code --verbose} option to a command, simple declare a {@code @Mixin}-annotated field with type {@code LoggingMixin}
 *     (if your command is a class), or a {@code @Mixin}-annotated method parameter of type {@code LoggingMixin} if your command
 *     is a {@code @Command}-annotated method.
 * </p>
 * <p>
 *     This mixin can be used on multiple commands, on any level in the command hierarchy.
 * </p>
 * <p>
 *     Make sure that {@link #configureLoggers} is called before executing any command.
 *     This can be accomplished with:
 * </p>
 * <pre>
 * public static void main(String... args) {
 *     new CommandLine(new Loguccino())
 *             .setExecutionStrategy(LoggingMixin::executionStrategy))
 *             .execute(args);
 * }
 * </pre>
 *
 * @author Remko Popma (https://github.com/remkop)
 */
public class LoggingMixin {
    @SuppressWarnings("unused")
    private @Spec(Target.MIXEE)
    CommandLine.Model.CommandSpec mixee;

    private boolean[] verbosity = new boolean[0];
    private Path logfile = Paths.get("./loguccino-" + TIMESTAMP + ".log");

    private static LoggingMixin getTopLevelCommandLoggingMixin(CommandLine.Model.CommandSpec commandSpec) {
        return ((Loguccino) commandSpec.root().userObject()).loggingMixin;
    }

    /**
     * Set the specified log filename on the LoggingMixin of the top-level command.
     * @param logfile the new logfile value
     */
    @SuppressWarnings("unused")
    @Option(names = {"--log"},
            description = {
                    "The path where logging messages will be written.",
                    "Default value: loguccino-{date: ddMMyyyyHHmmss}.log"
            })
    public void setLogfile(Path logfile) {
        getTopLevelCommandLoggingMixin(mixee).logfile = logfile;
    }

    /**
     * Sets the specified verbosity on the LoggingMixin of the top-level command.
     * @param verbosity the new verbosity value
     */
    @SuppressWarnings("unused")
    @Option(names = {"-v", "--verbose"}, description = {
            "Specify multiple -v options to increase verbosity.",
            "For example, `-v -v` or `-vv`"})
    public void setVerbose(boolean[] verbosity) {
        getTopLevelCommandLoggingMixin(mixee).verbosity = verbosity;
    }

    /**
     * Returns the verbosity from the LoggingMixin of the top-level command.
     * @return the verbosity value
     */
    public boolean[] getVerbosity() {
        return getTopLevelCommandLoggingMixin(mixee).verbosity;
    }

    /**
     * Configures Slf4j based on the verbosity level of the top-level command's LoggingMixin,
     * before invoking the default execution strategy ({@link picocli.CommandLine.RunLast RunLast}) and returning the result.
     * <p>
     *     Example usage:
     * </p>
     * <pre>
     * public void main(String... args) {
     *     new CommandLine(new Loguccino())
     *             .setExecutionStrategy(LoggingMixin::executionStrategy))
     *             .execute(args);
     * }
     * </pre>
     *
     * @param parseResult represents the result of parsing the command line
     * @return the exit code of executing the most specific subcommand
     */
    public static int executionStrategy(ParseResult parseResult) {
        init(parseResult);
        return new CommandLine.RunLast().execute(parseResult);
    }

    private static void init(ParseResult parseResult) {
        LoggingMixin mixee = getTopLevelCommandLoggingMixin(parseResult.commandSpec());
        if (mixee.logfile == null) {
            String subcommand = parseResult.expandedArgs().stream().filter(s -> Arrays.asList("scan", "patch").contains(s)).findFirst().orElse("") + "-";
            mixee.logfile = Paths.get("./loguccino-" + subcommand + TIMESTAMP + ".log");
        }
        getTopLevelCommandLoggingMixin(parseResult.commandSpec()).configureLoggers();
    }

    /**
     * Configures the Slf4j console append, using the specified verbosity:
     * <ul>
     *     <li>{@code -vv} : enable TRACE level</li>
     *     <li>{@code -v} : enable DEBUG level</li>
     *     <li>(not specified) : enable INFO level</li>
     * </ul>
     */
    public void configureLoggers() {
        Level level = getTopLevelCommandLoggingMixin(mixee).calcLogLevel();
        Configuration.set("writerC", "console");
        Configuration.set("writerC.tag", "SYSTEM");
        Configuration.set("writerC.level", "INFO");
        Configuration.set("writerC.format", "{level}: {message|indent=4}");
        Configuration.set("writerF", "rolling file");
        Configuration.set("writerF.file", getTopLevelCommandLoggingMixin(mixee).logfile.toString());
        Configuration.set("writerF.format", "{date: HH:mm:ss.SSS} {level}: {message|indent=4}{exception|indent=4}");
        Configuration.set("writerF.level", level.name());
    }

    private Level calcLogLevel() {
        switch (getVerbosity().length) {
            case 0: return Level.INFO;
            case 1: return Level.DEBUG;
            default: return Level.TRACE;
        }
    }
}
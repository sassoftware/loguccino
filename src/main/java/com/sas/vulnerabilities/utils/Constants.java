package com.sas.vulnerabilities.utils;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public class Constants {
    public static final String POM_PROPERTIES = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties";
    public static final String LOG4J_JNDI_LOOKUP = "org/apache/logging/log4j/core/lookup/JndiLookup.class";
    public static final String NESTED_PATH_SEPARATOR = "::";
    public static final int INVENTORY_SKIP_LINES = 1;
    public static final String TIMESTAMP = DateTimeFormatter.ofPattern("ddMMyyyyHHmmss").format(ZonedDateTime.now());
}
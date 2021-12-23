package com.sas.vulnerabilities.utils;

import picocli.CommandLine;

import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

/**
 * {@link picocli.CommandLine.IVersionProvider} implementation that returns version information from the loguccino-x.x.x.jar file's {@code /META-INF/MANIFEST.MF} file.
 */
public class ManifestVersionProvider implements CommandLine.IVersionProvider {
    @Override
    public String[] getVersion() throws Exception {
        Enumeration<URL> resources = ManifestVersionProvider.class.getClassLoader().getResources("META-INF/MANIFEST.MF");
        while (resources.hasMoreElements()) {
            URL url = resources.nextElement();
            try {
                Manifest manifest = new Manifest(url.openStream());
                if (isApplicableManifest(manifest)) {
                    Attributes attributes = manifest.getMainAttributes();
                    return new String[] {
                            get(attributes, "Implementation-Title") + " version " + get(attributes, "Implementation-Version"),
                            "JVM: ${java.version} (${java.vendor} ${java.vm.name} ${java.vm.version})",
                            "OS: ${os.name} ${os.version} ${os.arch}"
                    };
                }
            } catch (IOException ex) {
                return new String[] { "unknown" };
            }
        }
        return new String[0];
    }

    private boolean isApplicableManifest(Manifest manifest) {
        Attributes attributes = manifest.getMainAttributes();
        return "loguccino".equals(get(attributes, "Implementation-Title"));
    }

    private static Object get(Attributes attributes, String key) {
        return attributes.get(new Attributes.Name(key));
    }
}

package com.sas.vulnerabilities.model;

import java.util.Objects;

import static com.sas.vulnerabilities.utils.Constants.*;

public class VulnerableArchive {
	public static final String[] HEADING = new String[]{"AffectedFile", "NestedPath", "AffectedVersion", "Patched"};

	private String affectedFile;
	private String nestedPath;
	private Version version;
	private boolean patched;

	public VulnerableArchive() {
	}

	public VulnerableArchive(String rootFile, String nestedPath, Version version) {
		this.affectedFile = rootFile;
		this.nestedPath = nestedPath;
		this.version = version;
	}

	public static VulnerableArchive fromCsvRow(String[] csvRow) {
		VulnerableArchive v = new VulnerableArchive();

		// to ensure compatibility with prev scan results
		if (csvRow.length > 0) {
			v.setAffectedFile(csvRow[0]);
		}
		if (csvRow.length > 1) {
			v.setNestedPath(csvRow[1]);
		}
		if (csvRow.length > 2) {
			v.setVersion(Version.fromCsvColumn(csvRow[2]));
		}
		if (csvRow.length > 3) {
			v.setPatched(Boolean.parseBoolean(csvRow[3]));
		}

		return v;
	}

	public String[] toCsvRow(){
		return new String[] {affectedFile, nestedPath, version.toString(), String.valueOf(patched)};
	}

	public String getAffectedFile() {
		return affectedFile;
	}

	public String getNestedPath() {
		return nestedPath;
	}

	public String[] getNestedPaths() {
		return nestedPath.split(NESTED_PATH_SEPARATOR);
	}

	public Version getVersion() {
		return version;
	}

	public boolean isPatched() {
		return patched;
	}

	public void setPatched(boolean patched) {
		this.patched = patched;
	}

	public void setAffectedFile(String affectedFile) {
		this.affectedFile = affectedFile;
	}

	public void setNestedPath(String nestedPath) {
		this.nestedPath = nestedPath;
	}

	public void setVersion(Version version) {
		this.version = version;
	}

	public static boolean isVulnerable(int major, int minor, int patch) {
		if (isNonVulnerable(major, minor, patch)) return false;

		return major == 2 && (minor < 14 || (minor == 14 && patch <= 1));
	}

	public static boolean isVulnerable(Version version) {
		return isVulnerable(version.getMajor(), version.getMinor(), version.getPatch());
	}

	public static boolean isNonVulnerable(int major, int minor, int patch) {
		return major == 2 && minor == 12 && patch == 2;
	}

	@Override
	public String toString() {
		return "VulnerableArchive{" +
				"affectedFile='" + affectedFile + '\'' +
				", nestedPath='" + nestedPath + '\'' +
				", version=" + version +
				", patched=" + patched +
				'}';
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof VulnerableArchive)) return false;
		VulnerableArchive that = (VulnerableArchive) o;
		return patched == that.patched && Objects.equals(affectedFile, that.affectedFile) && Objects.equals(nestedPath, that.nestedPath) && Objects.equals(version, that.version);
	}

	@Override
	public int hashCode() {
		return Objects.hash(affectedFile, nestedPath, version, patched);
	}
}

package com.sas.vulnerabilities.model;

import org.tinylog.Logger;

import java.util.Objects;

public class Version {
	private int major;
	private int minor;
	private int patch;

	public Version() {
	}

	public Version(int major, int minor, int patch) {
		this.major = major;
		this.minor = minor;
		this.patch = patch;
	}

	public int getMajor() {
		return major;
	}

	public int getMinor() {
		return minor;
	}

	public int getPatch() {
		return patch;
	}

	public void setMajor(int major) {
		this.major = major;
	}

	public void setMinor(int minor) {
		this.minor = minor;
	}

	public void setPatch(int patch) {
		this.patch = patch;
	}

	public static Version fromCsvColumn(String version) {
		Version v = new Version();

		String[] split = version.split(".");

		try {

			if (split.length > 0) {
				v.setMajor(Integer.parseInt(split[0]));
			}
			if (split.length > 1) {
				v.setMinor(Integer.parseInt(split[1]));
			}
			if (split.length > 2) {
				v.setPatch(Integer.parseInt(split[2]));
			}
		} catch (Exception e) {
			Logger.warn(e, "Could not parse version " + version);
		}

		return v;
	}

	@Override
	public String toString() {
		return String.format("%d.%d.%d", major, minor, patch);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof Version)) return false;
		Version version = (Version) o;
		return major == version.major && minor == version.minor && patch == version.patch;
	}

	@Override
	public int hashCode() {
		return Objects.hash(major, minor, patch);
	}
}

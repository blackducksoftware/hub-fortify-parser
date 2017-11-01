package com.blackducksoftware.integration.fortify.parser;

import java.util.Date;

/**
 * BlackDuck scan definition.
 * This object is kind of parser domain object that should be converted to Fortify scan representation using
 * com.fortify.plugin.api.ScanBuilder instance.
 * See this method to understand how this conversion should be implemented com.blackducksoftware.integration.fortify.parser.BlackDuckIssueParser#buildFortifyScan
 * It is up to BlackDuck developers to use it or remove it if it is not needed.
 */
public class BlackDuckScan {

    /**
     * Natural unique scan identifier.
     * Max length is 255.
     */
    private String guid;

    /**
     * Date and time when scan file was created.
     * Do not use parsing date here!
     */
    private Date scanDate;

    /**
     * If scan was created during a build session (on Jenkins / TeamCity / VSTS / etc) some build identifier should be
     * placed here. Field is optional.
     * Max length is 255.
     */
    private String buildId;

    /**
     * Typically this is a version control identifier to indicate which exact revision is being scanned.
     * Field is optional.
     * Max length is 2000.
     */
    private String scanLabel;

    /**
     * The host name of the machine that ran the scan.
     * Optional.
     * Max length is 255.
     */
    private String hostName;

    /**
     * How long the scan took, in seconds.
     * Optional.
     */
    private Integer elapsedTime;

    /**
     * Number of files in the scanned application that have been scanned during the scan.
     * Optional.
     */
    private Integer numFiles;

    /**
     * Version of the scanner that generated scan file.
     * For BlackDuck it most probably should be version of the BlackDuck Hub software.
     * Optional.
     * Max length is 80.
     */
    private String engineVersion;

    public String getGuid() {
        return guid;
    }

    public void setGuid(String guid) {
        this.guid = guid;
    }

    public Date getScanDate() {
        return scanDate;
    }

    public void setScanDate(Date scanDate) {
        this.scanDate = scanDate;
    }

    public String getBuildId() {
        return buildId;
    }

    public void setBuildId(String buildId) {
        this.buildId = buildId;
    }

    public String getScanLabel() {
        return scanLabel;
    }

    public void setScanLabel(String scanLabel) {
        this.scanLabel = scanLabel;
    }

    public String getHostName() {
        return hostName;
    }

    public void setHostName(String hostName) {
        this.hostName = hostName;
    }

    public Integer getElapsedTime() {
        return elapsedTime;
    }

    public void setElapsedTime(Integer elapsedTime) {
        this.elapsedTime = elapsedTime;
    }

    public Integer getNumFiles() {
        return numFiles;
    }

    public void setNumFiles(Integer numFiles) {
        this.numFiles = numFiles;
    }

    public String getEngineVersion() {
        return engineVersion;
    }

    public void setEngineVersion(String engineVersion) {
        this.engineVersion = engineVersion;
    }
}

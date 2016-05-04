/**
 * 
 */
package com.blackducksoftware.integration.fortify;

/**
 * @author akamen
 * 
 */
public class BlackDuckConstants {

    /**
     * Scan constants
     */
    public static final String SCAN_LABEL = "Black Duck Hub Vulnerability Import";

    // TODO: Need to dynamically determine version of the hub
    public static final String SCAN_VERSION = "Black Duck Hub 3.0";

    // Per instructions, setting black duck eloc to 0
    public static final Integer SCAN_ELOC = 0;

    // Per instructions, setting annotations to 0
    public static final Integer SCAN_FORTIFY_ANNOTATIONS = 0;

    public static final String BLACKDUCK = "Black Duck Software";

    /**
     * Issue constants
     */

    public static final String ISSUE_CATEGORY = "3rd Party Component";

    /**
     * General
     */

    // The number of headers we expect in a legitimate CSV file
    public static final Integer BLACKDUCK_HEADER_COUNT = 21;

    public static final String BLACKDUCK_INVALID_CSV = "Invalid Black Duck Hub CSV report";

    public static final String CSV_FILE_EXTENTION_FOR_SSC = "*.csv";

    public static final String LOG_FILE_EXTENTION_FOR_SSC = "*.log";

    public static final String CSV_FILE_EXTENTION = "csv";

    public static final String LOG_FILE_EXTENTION = "log";
}

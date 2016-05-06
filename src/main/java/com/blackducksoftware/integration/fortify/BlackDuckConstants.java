/**
 * Copyright (C) 2016 Black Duck Software, Inc.
 * http://www.blackducksoftware.com/
 * 
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.
 * 
 * The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
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

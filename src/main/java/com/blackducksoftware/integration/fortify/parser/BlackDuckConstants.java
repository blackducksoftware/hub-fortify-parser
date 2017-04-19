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
package com.blackducksoftware.integration.fortify.parser;

/**
 * Set of useful constants for black duck parser.
 * @author akamen
 */
public class BlackDuckConstants {

    public static final String PENTEST_ANALYZER_TYPE = "pentest";

    public static final String SCAN_LABEL = "Black Duck Hub Vulnerability Import";

    public static final String BLACKDUCK_ENGINE_TYPE = "BLACKDUCK_ENGINE_TYPE";

    public static final String ISSUE_CATEGORY = "3rd Party Component";

    /**
     * The number of headers we expect in a legitimate CSV file.
     */
    public static final Integer BLACKDUCK_HEADER_COUNT = 21;

    /**
     * Error message about invalid black duck scan file contnt.
     */
    public static final String BLACKDUCK_INVALID_CSV = "Invalid Black Duck Hub CSV report";

    public static float HIGH_LIKELIHOOD = 5f;

    public static float HIGH_ACCURACY = 5f;
}

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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Testing the CSV output of the Hub file.
 */

public class BlackDuckCSVParserTest
{
    private static final String SIMPLE_CSV = "src/test/resources/testcsv.csv";

    private static final String JUNK_TXT = "src/test/resources/junkfile.txt";

    private static final String COMPLEX_CSV = "src/test/resources/complexcsv.csv";

    private static File simpleCsvFile;

    private static File complexCsvFile;

    public static File junkFile;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        simpleCsvFile = new File(SIMPLE_CSV);
        if (!simpleCsvFile.exists()) {
            Assert.fail("Cannot find simple csv file");
        }

        complexCsvFile = new File(COMPLEX_CSV);
        if (!complexCsvFile.exists()) {
            Assert.fail("Cannot find complex csv file");
        }

        junkFile = new File(JUNK_TXT);
        if (!junkFile.exists()) {
            Assert.fail("Cannot find junk file");
        }
    }

    /**
     * Tests the uniqueness of the md5 on two streams.
     * Reads in two files and checks the md5, then overwrites the second file with the contents of the first
     * Expecting the same md5
     */
    @Test
    public void testMD5GenerationForFile()
    {
        InputStream firstFileStream = null;
        InputStream secondFileStream = null;
        try {
            firstFileStream = new FileInputStream(simpleCsvFile);
            String firstFilemd5string = BlackDuckCSVParser.getMD5ForStream(firstFileStream);
            Assert.assertNotNull(firstFilemd5string);

            secondFileStream = new FileInputStream(junkFile);
            String secondFilemd5string = BlackDuckCSVParser.getMD5ForStream(secondFileStream);
            Assert.assertNotNull(secondFilemd5string);

            Assert.assertNotEquals(firstFilemd5string, secondFilemd5string);

            // Overwrite contents
            secondFileStream = new FileInputStream(simpleCsvFile);
            secondFilemd5string = BlackDuckCSVParser.getMD5ForStream(secondFileStream);

            Assert.assertEquals(firstFilemd5string, secondFilemd5string);

        } catch (Exception e) {
            Assert.fail(e.getMessage());
        } finally
        {
            try {
                firstFileStream.close();
            } catch (IOException e) {

            }
            try {
                secondFileStream.close();
            } catch (IOException e) {

            }
        }
    }

    @Test
    public void testFileIntegrity()
    {
        try {
            InputStream junkStream = new FileInputStream(junkFile);
            try {
                BlackDuckCSVParser parser = new BlackDuckCSVParser(junkStream);
            } catch (Exception e) {
                Assert.assertEquals(BlackDuckConstants.BLACKDUCK_INVALID_CSV, e.getMessage());
            }
        } catch (FileNotFoundException e) {
            Assert.fail(e.getMessage());
        }

    }

    @Test
    public void testBasicCSVFile()
    {
        BlackDuckCSVParser blackDuckParser;
        try {
            InputStream targetStream = new FileInputStream(simpleCsvFile);
            blackDuckParser = new BlackDuckCSVParser(targetStream);

            List<BlackDuckIssue> issues = blackDuckParser.getRows();

            // Test for correct rows
            Assert.assertEquals(8, issues.size());

            // Test for content integrity
            BlackDuckIssue firstIssue = issues.get(0);

            Assert.assertEquals("8c60f9fd-7885-48e5-9890-05e2fd8149e0", firstIssue.getProjectId());
            Assert.assertEquals("2d754b4e-c2fc-42f7-876a-f7eefd9b6d8b", firstIssue.getVersionId());
            Assert.assertEquals("dpkg", firstIssue.getProjectName());
            Assert.assertEquals("1.17.26", firstIssue.getVersion());
            Assert.assertEquals("CVE-2006-0300", firstIssue.getVulnerabilityId());
            Assert.assertNotNull(firstIssue.getDescription());
            Assert.assertEquals("2/24/2006", firstIssue.getPublishedOn());
            Assert.assertEquals("3/7/2011", firstIssue.getUpdatedOn());
            // Must provide delta on the floats
            Assert.assertEquals(5.1, firstIssue.getBaseScore(), .01);
            Assert.assertEquals(4.9, firstIssue.getExploitability(), .01);
            Assert.assertEquals(6.4, firstIssue.getImpact(), .01);
            Assert.assertEquals("NVD", firstIssue.getVulnerabilitySource());
            Assert.assertEquals("NEW", firstIssue.getRemediationStatus());
            Assert.assertEquals("2/9/2016", firstIssue.getRemediationTargetDate());
            Assert.assertEquals("2/9/2016", firstIssue.getRemediationActualDate());
            Assert.assertEquals("http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2006-0300", firstIssue.getURL());

            // Test for unique id
            Assert.assertEquals(":CVE-2006-0300", firstIssue.getId());

        } catch (FileNotFoundException e) {
            Assert.fail(e.getMessage());
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    /**
     * Tests a longer csv with every cell filled out.
     * 
     */
    @Test
    public void testComplexCSVFile()
    {
        BlackDuckCSVParser blackDuckParser;
        try {
            InputStream targetStream = new FileInputStream(complexCsvFile);
            blackDuckParser = new BlackDuckCSVParser(targetStream);

            List<BlackDuckIssue> issues = blackDuckParser.getRows();

            // Test for correct rows
            Assert.assertEquals(33, issues.size());

        } catch (FileNotFoundException e) {
            Assert.fail(e.getMessage());
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }
}

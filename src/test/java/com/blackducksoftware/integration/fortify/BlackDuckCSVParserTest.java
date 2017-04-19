/**
 * Copyright (C) 2016 Black Duck Software, Inc.
 * http://www.blackducksoftware.com/
 * <p>
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.
 * <p>
 * The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.blackducksoftware.integration.fortify;

import com.blackducksoftware.integration.fortify.parser.BlackDuckBeanProcessor;
import com.blackducksoftware.integration.fortify.parser.BlackDuckCSVParser;
import com.blackducksoftware.integration.fortify.parser.BlackDuckConstants;
import com.blackducksoftware.integration.fortify.parser.BlackDuckIssue;
import com.univocity.parsers.common.ParsingContext;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;

import static com.blackducksoftware.integration.fortify.parser.BlackDuckUtils.getMD5ForStream;

/**
 * Testing the CSV output of the Hub file.
 */

public class BlackDuckCSVParserTest {
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
    public void testMD5GenerationForFile() {
        InputStream firstFileStream = null;
        InputStream secondFileStream = null;
        try {
            firstFileStream = new FileInputStream(simpleCsvFile);
            String firstFilemd5string = getMD5ForStream(firstFileStream);
            Assert.assertNotNull(firstFilemd5string);

            secondFileStream = new FileInputStream(junkFile);
            String secondFilemd5string = getMD5ForStream(secondFileStream);
            Assert.assertNotNull(secondFilemd5string);

            Assert.assertNotEquals(firstFilemd5string, secondFilemd5string);

            // Overwrite contents
            secondFileStream = new FileInputStream(simpleCsvFile);
            secondFilemd5string = getMD5ForStream(secondFileStream);

            Assert.assertEquals(firstFilemd5string, secondFilemd5string);

        } catch (Exception e) {
            Assert.fail(e.getMessage());
        } finally {
            try {
                if (firstFileStream != null) {
                    firstFileStream.close();
                }
            } catch (IOException e) {
                // noop
            }
            try {
                if (secondFileStream != null) {
                    secondFileStream.close();
                }
            } catch (IOException e) {
                // noop
            }
        }
    }

    @Test
    public void testFileIntegrity() {
        try {
            InputStream junkStream = new FileInputStream(junkFile);
            try {
                BlackDuckCSVParser parser = new BlackDuckCSVParser();
                parser.parseIssues(junkStream, new BlackDuckBeanProcessor() {
                    @Override
                    public void beanProcessed(BlackDuckIssue bean, ParsingContext context) {
                        // we do not really care about the results here.
                    }
                });
            } catch (Exception e) {
                Assert.assertEquals(BlackDuckConstants.BLACKDUCK_INVALID_CSV, e.getMessage());
            }
        } catch (FileNotFoundException e) {
            Assert.fail(e.getMessage());
        }

    }

    @Test
    public void testBasicCSVFile() {
        try {
            final InputStream targetStream = new FileInputStream(simpleCsvFile);
            BlackDuckCSVParser blackDuckParser = new BlackDuckCSVParser();
            blackDuckParser.parseIssues(targetStream, new BlackDuckBeanProcessor() {

                int rowsProcessed = 0;

                @Override
                public void beanProcessed(BlackDuckIssue bean, ParsingContext context) {
                    rowsProcessed++;
                    if (rowsProcessed == 1) {
                        Assert.assertEquals("8c60f9fd-7885-48e5-9890-05e2fd8149e0", bean.getProjectId());
                        Assert.assertEquals("2d754b4e-c2fc-42f7-876a-f7eefd9b6d8b", bean.getVersionId());
                        Assert.assertEquals("dpkg", bean.getProjectName());
                        Assert.assertEquals("1.17.26", bean.getVersion());
                        Assert.assertEquals("CVE-2006-0300", bean.getVulnerabilityId());
                        Assert.assertNotNull(bean.getDescription());
                        Assert.assertEquals("2/24/2006", bean.getPublishedOn());
                        Assert.assertEquals("3/7/2011", bean.getUpdatedOn());
                        // Must provide delta on the floats
                        Assert.assertEquals(BigDecimal.valueOf(5.1), bean.getBaseScore());
                        Assert.assertEquals(BigDecimal.valueOf(4.9), bean.getExploitability());
                        Assert.assertEquals(BigDecimal.valueOf(6.4), bean.getImpact());
                        Assert.assertEquals("NVD", bean.getVulnerabilitySource());
                        Assert.assertEquals("NEW", bean.getRemediationStatus());
                        Assert.assertEquals("2/9/2016", bean.getRemediationTargetDate());
                        Assert.assertEquals("2/9/2016", bean.getRemediationActualDate());
                        Assert.assertEquals("http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2006-0300", bean.getURL());
                        // Test for unique id
                        Assert.assertEquals("121c18ed-25c7-33ea-bc14-17f03e5aaa29", bean.getId());
                    }
                }

                @Override
                public void processEnded(ParsingContext context) {
                    super.processEnded(context);
                    Assert.assertEquals(8, rowsProcessed);
                }
            });
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    /**
     * Tests a longer csv with every cell filled out.
     */
    @Test
    public void testComplexCSVFile() {
        try {
            InputStream targetStream = new FileInputStream(complexCsvFile);
            BlackDuckCSVParser blackDuckParser = new BlackDuckCSVParser();
            blackDuckParser.parseIssues(targetStream, new BlackDuckBeanProcessor() {
                int rowsProcessed = 0;

                @Override
                public void beanProcessed(BlackDuckIssue bean, ParsingContext context) {
                    rowsProcessed++;
                }

                @Override
                public void processEnded(ParsingContext context) {
                    super.processEnded(context);
                    // Test for correct rows
                    Assert.assertEquals(33, rowsProcessed);
                }
            });
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }
}

package com.blackducksoftware.integration.fortify;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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

    private static File simpleCsvFile;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        simpleCsvFile = new File(SIMPLE_CSV);
        if (!simpleCsvFile.exists()) {
            Assert.fail("Cannot find simple csv file");
        }
    }

    @Test
    public void testFileIntegrity()
    {
        File junkFile = new File(JUNK_TXT);
        if (!junkFile.exists()) {
            Assert.fail("Junk file DNE");
        }

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
            Assert.assertEquals("8c60f9fd-7885-48e5-9890-05e2fd8149e0:2d754b4e-c2fc-42f7-876a-f7eefd9b6d8b:CVE-2006-0300", firstIssue.getId());

        } catch (FileNotFoundException e) {
            Assert.fail(e.getMessage());
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }
}

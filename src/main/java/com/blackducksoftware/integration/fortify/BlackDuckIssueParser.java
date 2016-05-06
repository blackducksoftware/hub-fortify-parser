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

import java.io.IOException;
import java.io.InputStream;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.springframework.stereotype.Component;

import com.fortify.pub.issueparsing.AnalysisFileParser;
import com.fortify.pub.issueparsing.AnalysisSingleFileParser;
import com.fortify.pub.issueparsing.IssueHandler;
import com.fortify.pub.issueparsing.PriorityValues;
import com.fortify.pub.issueparsing.Scan;
import com.fortify.pub.issueparsing.ScanCertification;
import com.fortify.pub.issueparsing.UpdateStatus;
import com.fortify.pub.util.StreamProvider;
import com.fortify.ui.model.issue.IssueUtil;
import com.fortify.ui.model.xml.Impl.IssueDescriptionImpl;
import com.fortify.ui.model.xml.interfaces.CategorySourceTypeName;
import com.fortify.ui.model.xml.interfaces.InternalIssueParseHandler;

@Component("blackDuckParser")
public class BlackDuckIssueParser implements AnalysisFileParser, AnalysisSingleFileParser {

    // For Fortify, describes the type of analysis.
    private static final String PENTEST_ANALYZER_TYPE = "pentest";

    // Non-persistent local parser
    private BlackDuckCSVParser blackDuckParser;

    /**
     * /*
     * This method must return fully initialized Scan object.
     * This object contains some attributes that of the scan that was performed and which results are about to be
     * uploaded.
     * 
     * Scan attributes:
     * private Date scanDate - date and time when scan was performed.
     * private String label - scan label is just a string that describes scan. Something like very short scan
     * description.
     * private String buildId - optional. if scan was performed as a part of build process, some unique build ID
     * should be here
     * private Integer elapsed - optional. how much time it took to perfrom scan.
     * private Integer loc - optional. ho many lines of code was scanned;
     * private Integer files - how many files were scanned;
     * private String host - not sure here. Just leav it empty;
     * private String version - set the version of the blackduck scanner that produced the scan.
     * private int warnings - optional. How many warnings were detected during scan. Might not be applicable for
     * black duck.
     * private String description - optional scan description.
     * private boolean current - this attribute should be initialized by SSC.
     * private String entryName - just set it = to entryName passed in method parameter.
     * private String uuid - unique identifier for this scan. This is important attribute that helps SSC to
     * understand if this upload is duplicated. It might be some random GUID or any string that
     * should be different for different scans.
     * private Integer eLOC - set it to 0 for black duck.
     * private ScanCertification certification - not sure here. Just leave defautl value
     * ScanCertification.NOT_PRESENT here.
     * private String projectLabel - scanned application project
     * private String versionLabel - and version labels. I think these 2 attributes can be empty for black duck
     * scans.
     * private Integer fortifyAnnotations - set it to 0 for black duck.
     * private Collection<Category> categories - not sure. Lets leav it empty for now.
     * private Map<UpdateStatus, Set<String>> iids - this array will be filled during the scan processing.
     */
    @Override
    public Scan parseAnalysisInformation(InputStream inputStream, String entryName) throws IOException {
        BlackDuckLogger.logInfo("Initializing new scan for Black Duck");
        Scan blackDuckScan = new Scan();

        try {
            Date scanDate = getAnalysisDate(inputStream);
            BlackDuckLogger.logInfo("Date for scan object: " + scanDate);
            blackDuckScan.setScanDate(scanDate);

            // This is a unique ID *per* file.
            blackDuckScan.setUuid(generateUniqueKey(inputStream));

            blackDuckScan.setLabel(BlackDuckConstants.SCAN_LABEL);
            blackDuckScan.setVersionLabel(BlackDuckConstants.SCAN_VERSION);
            blackDuckScan.setELOC(BlackDuckConstants.SCAN_ELOC);
            blackDuckScan.setCertification(ScanCertification.NOT_PRESENT);
            BlackDuckLogger.logInfo("Entry name: " + entryName);
            blackDuckScan.setEntryName(entryName);
            blackDuckScan.setProjectLabel("ProjectLabelGoesHere"); // TODO: Figure out project name
            blackDuckScan.setVersionLabel("VersionLabelGoesHere"); // TODO: Figure out project version
            blackDuckScan.setFortifyAnnotations(BlackDuckConstants.SCAN_FORTIFY_ANNOTATIONS);
        } catch (Exception e)
        {
            throw new IOException("Unable to complete scan", e);
        }
        return blackDuckScan;
    }

    /**
     * Generates a unique SCAN ID per file. Uses the md5 for the supplied inputstream.
     * 
     * @param inputStream
     * @return
     * @throws Exception
     */
    private String generateUniqueKey(InputStream inputStream) throws Exception {
        String md5sumForStream = BlackDuckCSVParser.getMD5ForStream(inputStream);
        BlackDuckLogger.logInfo("Generating unique SCAN ID for file: " + md5sumForStream);
        return md5sumForStream;
    }

    /**
     * Checks for CSV integrity by comparing the number of headers.
     */
    @Override
    public boolean accept(String fullFileName, InputStream inputStream) {
        BlackDuckLogger.logInfo("Parsing the uploaded file: " + fullFileName);
        boolean accepted = false;

        try {
            blackDuckParser = new BlackDuckCSVParser(inputStream);
            accepted = true;

        } catch (Exception e)
        {
            BlackDuckLogger.logError("Error setting up the blackduck parser", e);
        }

        return accepted;
    }

    /**
     * Unique analyzer name
     */
    @Override
    public String getAnalyzerName() {
        return BlackDuckConstants.BLACKDUCK;
    }

    @Override
    public Scan parseAnalysisInformation(ZipFile zipFile, ZipEntry zipEntry) throws IOException {
        InputStream inputStream = zipFile.getInputStream(zipEntry);
        String entryName = zipEntry.getName();
        return parseAnalysisInformation(inputStream, entryName);
    }

    @Override
    public int getParserOrder() {
        return PENTEST_ORDER;
    }

    @Override
    public List<String> getSupportedFileExtensions() {
        return Collections.singletonList(BlackDuckConstants.LOG_FILE_EXTENTION_FOR_SSC);
    }

    /**
     * TODO: There is currently no way to determine unique data of a black duck csv file.
     */
    @Override
    public Date getAnalysisDate(InputStream inputStream) {
        /*
         * You must place some logic here that generates a scan date. This is very important thing since SSC uses this
         * date to check if results located inside this fiel where
         * uploaded before ir not. It will help SSC to prevent processing of the same files more than once.
         * All scanners that SSC currently supports store the scan date inside the scan result file. You will need to
         * figure out where to get this date from black duck scan results.
         * This date is also helps SSC to understand the status of issue - is it new, or is it reintroduced, or is it
         * fixed.
         */
        return new Date();
    }

    /**
     * Parses the local stream and converts to internal beans
     * In our case, the parsing is already done so we will just fetch the rows.
     */
    @Override
    public void parseIssueInformation(StreamProvider streamProvider, IssueHandler issueHandler, boolean latestScan, Scan scan) throws IOException, SQLException {
        List<BlackDuckIssue> blackDuckIssues = new ArrayList<BlackDuckIssue>();
        try {
            blackDuckIssues = blackDuckParser.getRows();
        } catch (Exception e) {
            BlackDuckLogger.logError(e.getMessage());
        }

        for (BlackDuckIssue blackDuckIssue : blackDuckIssues) {
            processIssue(blackDuckIssue, issueHandler, latestScan, scan);
        }
    }

    /**
     * Processes the individual Black Duck issues and converts them to internal Fortify issues.
     * In order to make each issue unique to the project, the name of the file the will be used
     * to generate a portion of the ID.
     * 
     * @param blackDuckIssue
     * @param issueHandler
     * @param latestScan
     * @param scan
     */
    private void processIssue(BlackDuckIssue blackDuckIssue, IssueHandler issueHandler, boolean latestScan, Scan scan) {
        // Important: Provide the entry name of the file to establish project uniqueness for IDs
        blackDuckIssue.setId(scan.getEntryName());

        InternalIssueParseHandler internalIssueHandler = (InternalIssueParseHandler) issueHandler;
        BlackDuckLogger.logInfo("Creating new issue with ID: " + blackDuckIssue.getId());
        final UpdateStatus updateStatus = internalIssueHandler.startIssue(blackDuckIssue.getId());

        internalIssueHandler.setManual(false); // if BlackDuck allows customers to enter information about
                                               // vulnerabilities manually, make this value variable. Otherwise just
                                               // pass FALSE here,

        internalIssueHandler.setAnalyzerName(IssueUtil.canonicalizeAnalyzerName(PENTEST_ANALYZER_TYPE));

        // Uknown what to do for category subtype
        final String categorySubType = "";
        internalIssueHandler.setCategoryTypeAndSubType(BlackDuckConstants.ISSUE_CATEGORY, categorySubType);

        // This is not great, but there is not other place version in SSC data model.
        internalIssueHandler.setFileName(blackDuckIssue.getProjectName() + ":" + blackDuckIssue.getVersion());

        // Issue description
        // TODO: Commenting this out because the makeDescription method does not compile here.
        // internalIssueHandler.setDescription(makeDescription(blackDuckIssue));
        /*
         * or you can use following approach for description:
         * StringBuilder description = new StringBuilder(data.getDescription());
         * description.append("\n\header of description part1:\t").append(blackDuckIssue.getField1Value());
         * description.append("\n\header of description part2:\t").append(blackDuckIssue.getField2Value());
         * ...
         * description.append("\n\header of description partN:\t").append(blackDuckIssue.getFieldNValue());
         * issueHandler.setIssueSpecificDescription(description.toString());
         * And put anything you like in the description field.
         */

        issueHandler.setIssueSpecificDescription(blackDuckIssue.getDescription());

        // lets set empty string here. I will check how this field is used in SSC.
        issueHandler.setSink("");

        // Blackduck does not scan actual functions, so this is empty string
        issueHandler.setFunctionName("");

        // Leave blank?
        issueHandler.setPrimaryRuleID("");

        issueHandler.setSeverity(blackDuckIssue.getExploitability());
        issueHandler.setConfidence(blackDuckIssue.getBaseScore());
        issueHandler.setLikelihood(5f);
        issueHandler.setImpact(blackDuckIssue.getImpact());
        issueHandler.setAccuracy(5f);

        // You need to calculate this attribute using Exploitability / BaseScore / Impact or any other attributes.
        // TODO: Should we be determining this here?
        issueHandler.setPriority(PriorityValues.Critical);

        issueHandler.setProduct(BlackDuckConstants.BLACKDUCK);

        // Let's talk about it on a meeting.
        issueHandler.setCategorySourceType(CategorySourceTypeName.NATIVE.name());

        // Source of CVE
        issueHandler.setURL(blackDuckIssue.getURL());

        issueHandler.endIssue(blackDuckIssue.getId());
        scan.putInstanceID(updateStatus, blackDuckIssue.getId());
    }

    /**
     * TODO: Find out how to utilize IssueDescriptionImpl without breaking a bunch of stuff
     * 
     * @param blackDuckIssue
     * @return
     */
    private IssueDescriptionImpl makeDescription(BlackDuckIssue blackDuckIssue) {
        // IssueDescriptionImpl issue = new IssueDescriptionImpl(blackDuckIssue.getDescription(), null,
        // blackDuckIssue.getVulnerabilityId(),
        // blackDuckIssue.getRemediationComment(),
        // blackDuckIssue.getURL(), null, false);

        // return issue;
        return null;
    }

}

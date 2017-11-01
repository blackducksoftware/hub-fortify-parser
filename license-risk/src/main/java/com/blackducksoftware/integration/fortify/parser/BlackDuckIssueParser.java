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
package com.blackducksoftware.integration.fortify.parser;

import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.fortify.plugin.spi.ParserPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;

public class BlackDuckIssueParser implements ParserPlugin<BlackDuckVulnerabilityAttribute> {

    private static Logger LOG = LoggerFactory.getLogger(BlackDuckIssueParser.class);

    @Override
    public void start() throws Exception {
        LOG.info("BlackDuckIssueParser is starting...");
    }

    @Override
    public void stop() throws Exception {
        LOG.info("BlackDuckIssueParser is stopping working...");
    }

    @Override
    public Class<BlackDuckVulnerabilityAttribute> getVulnerabilityAttributesClass() {
        return BlackDuckVulnerabilityAttribute.class;
    }

    @Override
    public void parseScan(final ScanData scanData, final ScanBuilder scanBuilder) throws IOException {
        final BlackDuckCSVParser blackDuckParser = new BlackDuckCSVParser();
        try (final InputStream is = getScanInputStream(scanData)) {
            final BlackDuckScan blackDuckScan = blackDuckParser.parseScan(is);
            buildFortifyScan(scanBuilder, blackDuckScan);
        }
    }

    @Override
    public void parseVulnerabilities(final ScanData scanData, final VulnerabilityHandler vh) throws ScanParsingException, IOException {
        BlackDuckCsvRowProcessor blackDuckCsvRowProcessor = new BlackDuckCsvRowProcessor(vh);
        final BlackDuckCSVParser blackDuckParser = new BlackDuckCSVParser();
        try (final InputStream is = getScanInputStream(scanData)) {
            blackDuckParser.parseIssues(is, blackDuckCsvRowProcessor);
        }
    }

    private InputStream getScanInputStream(final ScanData scanData) throws IOException {
        // TODO: use correct predicate for entry name, for now use the first entry
        return scanData.getInputStream(x -> x.endsWith(".csv"));
    }

    private void buildFortifyScan(final ScanBuilder scanBuilder, final BlackDuckScan blackDuckScan) {
        scanBuilder.setGuid(blackDuckScan.getGuid());
        scanBuilder.setScanDate(blackDuckScan.getScanDate());
        scanBuilder.setBuildId(blackDuckScan.getBuildId());
        scanBuilder.setScanLabel(blackDuckScan.getScanLabel());
        scanBuilder.setHostName(blackDuckScan.getHostName());
        scanBuilder.setElapsedTime(blackDuckScan.getElapsedTime());
        scanBuilder.setNumFiles(blackDuckScan.getNumFiles());
        scanBuilder.setEngineVersion(blackDuckScan.getEngineVersion());
        scanBuilder.completeScan();
    }
}

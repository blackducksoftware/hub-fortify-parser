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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fortify.plugin.api.ScanParsingException;
import com.univocity.parsers.common.processor.BeanProcessor;
import com.univocity.parsers.csv.CsvParserSettings;

/**
 * Class responsible for parsing issue / scan related data from provided CSV file.
 *
 * @author akamen
 *
 */
public class BlackDuckCSVParser {

    private static final Logger LOG = LoggerFactory.getLogger(BlackDuckCSVParser.class);

    /**
     * Parse scan information from provided stream.
     *
     * @param inputStream
     *            stream that contains uploaded BlackDuck scan result file data.
     * @return initialized BlackDuckScan object. Null values are not accepted.
     * @throws IOException
     *             in case any errors
     */
    public BlackDuckScan parseScan(final InputStream inputStream) throws IOException {
        /*
         * Some notes from Fortify developers:
         * This method is kind of useless for now since BlackDuck CSV result file does not contain any information about
         * scan itself and this method basically does nothing except setting some hard coded values.
         * So, this method should be reimplemented somehow and to make it provided initialized scan object.
         * We were informed that BlackDuc hub supports another export format (JSON). If JASON file contains any
         * information
         * about scan, it should be better to re-implement the parsing logic and move from CSV parsing to JSON fiel
         * parsing.
         * In this case this method will be implemented correctly and return real scan object.
         * If moving to JSON file parsing does not help much, it might be better to completely remove this method and
         * include 2 mandatory scan attributes (engineType and scanDate) in scan.info file that will be zipped with
         * black duck scan result CSV file.
         * You can find more information about this in plugin developers guide.
         */
        LOG.info("Initializing new scan for Black Duck");
        if (inputStream == null) {
            throw new IllegalArgumentException("inputStream cannot be null");
        }
        final BlackDuckScan blackDuckScan = new BlackDuckScan();
        /*
         * FIX ME!
         * You must place some logic here that generates a scan date. This is very important thing since SSC uses this
         * date to check if results located inside this field where uploaded before ir not. It will help SSC to prevent
         * processing of the same files twice.
         * All parser plugins that SSC currently supports store the scan date inside the scan result file. You will need
         * to
         * figure out where to get this date from black duck scan results.
         * This date also helps SSC to understand the status of issue - is it new, or is it reintroduced, or is it
         * fixed.
         * If there is not way to get this file from CSV file, scan date must be included in scan.info file. See the
         * comment
         * above for more details.
         */
        Date scanDate = null;
        BufferedReader reader = null;

        try {
            reader = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
            String sCurrentLine;

            int counter = 0;
            while ((sCurrentLine = reader.readLine()) != null) {
                if (counter == 0) {
                    counter++;
                    continue;
                } else {
                    final String[] lineArr = sCurrentLine.split(",");
                    LOG.debug("Scan date from File::" + lineArr[lineArr.length - 5]);
                    scanDate = BlackDuckUtils.convertToDateTime(lineArr[lineArr.length - 5]);
                    LOG.debug("Scan date::" + scanDate);
                    break;
                }
            }
        } catch (final Exception e) {
            e.printStackTrace();
            LOG.error(e.getMessage(), e);
            throw new IOException("Error while parsing the scan date");
        }
        blackDuckScan.setScanDate(scanDate != null ? scanDate : new Date());
        blackDuckScan.setGuid(BlackDuckUtils.getMD5ForStream(inputStream));
        blackDuckScan.setScanLabel(BlackDuckConstants.SCAN_LABEL);
        return blackDuckScan;
    }

    /**
     * Method to start parsing issues from the provided input stream.
     *
     * @param inputStream
     *            stream that contains uploaded BlackDuck scan result file data.
     * @param beanProcessor
     *            BeanProcessor implementation that is responsible for fetching vulnerabilities from the
     *            rows of the provided black duck result CSV file.
     * @throws ScanParsingException
     * @throws IOException
     *             If an I/O error occurs during CSV file processing.
     * @throws IllegalArgumentException
     *             if inputStream and / or beanProcessor are null.
     */
    public void parseIssues(final InputStream inputStream, final BeanProcessor<BlackDuckIssue> beanProcessor) throws ScanParsingException, IOException {
        LOG.info("Parsing issues for Black Duck");
        if (inputStream == null) {
            throw new IllegalArgumentException("inputStream cannot be null");
        }
        if (beanProcessor == null) {
            throw new IllegalArgumentException("beanProcessor cannot be null");
        }
        final CsvParserSettings parserSettings = new CsvParserSettings();
        parserSettings.setRowProcessor(beanProcessor);
        parserSettings.setHeaderExtractionEnabled(true);
        try (final InputStreamCsvParser inputStreamCsvParser = new InputStreamCsvParser(parserSettings, inputStream)) {
            inputStreamCsvParser.parse();
        }
    }
}

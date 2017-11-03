package com.blackducksoftware.integration.fortify.parser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.univocity.parsers.common.ParsingContext;

/**
 * Custom version of BeanProcessor to handle black duck scan results.
 */
public class BlackDuckCsvRowProcessor extends BlackDuckBeanProcessor {

    private static Logger LOG = LoggerFactory.getLogger(BlackDuckCsvRowProcessor.class);

    private final VulnerabilityHandler vulnerabilityHandler;

    private int rowsProcessed;

    /**
     * Constructor.
     *
     * @param vulnerabilityHandler
     *            VulnerabilityHandler implementation to provide processor the way to pass parsed
     *            vulnerabilities from parser to SSC.
     */
    public BlackDuckCsvRowProcessor(VulnerabilityHandler vulnerabilityHandler) {
        super();
        this.vulnerabilityHandler = vulnerabilityHandler;
    }

    /**
     * Method is called by framework when new scan file parsing session
     *
     * @param context
     *            com.univocity.parsers.common.ParsingContext instanse
     */
    @Override
    public void processStarted(ParsingContext context) {
        super.processStarted(context);
        rowsProcessed = 0;
    }

    /**
     *
     * @param blackDuckIssue
     * @param context
     */
    @Override
    public void beanProcessed(BlackDuckIssue blackDuckIssue, ParsingContext context) {
        if (rowsProcessed == 0) {
            validateHeaders(context.headers());
        }
        buildVulnerability(blackDuckIssue, vulnerabilityHandler);
        rowsProcessed++;
    }

    private void validateHeaders(String[] headers) {
        if (headers == null) {
            LOG.error("Empty headers");
            throw new BlackDuckParsingException(BlackDuckConstants.BLACKDUCK_INVALID_CSV);
        }
        if (headers.length != BlackDuckConstants.BLACKDUCK_HEADER_COUNT) {
            LOG.error("Header count mismatch, header count: " + headers.length);
            throw new BlackDuckParsingException(BlackDuckConstants.BLACKDUCK_INVALID_CSV);
        }
    }

    private void buildVulnerability(BlackDuckIssue blackDuckIssue, VulnerabilityHandler vulnerabilityHandler) {
        // Start building new vulnerability and obtain builder object
        final StaticVulnerabilityBuilder vulnerabilityBuilder = vulnerabilityHandler.startStaticVulnerability(blackDuckIssue.getId());

        // Standard attributes values
        vulnerabilityBuilder.setAnalyzer(BlackDuckConstants.PENTEST_ANALYZER_TYPE);
        vulnerabilityBuilder.setCategory(BlackDuckConstants.ISSUE_CATEGORY);
        vulnerabilityBuilder.setSubCategory("");
        vulnerabilityBuilder.setFileName(blackDuckIssue.getComponentName() + ":" + blackDuckIssue.getComponentVersion());
        vulnerabilityBuilder.setConfidence(0f);
        switch (blackDuckIssue.getSeverity()) {
        case "HIGH":
            vulnerabilityBuilder.setPriority(StaticVulnerabilityBuilder.Priority.High);
            break;
        case "MEDIUM":
            vulnerabilityBuilder.setPriority(StaticVulnerabilityBuilder.Priority.Medium);
            break;
        case "LOW":
            vulnerabilityBuilder.setPriority(StaticVulnerabilityBuilder.Priority.Low);
            break;
        default:
            vulnerabilityBuilder.setPriority(StaticVulnerabilityBuilder.Priority.Critical);
            break;
        }
        vulnerabilityBuilder.setLikelihood(BlackDuckConstants.HIGH_LIKELIHOOD);
        vulnerabilityBuilder.setAccuracy(BlackDuckConstants.HIGH_ACCURACY);
        vulnerabilityBuilder.setEngineType(BlackDuckConstants.BLACKDUCK_ENGINE_TYPE);
        // Blackduck specific attributes values
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.PROJECT_NAME, blackDuckIssue.getProjectName());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.PROJECT_VERSION, blackDuckIssue.getProjectVersion());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.COMPONENT_NAME, blackDuckIssue.getComponentName());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.COMPONENT_VERSION, blackDuckIssue.getComponentVersion());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.COMPONENT_ID, blackDuckIssue.getComponentId());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.COMPONENT_VERSION_ID, blackDuckIssue.getComponentVersionId());
        vulnerabilityBuilder.setDateCustomAttributeValue(BlackDuckVulnerabilityAttribute.RELEASED_ON,
                BlackDuckUtils.convertToDate(blackDuckIssue.getReleasedOn()));
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.NEWER_RELEASED_COUNT, blackDuckIssue.getNewerReleasedCount());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.TRENDING, blackDuckIssue.getTrending());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.COMMIT_COUNT_LAST_12_MONTH, blackDuckIssue.getCommitCount12Month());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.CONTRIBUTOR_COUNT_LAST_12_MONTH,
                blackDuckIssue.getContributorCount12Month());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.URL, blackDuckIssue.getURL());

        vulnerabilityBuilder.completeVulnerability();
    }

    @Override
    public void processEnded(ParsingContext context) {
        super.processEnded(context);
    }

    private static class BlackDuckParsingException extends RuntimeException {

        public BlackDuckParsingException(String message) {
            super(message);
        }

    }
}

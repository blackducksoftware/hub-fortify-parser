package com.blackducksoftware.integration.fortify.parser;

import com.univocity.parsers.common.processor.BeanProcessor;

/**
 * Wrapper for BeanProcessor to avoid using BlackDuckIssue in constructors.
 */
public abstract class BlackDuckBeanProcessor extends BeanProcessor<BlackDuckIssue> {

    /**
     * Creates a processor for java beans of a given type.
     */
    public BlackDuckBeanProcessor() {
        super(BlackDuckIssue.class);
    }
}

/*
 * Copyright (C) 2015 Ladislav Jech
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package org.prometheus.cryptographic_processor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.prometheus.cryptographic_processor.result.GenericResult;
import org.prometheus.logging_environment.EnvironmentConfiguration;
import org.prometheus.logging_environment.EnvironmentConfigurationException;

/**
 * Heart of cryptographic processor library. This <b>abstract</b> class provides
 * a template for creating specific cryptographic algorithm instances.
 * <p>
 * This class is part of factory pattern, so factory should be always used for
 * creating specific algorithm/crypto-mechanism to be used.
 *
 * @author Ladislav Jech
 * @version 1.0
 */
public abstract class CryptographicProcessor {

    private static final Logger log = LogManager.getLogger();

    private final GenericResult result = new GenericResult();

    private CryptographicProcessorType cpType = null;

    private static boolean isEnvironmentInititated = false;

    static {
        /* Generic environment initialization */
        if (!CryptographicProcessor.isEnvironmentInititated) {
            try {
                final EnvironmentConfiguration ec = EnvironmentConfiguration.getInstance();
                ec.init();
                log.debug("Environment configured successfully for cryptographic processor subsystem.");
                CryptographicProcessor.setIsEnvironmentInititated(true);
            } catch (EnvironmentConfigurationException ex) {
                System.out.println("Cannot configure environment: " + ex.getLocalizedMessage());
                // System.exit(1); /* Used only with production systems */
            }
        }
    }

    /**
     *
     * @param cpType
     * @throws CryptographicProcessorException
     */
    public CryptographicProcessor(CryptographicProcessorType cpType) throws CryptographicProcessorException {
        GenericResult.getInstance().setCryptographicProcessorType(cpType);
        this.cpType = cpType;
        configureEnvironment();
    }

    /**
     *
     */
    protected abstract void construct();

    /**
     *
     * @return
     */
    public CryptographicProcessorType getProcessor() {

        return cpType;
    }

    /**
     * Method used for set the processor type
     *
     * @param cpType
     */
    public void setProcessorType(CryptographicProcessorType cpType) {
        this.cpType = cpType;
    }

    private void configureEnvironment() throws CryptographicProcessorException {
        try {
            EnvironmentConfiguration ec = new EnvironmentConfiguration();
            ec.init();
        } catch (EnvironmentConfigurationException ex) {
            String msg = "There occured error while preparing environment from within cryptographic processor.";
            log.error(msg, ex);
            throw new CryptographicProcessorException(msg, ex);
        }
    }

    /**
     * TODO
     *
     * @return TODO todo
     * @since 1.0
     */
    public GenericResult getGenericResult() {
        return this.result;
    }

    /**
     * Gets current value of field used as detection of environment
     * configuration status.
     *
     * @return current value
     * @since 1.0
     */
    private static boolean isIsEnvironmentInititated() {
        return isEnvironmentInititated;
    }

    /**
     * Sets static field used as detection of environment configuration status
     * into state.
     *
     * @param isEnvironmentInititated indicator of environment configuration?
     * @since 1.0
     */
    private static void setIsEnvironmentInititated(boolean isEnvironmentInititated) {
        CryptographicProcessor.isEnvironmentInititated = isEnvironmentInititated;
    }

}

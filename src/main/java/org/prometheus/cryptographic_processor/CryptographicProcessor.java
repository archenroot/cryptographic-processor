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

import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.prometheus.logging_environment.EnvironmentConfiguration;
import org.prometheus.logging_environment.EnvironmentConfigurationException;

public abstract class CryptographicProcessor {

    
    private static final Logger log = LogManager.getLogger();
    
    
    private CryptographicProcessorType cpType = null;

    public CryptographicProcessor(CryptographicProcessorType cpType) throws CryptographicProcessorException {
        this.cpType = cpType;
        configureEnvironment();
    }

    protected abstract void construct();

    public CryptographicProcessorType getProcessor() {
        
        return cpType;
    }
    public void setProcessor(CryptographicProcessorType cpType){
        this.cpType = cpType;
    }

    private void configureEnvironment() throws CryptographicProcessorException {
        try {
            EnvironmentConfiguration ec = new EnvironmentConfiguration();
            ec.init();
        } catch (EnvironmentConfigurationException ex) {
            String msg ="There occured error while preparing environment from within cryptographic processor.";
            log.error(msg,ex);
            throw new CryptographicProcessorException(msg,ex);
        }
    }
}

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
package org.prometheus.cryptographic_processor.pgp;

import org.prometheus.cryptographic_processor.CryptographicProcessorException;

/**
 * General PGP Cryptographic Processor exception. Is used as wrapper exception
 * for any PGP related processing.
 *
 * @author Ladislav Jech <archenroot@gmail.com>
 */
public class PGPProcessorException extends CryptographicProcessorException{


    /**
     * General constructor.
     */
    public PGPProcessorException() {
        super();
    }

    /**
     * Exception constructor which passes error message.
     *
     * @param message Exception description.
     */
    public PGPProcessorException(final String message) {
        super(message);
    }

    /**
     * Exception constructor which passes error cause.
     *
     * @param cause Exception cause.
     */
    public PGPProcessorException(final Throwable cause) {
        super(cause);
    }

    /**
     * Exception constructor which passes both error description and cause as
     * well.
     *
     * @param message Exception cause.
     * @param cause Exception cause.
     */
    public PGPProcessorException(
            final String message,
            final Throwable cause) {
        super(message, cause);
    }
}

  
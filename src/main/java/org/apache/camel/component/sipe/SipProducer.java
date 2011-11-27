/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.camel.component.sipe;

import org.apache.camel.AsyncCallback;
import org.apache.camel.AsyncProcessor;
import org.apache.camel.Exchange;
import org.apache.camel.ServicePoolAware;
import org.apache.camel.impl.DefaultProducer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SipProducer extends DefaultProducer implements AsyncProcessor, ServicePoolAware {
    private static final Logger log = LoggerFactory.getLogger(SipProducer.class);

    public static final String COMPLETED = "org.apache.camel.component.sipe.SipProducer.COMPLETED";
    public static final long TIMEOUT = 10000;

    private SipEndpoint sipEndpoint;

    public SipProducer(SipEndpoint sipEndpoint) {
        super(sipEndpoint);
        this.sipEndpoint = sipEndpoint;
    }

    // DefaultProducer doStart/Stop contains logging statements only,
    // so the sequence of super invocation is not essential
    @Override
    protected void doStart() throws Exception {
        super.doStart();
        sipEndpoint.startSipStack();
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();
        sipEndpoint.stopSipStack();
    }

    private String getTo(Exchange exchange) {
        String to = exchange.getIn().getHeader("to", String.class);
        if (to == null)
            to = sipEndpoint.getToUser();
        if (to == null)
            throw new IllegalArgumentException(
                    "SIP adressee not set - use setHeader(\"to\") or specify toUser= route parameter");
        if (to.indexOf("@") == -1) {
            if (sipEndpoint.getToHost() == null)
                throw new IllegalArgumentException(
                        "SIP adressee domain is not set - use user@domain TO or specify toHost= route parameter");
            to = to + "@" + sipEndpoint.getToHost();
        }
        return to;
    }

    public void process(Exchange exchange) throws Exception {
        final String body = exchange.getIn().getBody(String.class);
        String to = getTo(exchange);
        synchronized (body) {
            try {
                sipEndpoint.getSipProducerListener().sendChatMessage(exchange, to, body, new AsyncCallback() {
                    public void done(boolean doneSync) {
                        synchronized (body) {
                            body.notifyAll();
                        }
                    }
                });
                long start = System.currentTimeMillis();
                while (exchange.getProperty(COMPLETED) == null) {
                    body.wait(TIMEOUT);
                    if (System.currentTimeMillis() - start > TIMEOUT)
                        throw new RuntimeException("Too much time elapsed waiting for message completion");
                }
                exchange.removeProperty(COMPLETED);
                if (exchange.isFailed()) {
                    Exception e = exchange.getException();
                    if (e == null)
                        throw new RuntimeException("Exchange failed for unknown reason");
                    else
                        throw e;
                }
            } catch (Exception ex) {
                log.error("process() failed", ex);
                throw ex;
            }
        }
    }

    // http://camel.apache.org/asynchronous-processing.html
    public boolean process(Exchange exchange, AsyncCallback callback) {
        String body = exchange.getIn().getBody(String.class);
        String to;
        try {
            to = getTo(exchange);
        } catch (Exception e) {
            exchange.setException(e);
            //callback.done(true); // XXX ?
            return true;
        }
        try {
            sipEndpoint.getSipProducerListener().sendChatMessage(exchange, to, body, callback);
            return false;
        } catch (Exception ex) {
            log.error("async process() failed", ex);
            exchange.setException(ex);
            return true;
        }
    }
}

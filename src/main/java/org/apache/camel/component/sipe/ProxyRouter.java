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

import gov.nist.javax.sip.stack.HopImpl;
import java.util.ArrayList;
import java.util.ListIterator;
import javax.sip.SipStack;
import javax.sip.address.Hop;
import javax.sip.address.Router;
import javax.sip.message.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class ProxyRouter implements Router {
    private static final Logger log = LoggerFactory.getLogger(ProxyRouter.class);

    SipProducerListener listener;

    public ProxyRouter(SipStack stack, String proxy) {
    }

    void setSipListener(SipProducerListener listener) {
        this.listener = listener;
    }

    public Hop getOutboundProxy() {
        if (log.isDebugEnabled())
            log.debug("routing to " + listener.getProxyHost() + ":" + listener.getProxyPort() + " via " + listener.getTransport().toUpperCase());
        return new HopImpl(listener.getProxyHost(), listener.getProxyPort(), listener.getTransport());
    }

    public ListIterator getNextHops(Request request) {
        ArrayList<Hop> a = new ArrayList<Hop>(1);
        a.add(getNextHop(request));
        return a.listIterator();
    }

    public Hop getNextHop(Request request) {
        return getOutboundProxy();
    }
}

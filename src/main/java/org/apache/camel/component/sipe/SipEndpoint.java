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

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.sip.ListeningPoint;
import javax.sip.SipFactory;
import javax.sip.SipProvider;
import javax.sip.SipStack;

import org.apache.camel.Component;
import org.apache.camel.Consumer;
import org.apache.camel.Processor;
import org.apache.camel.Producer;
import org.apache.camel.impl.DefaultEndpoint;
import org.apache.camel.util.ObjectHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SipEndpoint extends DefaultEndpoint {
    private static final transient Logger log = LoggerFactory.getLogger(SipEndpoint.class);

    private static volatile int seq = 0;
    private static final SipFactory sipFactory = SipFactory.getInstance();
    static {
        sipFactory.setPathName("gov.nist");
    }
    private final Map<String, SipProducerListener> listeningPointListeners = new HashMap<String, SipProducerListener>();

    private String uri;

    private final Properties sipStackProperties = new Properties();

    // only set in instance of SipEndpoint that created Listening Point, Provider, and started the SIP stack
    private SipStack sipStack = null;
    private ListeningPoint listeningPoint;
    private SipProvider provider;
    // set in every instance of SipEndpoint
    private SipProducerListener sipProducerListener = null;
    // reference counter for every Producer started/stopped
    private int refCounter = 0;

    private String stackName;
    private String transport = "tcp";
    private String trustStore;
    private String keyStore;
    private String keyStorePassword;
    private int maxForwards;
    private boolean consumer = false;
    private String maxMessageSize;
    // XXX not used
    private String contentType = "text/plain";
    private String serverLog;
    private String debugLog;
    private String traceLevel = "32";
    private String ip;
	private String authUserName;
	private String authPassword;
	private String authAdDomain;
    private final Set<String> presenceList = new HashSet<String>();
    private String fromUser;
    private String fromHost;
    private int fromPort = 5060;
    private String toUser;
    private String toHost;
    private String proxyHost;
    private int proxyPort = 5060;

    public SipEndpoint(String uri, String remaining, Component component) throws SocketException {
        super(uri, component);
        this.uri = remaining;

        setStackName("CIH-" + seq++);
        setMaxMessageSize("20480");
        // Possible statuses of users in OCS
        // 3500 - Online
        // 5000 - Inactive
        // 6500 - Busy
        // 9500 - Do not disturb
        // 12500 - Be right back
        // 15500 - Away
        // 18000 - Offline
        setPresenceList("3500,5000,12500,15550");
        setIp(null);
        sipStackProperties.setProperty("javax.sip.USE_ROUTER_FOR_ALL_URIS", "true");
        sipStackProperties.setProperty("javax.sip.ROUTER_PATH", "org.apache.camel.component.sipe.ProxyRouter");
        //sipStackProperties.setProperty("gov.nist.javax.sip.THREAD_POOL_SIZE", "1");
        //sipStackProperties.setProperty("gov.nist.javax.sip.TCP_POST_PARSING_THREAD_POOL_SIZE", "1");
    }

    public boolean isSingleton() {
        return true;
    }

    // do not use atomic ref - use synchronized!
    protected synchronized void startSipStack() throws Exception {
        if (refCounter++ > 0)
            return;

        String user = null;
        String host = null;
        String port = null;

        int portI = uri.indexOf(":");
        if (portI > 0) {
            port = uri.substring(portI+1);
            uri = uri.substring(0, portI);
        }
        int atI = uri.indexOf("@");
        if (atI > 0) {
            user = uri.substring(0, atI);
            uri = uri.substring(atI);
        }
        host = uri;

        if (consumer) {
            if (fromUser == null)
                fromUser = user;
            fromHost = host;
            if (port != null)
                fromPort = Integer.valueOf(port);
        } else {
            if (toUser == null)
                toUser = user;
            proxyHost = host;
            if (port != null)
                proxyPort = Integer.valueOf(port);
            ObjectHelper.notNull(proxyHost, "Proxy Host (sipe:proxy-host:port)");
        }
        ObjectHelper.notNull(fromUser, "fromUser");
        ObjectHelper.notNull(fromHost, "fromHost");
        ObjectHelper.notNull(fromPort, "fromPort");

        String instanceKey = ip + "|" + fromPort;
        synchronized (listeningPointListeners) {
            // TODO must check for transport tcp/tls (at least)
            sipProducerListener = listeningPointListeners.get(instanceKey);
            if (sipProducerListener == null) {
                sipStack = sipFactory.createSipStack(sipStackProperties);
                listeningPoint = sipStack.createListeningPoint(ip, fromPort, transport);
                provider = sipStack.createSipProvider(listeningPoint);
                sipProducerListener = new SipProducerListener(this);
                provider.addSipListener(sipProducerListener);
                ((ProxyRouter)sipStack.getRouter()).setSipListener(sipProducerListener);
                listeningPointListeners.put(instanceKey, sipProducerListener);
            }
            // XXX sipProducerListener is initialized with SipEndpoint with different settings
        }
        if (sipStack != null)
            sipStack.start();
    }

    protected synchronized void stopSipStack() throws Exception {
        if (--refCounter > 0)
            return;

        if (sipStack == null) {
            sipProducerListener = null;
            return;
        }

        sipProducerListener.stopTimer();
        sipStack.stop();
        sipStack.deleteListeningPoint(listeningPoint);
        provider.removeSipListener(sipProducerListener);
        sipStack.deleteSipProvider(provider);
        
        sipProducerListener = null;
        provider = null;
        sipStack = null;
    }

    public Consumer createConsumer(Processor processor) throws Exception {
        if (!consumer)
            throw new UnsupportedOperationException("Endpoint is not a Consumer (set consumer=true)");
        throw new UnsupportedOperationException("SIPE Consumer not implemented");
        // return new SipConsumer(this, processor);
    }

    public Producer createProducer() throws Exception {
        if (consumer)
            throw new UnsupportedOperationException("Endpoint is a Consumer (set consumer=false)");
        return new SipProducer(this);
    }

    private String getInetAddr(NetworkInterface ni) throws SocketException {
        InetAddress addr = null;
        Enumeration<InetAddress> addresses = ni.getInetAddresses();
        while (addresses.hasMoreElements()) {
           addr = addresses.nextElement();
           if (addr instanceof Inet4Address)
               break; // just take first IPv4
        }
        if (addr != null)
            return addr.getHostAddress();
        return null;
    }

    public void setIp(String ip) throws SocketException {
        NetworkInterface ni;
        if (ip != null) {
            // interface by name
            ni = NetworkInterface.getByName(ip);
            if (ni != null) {
                ip = getInetAddr(ni);
                if (ip != null) {
                    this.ip = ip;
                    return;
                }
            }
            // lets hope its IP and not mis-spelled interface name
            this.ip = ip;
            return;
        }
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

        // any other IP that looks goods for the purpose
        while(interfaces.hasMoreElements()) {
            ni = interfaces.nextElement();
            if (ni.isUp() && !ni.isLoopback() && !ni.isPointToPoint() && !ni.isVirtual()) {
                ip = getInetAddr(ni);
                if (ip != null) {
                    this.ip = ip;
                    return;
                }
            }
        }
        throw new SocketException("Unable to determine host primary IP for SIP stack binding");
    }

    public String getIp() {
        return ip;
    }

    public void setPresenceList(String presenceCodes) {
        presenceList.clear();
        presenceList.addAll(Arrays.asList(presenceCodes.split(",")));
    }

    public Set<String> getPresenceList() {
        return presenceList;
    }

    public boolean isConsumer() {
        return consumer;
    }

    public void setConsumer(boolean consumer) {
        this.consumer = consumer;
    }

    public String getAuthAdDomain() {
        return authAdDomain;
    }

    public void setAuthAdDomain(String authAdDomain) {
        this.authAdDomain = authAdDomain;
    }

    public String getAuthUserName() {
        return authUserName;
    }

    public void setAuthUserName(String authUserName) {
        this.authUserName = authUserName;
    }

    public String getAuthPassword() {
        return authPassword;
    }

    public void setAuthPassword(String authPassword) {
        this.authPassword = authPassword;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getFromHost() {
        return fromHost;
    }

    public void setFromHost(String fromHost) {
        this.fromHost = fromHost;
    }

    public int getFromPort() {
        return fromPort;
    }

    public void setFromPort(int fromPort) {
        this.fromPort = fromPort;
    }

    public String getFromUser() {
        return fromUser;
    }

    public void setFromUser(String fromUser) {
        this.fromUser = fromUser;
    }

    public int getMaxForwards() {
        return maxForwards;
    }

    public void setMaxForwards(int maxForwards) {
        this.maxForwards = maxForwards;
    }

    public String getMaxMessageSize() {
        return maxMessageSize;
    }

    public void setMaxMessageSize(String maxMessageSize) {
        this.maxMessageSize = maxMessageSize;
        sipStackProperties.setProperty("gov.nist.javax.sip.MAX_MESSAGE_SIZE", maxMessageSize);
    }

    public String getDebugLog() {
        return debugLog;
    }

    public void setDebugLog(String nistDebugLog) {
        this.debugLog = nistDebugLog;
        sipStackProperties.setProperty("gov.nist.javax.sip.DEBUG_LOG", nistDebugLog);
        setTraceLevel(traceLevel);
    }

    public String getServerLog() {
        return serverLog;
    }

    public void setServerLog(String nistServerLog) {
        this.serverLog = nistServerLog;
        sipStackProperties.setProperty("gov.nist.javax.sip.SERVER_LOG", nistServerLog);
        setTraceLevel(traceLevel);
    }

    public String getTraceLevel() {
        return traceLevel;
    }

    public void setTraceLevel(String nistTraceLevel) {
        this.traceLevel = nistTraceLevel;
        sipStackProperties.setProperty("gov.nist.javax.sip.TRACE_LEVEL", nistTraceLevel);
    }

    public String getStackName() {
        return stackName;
    }

    public void setStackName(String stackName) {
        this.stackName = stackName;
        sipStackProperties.setProperty("javax.sip.STACK_NAME", stackName);
    }

    public String getToHost() {
        return toHost;
    }

    public void setToHost(String toHost) {
        this.toHost = toHost;
    }

    public String getProxyHost() {
        return proxyHost;
    }

    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    public int getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(int toPort) {
        this.proxyPort = toPort;
    }

    public String getToUser() {
        return toUser;
    }

    public void setToUser(String toUser) {
        this.toUser = toUser;
    }

    public String getTransport() {
        return transport;
    }

    public void setTransport(String transport) {
        this.transport = transport;
    }

    public String getKeyStore() {
        return keyStore;
    }

    // see JAIN-SIP gov.nist.core.net.SslNetworkLayer and gov.nist.javax.sip.SipStackImpl
    public void setKeyStore(String keyStore) {
        this.keyStore = keyStore;
        sipStackProperties.setProperty("javax.net.ssl.keyStore", keyStore);
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
        sipStackProperties.setProperty("javax.net.ssl.keyStorePassword", keyStore);
    }

    public String getTrustStore() {
        return trustStore;
    }

    public void setTrustStore(String trustStore) {
        this.trustStore = trustStore;
        sipStackProperties.setProperty("javax.net.ssl.trustStore", keyStore);
    }

    public SipProducerListener getSipProducerListener() {
        return sipProducerListener;
    }

    public SipProvider getProvider() {
        return provider;
    }

    public SipStack getSipStack() {
        return sipStack;
    }
}

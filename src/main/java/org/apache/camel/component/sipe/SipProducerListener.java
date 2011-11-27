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

import gov.nist.javax.sip.Utils;
import gov.nist.javax.sip.header.WWWAuthenticate;
import gov.nist.javax.sip.message.SIPRequest;
import gov.nist.javax.sip.message.SIPResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.sip.ClientTransaction;
import javax.sip.Dialog;
import javax.sip.address.Address;
import javax.sip.address.SipURI;
import javax.sip.header.AuthorizationHeader;
import javax.sip.header.CSeqHeader;
import javax.sip.header.ProxyAuthorizationHeader;
import javax.sip.header.ViaHeader;
import javax.sip.DialogTerminatedEvent;
import javax.sip.IOExceptionEvent;
import javax.sip.InvalidArgumentException;
import javax.sip.RequestEvent;
import javax.sip.ResponseEvent;
import javax.sip.ServerTransaction;
import javax.sip.SipException;
import javax.sip.SipFactory;
import javax.sip.SipListener;
import javax.sip.SipProvider;
import javax.sip.TimeoutEvent;
import javax.sip.TransactionTerminatedEvent;
import javax.sip.address.AddressFactory;
import javax.sip.header.CallIdHeader;
import javax.sip.header.ContactHeader;
import javax.sip.header.ContentTypeHeader;
import javax.sip.header.ExpiresHeader;
import javax.sip.header.FromHeader;
import javax.sip.header.Header;
import javax.sip.header.HeaderFactory;
import javax.sip.header.MaxForwardsHeader;
import javax.sip.header.SubscriptionStateHeader;
import javax.sip.header.ToHeader;
import javax.sip.message.Message;
import javax.sip.message.MessageFactory;
import javax.sip.message.Request;
import javax.sip.message.Response;
import jcifs.ntlmssp.Type2Message;
import jcifs.util.Base64;
import org.apache.camel.AsyncCallback;
import org.apache.camel.Exchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/* Thanks to JAIN-SIP and Pidgin SIPE developers! */

public class SipProducerListener implements SipListener {
    private static final Logger log = LoggerFactory.getLogger(SipProducerListener.class);

    // singletons
    private static final SipFactory sipFactory = SipFactory.getInstance();
	private static AddressFactory addressFactory = null;
	private static HeaderFactory headerFactory = null;
	private static MessageFactory messageFactory = null;

    // headers that never changes
	private static MaxForwardsHeader maxForwardsHeader;
	private static Header userAgentHeader;
	private static Header authSuportedHeader;
    private static Header authEventHeader;
    private static Header authAllowEventsHeader;
	private static Header[] subscribeHeaders;
	private static Header[] inviteHeaders;
	private static ContentTypeHeader defaultContentTypeHeader;

    // for Via header generation
    private static final Utils sipUtils = new Utils();

    private static final int PRESENCE_CACHE_VALIDITY = 3600; // sec
    static {
        try {
            addressFactory = sipFactory.createAddressFactory();
            headerFactory = sipFactory.createHeaderFactory();
            messageFactory = sipFactory.createMessageFactory();
            maxForwardsHeader = headerFactory.createMaxForwardsHeader(70);
            userAgentHeader = headerFactory.createHeader("User-Agent", getUserAgentString());
            authSuportedHeader = headerFactory.createSupportedHeader("gruu-10, com.microsoft.msrtc.presence, adhoclist, msrtc-event-categories");
            authEventHeader = headerFactory.createHeader("Event", "registration");
            authAllowEventsHeader = headerFactory.createHeader("Allow-Events", "presence");
            /* The SUBSCRIBE request uses "presence" Event package as specified in
             * http://www.ietf.org/rfc/rfc3265.txt and http://www.ietf.org/rfc/rfc3856.txt
             * but we're not using application/pidf+xml as specifed in
             * http://www.ietf.org/rfc/rfc3856.txt because it only provides coarse-graned
             * presence state: offline (closed), online (open), away, busy.
             *
             * With MS enhanced presence http://msdn.microsoft.com/en-us/library/dd922532(v=office.12).aspx
             * it possible to get more states: Inactive, Do not disturb, Be right back.
             */
            subscribeHeaders = new Header[] {
                    headerFactory.createHeader("Event", "presence"),
                    headerFactory.createAcceptHeader("application", "rlmi+xml"),
                    headerFactory.createAcceptHeader("multipart", "related"),
                    // this is obsolete and we don't support it
                    // headerFactory.createAcceptHeader("text", "xml+msrtc.pidf"),

                    // MS enhanced presence
                    headerFactory.createAcceptHeader("application", "msrtc-event-categories+xml"),

                    // RFC3856 presence schema
                    // headerFactory.createAcceptHeader("application", "xpidf+xml"),
                    // headerFactory.createAcceptHeader("application", "pidf+xml"),

                    // why?
                    headerFactory.createHeader("Supported", "eventlist"),

                    // BENOTIFY request does not require response
                    // http://msdn.microsoft.com/en-us/library/cc246160(v=PROT.10).aspx
                    headerFactory.createHeader("Supported", "ms-benotify"),
                    headerFactory.createHeader("Proxy-Require", "ms-benotify"),

                    // do not use NOTIFY piggyback on SUBSCRIBE response
                    // http://msdn.microsoft.com/en-us/library/cc246152(v=PROT.10).aspx
                    // headerFactory.createHeader("Supported", "ms-piggyback-first-notify"),

                    // do not use batched SUBSCRIBE
                    // http://msdn.microsoft.com/en-us/library/dd944569(v=office.12).aspx
                    // headerFactory.createHeader("Require", "adhoclist"),
                    // headerFactory.createHeader("Require", "categoryList"),
                    headerFactory.createHeader("Expires", PRESENCE_CACHE_VALIDITY + "")
                };
            inviteHeaders = new Header[] {
                    // do we need this?
                    headerFactory.createHeader("Supported","ms-delayed-accept"),
                    headerFactory.createHeader("Supported","ms-renders-gif"),
                    /*
                    headerFactory.createHeader("Allow", "INVITE"),
                    headerFactory.createHeader("Allow", "BYE"),
                    headerFactory.createHeader("Allow", "ACK"),
                    headerFactory.createHeader("Allow", "CANCEL"),
                    headerFactory.createHeader("Allow", "INFO"),
                    headerFactory.createHeader("Allow", "UPDATE"),
                    headerFactory.createHeader("Allow", "REFER"),
                    headerFactory.createHeader("Allow", "NOTIFY"),
                    headerFactory.createHeader("Allow", "BENOTIFY"),
                    headerFactory.createHeader("Allow", "OPTIONS"),
                    */
                    headerFactory.createHeader("ms-keep-alive", "UAC;hop-hop=yes")
                };
            defaultContentTypeHeader = headerFactory.createContentTypeHeader("text", "plain");
            // defaulContentTypeHeader.setParameter("charset", "UTF-8");
        } catch (Exception ex) {
            log.error("SipProducerListener <clinit> failure", ex);
        }
    }

    private static String getUserAgentString() {
        // UCCAPI/3.5.6907.37 OC/3.5.6907.37 (Microsoft Office Communicator 2007 R2)
        String userAgent = "Camel::SIPE JAIN-SIP/1.2";
        try {
            Properties p = new Properties();
            p.load(SipProducerListener.class.getResourceAsStream("/META-INF/maven/com.tieto/camel-sipe/pom.properties"));
            String cameSipeVersion = p.getProperty("version");
            p.clear();
            p.load(SipProducerListener.class.getResourceAsStream("/META-INF/maven/javax.sip/jain-sip-ri/pom.properties"));
            String jainSipVersion = p.getProperty("version", "1.2");
            userAgent = "Camel::SIPE/" + cameSipeVersion + " JAIN-SIP/" + jainSipVersion;
            log.info("Initializing " + userAgent);
        } catch (Exception e) {}
        return userAgent;
    }

    // supplied by SipEndpoint
    private final SipEndpoint endpoint;
    private final SipProvider provider;
    // Endpoint settings
    public String fromIp;
    private int fromPort;
    private String fromUser;
    private String fromHost;
    private String authUserName;
    private String authPassword;
    private String authAdDomain;
    private String transport;
    // may be modified after 301 redirect
    private String proxyHost;
    private int proxyPort;

    private enum PeerState {
        OUT_OF_DIALOG,
        WAITING_FOR_INVITE_RESPONSE, IN_DIALOG //, WAITING_FOR_BYE_RESPONSE
    }
    private enum PresenceState {
        UNKNOWN, WAITING_FOR_SUBSCRIBE_RESPONSE, WAITING_FOR_NOTIFY, ONLINE, OFFLINE
    }
    private enum ConnectionState {
        UNAUTHORIZED, AUTH1, AUTH2, AUTH3, AUTHORIZED
    }
    ConnectionState state = ConnectionState.UNAUTHORIZED;
    // TODO
    boolean prolongedFailureMode = false;

    // authorization request header caching between phases
    private Request authRequest;
    // fromAddress is constant for the life of Endpoint
    private Address fromAddress;
    // see utils.MSUUID and http://msdn.microsoft.com/en-us/library/dd905844(v=office.12).aspx
    private final String epid;
    private final String sipInstance;
    // the local SIP instance GRUU, learned from auth phase 3 response
    private ContactHeader myContactHeader;

    // set after auth phase 3 is completed, used to create signature for Proxy-Authorization header
	private String authTargetName = "unset";
	private String authRealm = "unset";
	private String authOpaque;
	private byte[] sealKey;
	private byte[] signKey;
    // limit-rate authentication
    private int authRetryCounter = 0;
    private long authRetryTimestamp = 0;

    // for CSeq SIP header
	private long cSeqCounter = 0L;
    // for Cnum NTLM signature
	private long cnumCounter = 0L;

    // SIP transaction and dialog ApplicationData to support SipProducer's state-machine
    private long messageIdCounter = 0;
    private class MessageHolder {
        final long id = ++messageIdCounter;
        final Exchange exchange;
        final String to;
        final String body;
        final AsyncCallback callback;
        final long enqueueTime = System.currentTimeMillis();
        final Peer peer;
        ClientTransaction tx = null;
        //int txRetransmits = 0;

        public MessageHolder(Exchange exchange, String toUser, String body, AsyncCallback callback, Peer peer) {
            this.exchange = exchange;
            this.to = toUser;
            this.body = body;
            this.callback = callback;
            this.peer = peer;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final MessageHolder other = (MessageHolder) obj;
            if (this.id != other.id) {
                return false;
            }
            return true;
        }

        @Override
        public int hashCode() {
            int hash = 3;
            hash = 53 * hash + (int) (this.id ^ (this.id >>> 32));
            return hash;
        }
    };
    private final Deque<MessageHolder> queue = new LinkedList<MessageHolder>();
    private final Map<Long, MessageHolder> lost = new HashMap<Long, MessageHolder>();
    private final Timer timer = new Timer("Camel::SIPE timer", true);
    // for keepAlive()
    private volatile long lastPacket = 0;

    private class Peer {
        final String to;
        PresenceState presenceState = PresenceState.UNKNOWN;
        PeerState state = PeerState.OUT_OF_DIALOG;
        long subscribeSentTime = 0;
        long presenceExpiresTime = 0;
        long inviteSentTime = 0;
        Dialog dialog = null;
        final List messages = new ArrayList<MessageHolder>();

        public Peer(String toUser) {
            this.to = toUser;
        }
    }
    private final Map<String, Peer> peerCache = new HashMap<String, Peer>();

    public SipProducerListener(SipEndpoint endpoint) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        this.endpoint = endpoint;
        this.provider = endpoint.getProvider();
        this.transport = endpoint.getTransport();
        this.fromIp = endpoint.getIp();
        this.fromPort = endpoint.getFromPort();
        this.fromUser = endpoint.getFromUser();
        this.fromHost = endpoint.getFromHost();
        this.authAdDomain = endpoint.getAuthAdDomain();
        this.authUserName = endpoint.getAuthUserName();
        this.authPassword = endpoint.getAuthPassword();
        this.proxyHost = endpoint.getProxyHost();
        this.proxyPort = endpoint.getProxyPort();

        // generate instance EPID
        this.epid = stableEpid();
        this.sipInstance = "<urn:uuid:" + MSUUID.generate(epid) + ">";

        // schedule CRLFCRLF keepalive message and Garbage Collector to handle lost messages
        timer.schedule(
            new TimerTask() {
                @Override
                public void run() {
                    try {
                        gcLostMessages();
                        keepAlive();
                    } catch (Exception ex) {
                        log.error("Timer error", ex);
                    }
                }
            }, SipProducer.TIMEOUT, SipProducer.TIMEOUT/2);
    }

    public void stopTimer() {
        timer.cancel();
    }

    // for ProxyRouter
    public String getProxyHost() {
        return proxyHost;
    }

    public int getProxyPort() {
        return proxyPort;
    }

    public String getTransport() {
        return transport;
    }

	private static String toHex(byte[] bytes){
        if (bytes == null)
            return null;
        StringBuilder result = new StringBuilder(bytes.length*2);
        for (byte bb : bytes)
            result.append(Integer.toString((bb & 0xff) + 0x100, 16).substring(1));
        return result.toString();
	}

	private static final SecureRandom random = new SecureRandom();
	public static byte[] getRandomBytes(int length){
		byte[] rand = new byte[length];
		random.nextBytes(rand);
		return rand;
	}

	public static String getRandomHexStr(int length){
		byte[] randBytes = getRandomBytes(length);
		return toHex(randBytes);
	}

    /* Return a 10-char long EPID with 5 bytes of randomness */
    private String stableEpid() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String src = fromIp + "|" + fromPort + "|" + fromHost;
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        byte[] digest = sha1.digest(src.getBytes("ASCII"));
        return toHex(digest).substring(0, 10);
    }

    private static final String debugLineSeparator = "------------------------------------------";

    private void failExchange(MessageHolder message, Exception e) {
        if (log.isInfoEnabled() && !(e instanceof SipPresenceIncompatible)) {
            String body = message.body;
            if (body != null && body.length() > 50)
                body = body.substring(0, 50);
            log.info("Exchange failed: " + message.id + " " + message.to + " " + body, e);
        }
        long now = System.currentTimeMillis();
        message.exchange.setException(e);
        Peer peer = message.peer;
        peer.messages.remove(message);
        if (peer.state == PeerState.WAITING_FOR_INVITE_RESPONSE
                && peer.inviteSentTime + SipProducer.TIMEOUT/2 < now)
            peer.state = PeerState.OUT_OF_DIALOG;
        if((peer.presenceState == PresenceState.WAITING_FOR_SUBSCRIBE_RESPONSE || peer.presenceState == PresenceState.WAITING_FOR_NOTIFY)
                && peer.subscribeSentTime + SipProducer.TIMEOUT/2 < now)
            peer.presenceState = PresenceState.UNKNOWN;
        completeExchange(message);
    }

    private void completeExchange(MessageHolder message) {
        lost.remove(message.id);
        message.exchange.setProperty(SipProducer.COMPLETED, true);
        message.callback.done(false);
    }

	protected boolean startAuthentication() throws Exception {
        if (authRetryCounter > 5) {
            // start over from central director
            this.proxyHost = endpoint.getProxyHost();
            this.proxyPort = endpoint.getProxyPort();
            authRetryCounter = 0;
        }
        long now = System.currentTimeMillis();
        if (authRetryCounter > 2 && authRetryTimestamp + 10000 > now) {
            log.warn("Rate-limiting authentication");
            // lets somebody to wake-up us later with another message
            return false;
        } else {
            if (log.isDebugEnabled())
                log.debug("starting authentication as " + fromUser + "@" + fromHost);
            ++authRetryCounter;
            authRetryTimestamp = now;
            Request request = create1AuthRequest();
            //ClientTransaction tx = provider.getNewClientTransaction(request);
            //tx.sendRequest();
            provider.sendRequest(request);
            state = ConnectionState.AUTH1;
            return true;
        }
    }

    /* processMessage and SipListener functions are synchronized to serialize state-machine logic */

    private synchronized void processMessages() {
        if (state == ConnectionState.UNAUTHORIZED) {
            try {
                if (!startAuthentication()) {
                    Exception e = new RuntimeException("Unauthorized");
                    for (MessageHolder msg : queue)
                        failExchange(msg, e);
                    queue.clear();
                }
            } catch (Exception ex) {
                log.error("Unable to send authentication request", ex);
                // lets somebody to wake-up us later with another message
            }
            return;
        }
        if (state == ConnectionState.AUTH1 || state == ConnectionState.AUTH2 || state == ConnectionState.AUTH3)
            return;

        long now = System.currentTimeMillis();
        int size = queue.size();
        if (size == 0)
            log.debug("no queued SIP messages to process");
        while (size-- > 0) {
            MessageHolder msg = queue.removeFirst();
            Peer peer = msg.peer;
            try {
                if ((peer.presenceState == PresenceState.ONLINE || peer.presenceState == PresenceState.OFFLINE) &&
                        peer.presenceExpiresTime < now) {
                    if (log.isDebugEnabled())
                        log.debug(peer.to + " presence state expired");
                    peer.presenceState = PresenceState.UNKNOWN;
                }

                if (peer.presenceState == PresenceState.UNKNOWN) {
                    if (log.isDebugEnabled())
                        log.debug("subscribing to " + peer.to + " presence state");
                    Request request = createSubscribeRequest(msg.to);
                    ClientTransaction tx = provider.getNewClientTransaction(request);
                    tx.setApplicationData(msg);
                    tx.sendRequest();
                    peer.presenceState = PresenceState.WAITING_FOR_SUBSCRIBE_RESPONSE;
                    peer.messages.add(msg);
                    peer.subscribeSentTime = now;
                    continue;
                }
                if (peer.presenceState == PresenceState.OFFLINE) {
                    if (log.isDebugEnabled())
                        log.debug(peer.to + " presence status does not allow message delivery");
                    failExchange(msg, new SipPresenceIncompatible("'" + msg.to + "' user presence status does not allow message delivery"));
                    continue;
                }
                if (peer.presenceState == PresenceState.WAITING_FOR_SUBSCRIBE_RESPONSE ||
                    peer.presenceState == PresenceState.WAITING_FOR_NOTIFY) {
                    // lets enqueue into user queue and wait
                    if (log.isDebugEnabled())
                        log.debug("waiting for " + peer.to + " presence status");
                    peer.messages.add(msg);
                    continue;
                }
                // peer.presenceState -> ONLINE
                if (peer.state == PeerState.OUT_OF_DIALOG) {
                    if (log.isDebugEnabled())
                        log.debug(peer.to + " not in dialog, inviting");
                    Request request = createInviteRequest(msg.to);
                    ClientTransaction tx = provider.getNewClientTransaction(request);
                    tx.setApplicationData(msg);
                    tx.sendRequest();
                    peer.state = PeerState.WAITING_FOR_INVITE_RESPONSE;
                    peer.messages.add(msg);
                    peer.inviteSentTime = now;
                    continue;
                }
                if (peer.state == PeerState.WAITING_FOR_INVITE_RESPONSE /* ||
                    peer.state == PeerState.WAITING_FOR_BYE_RESPONSE*/) {
                    if (log.isDebugEnabled())
                        log.debug("waiting for " + peer.to + " INVITE response");
                        // log.debug("waiting for " + peer.to + " INVITE/BYE response");
                    // lets enqueue into user queue and wait
                    peer.messages.add(msg);
                    continue;
                }
                // peer.state -> IN_DIALOG
                if (log.isDebugEnabled())
                    log.debug("sending MESSAGE to " + msg.to);
                Request request = peer.dialog.createRequest(Request.MESSAGE);
                request = createMessageRequestViaDialog(msg.to, msg.body, request);
                ClientTransaction tx = provider.getNewClientTransaction(request);
                tx.setApplicationData(msg);
                peer.dialog.sendRequest(tx);
                msg.tx = tx;
                lastPacket = now;
            } catch (Exception ex) {
                failExchange(msg, ex);
            }
        }
    }

	public synchronized void processResponse(ResponseEvent evt) {
        ClientTransaction tx = evt.getClientTransaction();
        Dialog dialog = evt.getDialog();
        Request request = null;
		Response response = evt.getResponse();
		int status = response.getStatusCode();

        if (log.isDebugEnabled()) {
            if (tx != null) log.debug(tx.toString());
            if (dialog != null) log.debug(dialog.toString());
            log.debug(status + " " + response.getReasonPhrase());
            try {
                if (response instanceof SIPResponse) {
                    String content = ((SIPResponse)response).getMessageContent();
                    if (content != null)
                        log.debug(debugLineSeparator + "\n" + content + "\n" + debugLineSeparator);
                }
            } catch (Exception e) { e.printStackTrace(); }
        }

        try {
            // XXX must match to REGISTER transaction (or no transaction at all)
            // because we can get multiple 401 responses to in-flight (MESSAGE) requests?
            if (state == ConnectionState.AUTH1 || state == ConnectionState.AUTH2) {
                if (status != 401) {
                    log.error("No state machine for auth phase 1/2 and we got " + status + " " + response.getReasonPhrase());
                    return;
                }
            }
            // authentication
            if (state == ConnectionState.AUTH1) {
                extractAuthRealm(response);
                request = create2AuthRequest();
                //ClientTransaction tx = provider.getNewClientTransaction(request);
                state = ConnectionState.AUTH2;
                //tx.sendRequest();
                provider.sendRequest(request);

            } else if (state == ConnectionState.AUTH2) {
                request = create3AuthRequest(response);
                //ClientTransaction tx = provider.getNewClientTransaction(request);
                state = ConnectionState.AUTH3;
                //tx.sendRequest();
                provider.sendRequest(request);

            } else if (state == ConnectionState.AUTH3) {
                if (status == 200) {
                    if (extractGRUU(response)) {
                        state = ConnectionState.AUTHORIZED;
                        authRetryCounter = 0;
                    }
                // http://msdn.microsoft.com/en-us/library/cc246226(v=PROT.10).aspx
                }  else if (status == 301) { // 301 Redirect to Home Server
                    extractHomeServer(response);
                }  else {
                    log.error("Authorization failed: " + status + " " + response.getReasonPhrase());
                }
                if (state != ConnectionState.AUTHORIZED) {
                    state = ConnectionState.UNAUTHORIZED;
                    if (status == 301) {
                        startAuthentication();
                    } else {
                        // start over from central director
                        this.proxyHost = endpoint.getProxyHost();
                        this.proxyPort = endpoint.getProxyPort();
                    }
                } else {
                    log.debug("re-queueing messages after authentication");
                    for (Map.Entry<String, Peer> x : peerCache.entrySet()) {
                        Peer peer = x.getValue();
                        queue.addAll(peer.messages);
                        peer.messages.clear();
                    }
                }

            // message processing
            } else if (state == ConnectionState.AUTHORIZED) {
                if (status == 401) {
                    // start over from central director
                    this.proxyHost = endpoint.getProxyHost();
                    this.proxyPort = endpoint.getProxyPort();
                    state = ConnectionState.UNAUTHORIZED;
                    // re-SUBSCRIBE just in case we missed status change NOTIFY
                    for (Peer peer : peerCache.values())
                        peer.presenceState = PresenceState.UNKNOWN;
                    if (tx != null) {
                        request = tx.getRequest();
                        String method = request.getMethod();
                        boolean invite = Request.INVITE.equals(method);
                        if (invite || Request.MESSAGE.equals(method)) {
                            MessageHolder msg = (MessageHolder) tx.getApplicationData();
                            if (msg != null) {
                                queue.add(msg);
                                if (invite) {
                                    msg.peer.state = PeerState.OUT_OF_DIALOG;
                                    msg.peer.messages.remove(msg);
                                }
                            }
                            // wait for kick from outside if no message was re-queued
                        }
                    }
                } else {
                    if (tx == null) {
                        log.error("Response without transaction: " + status + " " + response.getReasonPhrase());
                        return;
                    }
                    request = tx.getRequest();
                    String method = request.getMethod();
                    MessageHolder msg = (MessageHolder) tx.getApplicationData();
                    if (msg == null) {
                        log.error("Response without transaction's ApplicationData: " + method + " " + status + " " + response.getReasonPhrase());
                        return;
                    }
                    Peer peer = msg.peer;

                    if (method.equals(Request.SUBSCRIBE)) {
                        if (peer.presenceState != PresenceState.WAITING_FOR_SUBSCRIBE_RESPONSE)
                            log.warn("Got " + status + " " + response.getReasonPhrase() +
                                    " in response to SUBSCRIBE but our state is " + peer.presenceState);
                        if (status == 200) {
                            // after refreshed or overriden subscription new NOTIFY must follow shortly
                            // also, NOTIFY may arrive before response
                            if (peer.presenceState == PresenceState.WAITING_FOR_SUBSCRIBE_RESPONSE)
                                peer.presenceState = PresenceState.WAITING_FOR_NOTIFY;
                        } else {
                            log.warn("Got " + status + " " + response.getReasonPhrase() +
                                    " in response to SUBSCRIBE " + peer.to);
                            // 404 is fast path - most likely edge server does not know about the domain
                            if (status == 404) {
                                peer.presenceExpiresTime = System.currentTimeMillis() + 600*1000;
                                peer.presenceState = PresenceState.OFFLINE;
                                queue.addAll(peer.messages);
                                peer.messages.clear();
                            } else {
                                peer.presenceState = PresenceState.UNKNOWN;
                            }
                        }

                    } else if (method.equals(Request.INVITE)) {
                        if (peer.state != PeerState.WAITING_FOR_INVITE_RESPONSE)
                            log.warn("Got " + status + " " + response.getReasonPhrase() +
                                    " in response to INVITE but our state is " + peer.state);

                        if (status == 100 || status == 101) {
                            // 100 Trying
                            // 101 Progress Report ms-diagnostics: 25008;reason="Attempting to route to Primary Pool"
                        } else if (status == 200) {
                            if (response.getHeader("Record-Route") == null)
                                log.error("No Record-Route in " + status + " " + response.getReasonPhrase() +
                                    " in response to INVITE");
                            dialog.setApplicationData(peer);
                            request = dialog.createAck(((CSeqHeader)response.getHeader("CSeq")).getSeqNumber());
                            request = createAckRequestViaDialog(msg.to, request);
                            dialog.sendAck(request);
                            peer.dialog = dialog;
                            // re-queue messages
                            queue.addAll(peer.messages);
                            peer.messages.clear();
                            peer.state = PeerState.IN_DIALOG;
                        } else {
                            log.warn("Got " + status + " " + response.getReasonPhrase() +
                                    " in response to INVITE");
                            peer.state = PeerState.OUT_OF_DIALOG;
                        }
                        // XXX should we ACK 4xx reject with proper auth header?

                    } else if (method.equals(Request.MESSAGE)) {
                        if (status == 200) {
                            completeExchange(msg);
                        // sometimes we also get 500 Stale CSeq Value from OC client
                        // looks like MS bug
                        } else {
                            String exMessage = "Got " + status + " " + response.getReasonPhrase() +
                                    " in response to MESSAGE";
                            log.warn(exMessage);
                            if(status == 481) { // Call Leg/Transaction Does Not Exist
                                // we brobably lost the BYE because connection to OCS timed out
                                peer.state = PeerState.OUT_OF_DIALOG;
                                queue.add(msg);
                            } else {
                                failExchange(msg, new RuntimeException(exMessage));
                            }
                        }

                        /* // just BYE for now to skip INVITE state maintenance troubles
                        request = dialog.createRequest(Request.BYE);
                        request = createByeRequestViaDialog(msg.to, request);
                        ClientTransaction byeTx = provider.getNewClientTransaction(request);
                        byeTx.setApplicationData(msg);
                        dialog.sendRequest(byeTx);
                        peer.state = PeerState.WAITING_FOR_BYE_RESPONSE;
                        */
                    } else if (method.equals(Request.BYE)) {
                        if (status != 200) {
                            log.warn("Got " + status + " " + response.getReasonPhrase() +
                                    " in response to BYE");
                        }
                        queue.addAll(peer.messages);
                        peer.messages.clear();
                        peer.state = PeerState.OUT_OF_DIALOG;
                    } else {
                        log.error("Got " + status + " " + response.getReasonPhrase() +
                                    " in response to " + method);
                    }
                }
            }
            // try to send because listener changed peer state
            processMessages();
        } catch (Exception ex) {
            log.error("SIP response listener failed", ex);
        }
	}

    private void extractAuthRealm(Response response) {
        // extract realm and targetname
        WWWAuthenticate wwwAuthHeader = (WWWAuthenticate)response.getHeader("WWW-Authenticate");
        if (wwwAuthHeader != null) {
            authRealm = wwwAuthHeader.getRealm();
            authTargetName = wwwAuthHeader.getParameter("targetname");
            if (authRealm == null || authTargetName == null)
                log.error("Cannot extract realm/targetname from: " + wwwAuthHeader.toString());
        } else {
            log.error("No WWW-Authenticate header in 401 Unauthorized response");
        }
    }

    private String extractAuthOpaqueAndGssapiData(Response response) {
        // extract NTLM's opaque and gssapi-data
        ListIterator<WWWAuthenticate> auth = response.getHeaders("WWW-Authenticate");
        authOpaque = null;
        if (auth != null) {
            String gssapiData = null;
            while (auth.hasNext()) {
                WWWAuthenticate wwwAuthHeader = auth.next();
                if (log.isDebugEnabled())
                    log.debug(wwwAuthHeader.toString());
                if (wwwAuthHeader.toString().indexOf("NTLM") > 0) {
                    authOpaque = wwwAuthHeader.getOpaque();
                    gssapiData = wwwAuthHeader.getParameter("gssapi-data");
                    break;
                }
            }
            if (authOpaque == null || gssapiData == null)
                log.error("Cannot extract opaque/gssapi-data from response WWW-Authenticate header(s)");
            else
                return gssapiData;
        } else {
            log.error("No WWW-Authenticate header in 401 Unauthorized response");
        }
        return null;
    }

    // do not remove .* - regexp WTF?
    private static final Pattern homeServerPattern =
            Pattern.compile(".*<sip:([^:;>]+)(?::(\\d+))?(?:;transport=(tls|tcp))?>.*",
                Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private void extractHomeServer(Response response) {
        // just take first Contact header
        ContactHeader contactHeader = (ContactHeader)response.getHeader("Contact");
        if (contactHeader != null) {
            String contact = contactHeader.toString();
            Matcher m = homeServerPattern.matcher(contact);
            if (m.matches()) {
                this.proxyHost = m.group(1);
                String portStr = m.group(2);
                if (!"".equals(portStr))
                    this.proxyPort = Integer.parseInt(portStr);
                // leave 'transport' as-is
                if (log.isDebugEnabled())
                    log.debug("home server is " + proxyHost + ":" + proxyPort + " via " + transport.toUpperCase());
            } else {
                log.error("Cannot extract home server address from: " + contact);
            }
        } else {
            log.error("No Contact header in 301 Redirect response");
        }
    }

    private boolean extractGRUU(Response response) throws ParseException {
        // multi-device registration returns multiple Contact headers with all registered
        // devices GRUU-s listed (bindings) - must match the correct one
        ListIterator<ContactHeader> contacts = response.getHeaders("Contact");
        if (contacts != null) {
            String gruu = null;
            while (contacts.hasNext()) {
                ContactHeader contactHeader = contacts.next();
                if (log.isDebugEnabled())
                    log.debug(contactHeader.toString());
                String instance = contactHeader.getParameter("+sip.instance");
                if (sipInstance.equals(instance)) {
                    gruu = contactHeader.getParameter("gruu");
                    break;
                }
            }
            if (gruu != null) {
                if (log.isDebugEnabled())
                    log.debug("authorization completed, my setting:\n\tepid = " +
                            epid + "\tsip.instance = " + sipInstance + "\n\theader gruu = " + gruu);
                myContactHeader = headerFactory.createContactHeader(addressFactory.createAddress(gruu));
                return true;
            } else {
                log.error("No GRUU information found in authorization response Contact header(s)");
            }
        } else {
            log.error("No Contact header found in authorization response");
        }
        log.debug("authentication failed");
        return false;
    }

	public synchronized void processRequest(RequestEvent evt) {
		Request request = evt.getRequest();
        Dialog dialog = evt.getDialog();

        if (log.isDebugEnabled()) {
            log.debug(request.getMethod() + " " + request.getRequestURI());
            try {
                if (request instanceof SIPRequest) {
                    String content = ((SIPRequest)request).getMessageContent();
                    if (content != null)
                        log.debug(debugLineSeparator + "\n" + content + "\n" + debugLineSeparator);
                }
            } catch (Exception e) { e.printStackTrace(); }
        }

        String method = request.getMethod();
        int respCode = Response.OK;

        boolean benotify = "BENOTIFY".equals(method);
        boolean emptyNotify = false;
        if (benotify || Request.NOTIFY.equals(method)) {
            // because we don't use batched SUBSCRIBE, I hope there will be no batched notifications
            // for multiple subscribers in single NOTIFY
            // XXX must implement proper parser
            // XXX implement subscription termination via Subscription-State:

            // empty BENOTIFY with
            // Subscription-State: terminated;expires=0
            // ms-diagnostics-public: 2139;reason="Terminating old subscription since new subscription dialog took over the previous one"
            // has zero length content
            if (request.getRawContent() != null) {
                byte[] rawContent = request.getRawContent();
                String content;
                try {
                    content = new String(rawContent, "UTF-8");
                } catch (UnsupportedEncodingException ex) {
                    throw new RuntimeException(ex);
                }
                int u = content.indexOf("categories\" uri=\"sip:");
                int a = content.indexOf("<availability>");
                if (u == -1 || a == -1) {
                    log.warn("Availability information not found in " + method + " request body:\n" + content);
                    // OCS will shut the NOTIFY delivery then?
                    //respCode = Response.BAD_REQUEST; // XXX also put Reason in response
                }  else {
                    String user = content.substring(u+21, content.indexOf("\"", u+21));
                    String availability = content.substring(a+14, content.indexOf("</availability>"));
                    if (log.isDebugEnabled())
                        log.debug(method + " info: user = " + user + "; availability = " + availability);
                    boolean present = false;
                    if (endpoint.getPresenceList().contains(availability))
                        present = true;
                    Peer peer = peerCache.get(user);
                    if (peer == null) {
                        // NOTIFY received because of SUBSCRIBE sent by previous instance
                        log.debug(user + " not in peer cache");
                        peer = new Peer(user);
                        peerCache.put(user, peer);
                    }
                    SubscriptionStateHeader subscriptionState = (SubscriptionStateHeader) request.getHeader("Subscription-State");
                    long now = System.currentTimeMillis();
                    peer.presenceExpiresTime = now +
                            1000*((subscriptionState != null) ? subscriptionState.getExpires() : PRESENCE_CACHE_VALIDITY);
                    peer.presenceState = present ? PresenceState.ONLINE : PresenceState.OFFLINE;
                    if (log.isDebugEnabled())
                        log.debug(user + " is now " + peer.presenceState);
                    queue.addAll(peer.messages);
                    peer.messages.clear();
                }
            } else {
                emptyNotify = true;
                // XXX handle Subscription-State: terminated?
            }
        } else if (Request.BYE.equals(method)) {
            byeByeDialog(dialog, true);
        } else {
            log.warn(method + " not implemented");
        }

        if (!benotify) {
            ServerTransaction tx = evt.getServerTransaction();
            try {
                Response response = messageFactory.createResponse(respCode, request);
                response.addHeader(createAuthHeader(fromUser, response));
                tx.sendResponse(response);
            } catch (Exception ex) {
                log.error("Unable to send response", ex);
            }
        }

        lastPacket = System.currentTimeMillis();

        if (!emptyNotify)
            processMessages();
	}

    private void byeByeDialog(Dialog dialog, boolean request) {
        if (dialog != null) {
            Peer peer = (Peer) dialog.getApplicationData();
            if (peer != null) {
                if (peer.dialog == dialog) {
                    peer.state = PeerState.OUT_OF_DIALOG;
                    peer.dialog = null;
                } else if (peer.dialog == null) {
                    log.debug("dialog already terminated, currently invoked via " + ((request) ? "BYE request" : "dialog timeout timer"));
                } else {
                    log.debug("terminated dialog is not current peer's dialog");
                }
            } else {
                if (request)
                    log.warn("No Peer associated with BYE request's Dialog");
            }
        } else {
            log.warn("No Dialog associated with BYE request");
        }
    }

    public synchronized void processTimeout(TimeoutEvent timeoutEvent) {
        log.warn("processTimeout received at Sip Producer Listener");

    }

    public synchronized void processDialogTerminated(DialogTerminatedEvent dialogTerminatedEvent) {
        log.debug("processDialogTerminated received at Sip Producer Listener");
        Dialog dialog = dialogTerminatedEvent.getDialog();
        byeByeDialog(dialog, false);
    }

    public synchronized void processIOException(IOExceptionEvent ioExceptionEvent) {
        log.warn("processIOException received at Sip Producer Listener");
    }

    public synchronized void processTransactionTerminated(TransactionTerminatedEvent transactionTerminatedEvent) {
        log.debug("processTransactionTerminated received at Sip Producer Listener");
    }

	public synchronized void sendChatMessage(Exchange exchange, String toUser, String message, AsyncCallback callback) throws Exception {
        log.debug("sending to " + toUser + ", message: " + message);
        if (prolongedFailureMode)
            throw new RuntimeException("Prolonged SIP failures - see previous errors");
        // associate message with user
        Peer peer = peerCache.get(toUser);
        if (peer == null)
            peer = new Peer(toUser);
        peerCache.put(toUser, peer);
        // message holder with auxiliary data
        if (message.isEmpty())
            message = " "; // OC client doesn't like empty messages
        MessageHolder holder = new MessageHolder(exchange, toUser, message, callback, peer);
        // message queue to act upon in processMessages() and SIP listener methods
        queue.addLast(holder);
        // central repository of messages to check for messages lost due to bugs/race conditions
        lost.put(holder.id, holder);
        processMessages(); // kick the state machine
	}

    private synchronized void keepAlive() throws IOException {
        if (state == ConnectionState.AUTHORIZED) {
            if (endpoint.getSipStack() == null)
                return; // timer stopped
            long now = System.currentTimeMillis();
            if (lastPacket + 40000 < now) {
                if (log.isDebugEnabled())
                    log.debug("sending keep-alive to " + proxyHost + ":" + proxyPort);
                ((gov.nist.javax.sip.ListeningPointImpl)
                        endpoint.getSipStack().getListeningPoints().next())
                            .sendHeartbeat(proxyHost, proxyPort);
                lastPacket = now;
            }
        }
    }

    private synchronized void gcLostMessages() {
        long now = System.currentTimeMillis();
        synchronized (lost) {
            Iterator<Map.Entry<Long, MessageHolder>> iter = lost.entrySet().iterator();
            while (iter.hasNext()) {
                Map.Entry<Long, MessageHolder> entry = iter.next();
                MessageHolder message = entry.getValue();
                if (message.enqueueTime + SipProducer.TIMEOUT < now) {
                    iter.remove();
                    queue.remove(message); // remove messages stuck due to failed authentication
                    // nobody needs this message anymore
                    String errMsg = "Lost message after " + SipProducer.TIMEOUT/1000 + "s of processing; peer presence state is "
                            + message.peer.presenceState;
                    failExchange(message, new RuntimeException(errMsg));
                }
            }
        }
    }

    private long nextCSeq() {
        long cSeq = ++cSeqCounter;
        if (cSeq > Integer.MAX_VALUE)
            cSeq = cSeqCounter = 1;
        return cSeq;
    }

    private long nextCnum() {
        return ++cnumCounter;
    }

    private String nextTag() {
        return getRandomHexStr(5);
    }

    private void addHeaders(Message msg, Header[] hdrs) {
        for (Header hdr : hdrs)
            msg.addHeader(hdr);
    }

    private List<ViaHeader> createViaHeader() throws ParseException, InvalidArgumentException {
        return Arrays.asList(headerFactory.createViaHeader(fromIp, fromPort, transport, sipUtils.generateBranchId()));
    }

    /* We send first REGISTER request to learn WWW-Authenticate header's realm and targetname.
     * epid and Contact header's sip.instance are interdependent
     * http://social.microsoft.com/Forums/en/communicationsservertelephony/thread/e95da9b3-5f48-4fd0-927a-bcbee3af176f
     * http://msdn.microsoft.com/en-us/library/dd905844(v=office.12).aspx
     * http://msdn.microsoft.com/en-us/library/dd945069(v=office.12).aspx
     * epid is declared obsoleted by Microsoft in OCS 2007 for the purpose of user agent addressing,
     * http://technet.microsoft.com/en-us/library/bb964041(office.12).aspx
     * but its still must be used for Registration phase to succeed
     * http://msdn.microsoft.com/en-us/library/dd946010(v=office.12).aspx
     * http://msdn.microsoft.com/en-us/library/dd907247(v=office.12).aspx
     * the (my) GRUU will be learned from auth phase 3 200 response
     * http://msdn.microsoft.com/en-us/library/dd949615(v=office.12).aspx
     *
REGISTER sip:cihdev.com;transport=tcp SIP/2.0
Call-ID: 0387b49d142a73837101bcef2185fa4f
CSeq: 55 REGISTER
From: <sip:ocstester3@cihdev.com>;tag=5a61654a7cfe3844;epid=074684aa6f
To: <sip:ocstester3@cihdev.com>
Via: SIP/2.0/TCP 10.57.17.39:5066;branch=38f24744e1dbd0ede67d81631778
Max-Forwards: 70
Contact: <sip:10.57.17.39:5066;transport=tcp>;methods="INVITE, MESSAGE, INFO, OPTIONS, BYE, CANCEL, NOTIFY, ACK, REFER, BENOTIFY";proxy=replace;+sip.instance="<urn:uuid:9634b518-abb4-5216-8afb-9f6479a1f60e>"
User-Agent: UCCAPI/3.5.6907.37 OC/3.5.6907.37 (Microsoft Office Communicator 2007 R2)
Supported: gruu-10,com.microsoft.msrtc.presence,adhoclist,msrtc-event-categories
Content-Length: 0
    */
	private Request createAuthRequest() throws Exception {
		SipURI requestURI = addressFactory.createSipURI(null, fromHost);
		requestURI.setTransportParam(transport);

		SipURI fromURI = addressFactory.createSipURI(fromUser, fromHost);
		this.fromAddress = addressFactory.createAddress(fromURI);
		FromHeader fromHeader = headerFactory.createFromHeader(fromAddress, nextTag());
		fromHeader.setParameter("epid", epid);

		SipURI toURI = addressFactory.createSipURI(fromUser, fromHost);
		Address toAddress = addressFactory.createAddress(toURI);
		ToHeader toHeader = headerFactory.createToHeader(toAddress, null);

		CallIdHeader callIdHeader = headerFactory.createCallIdHeader(getRandomHexStr(16));
		CSeqHeader cSeqHeader = headerFactory.createCSeqHeader(nextCSeq(), Request.REGISTER);

		Request request = messageFactory.createRequest(requestURI,
				Request.REGISTER, callIdHeader, cSeqHeader, fromHeader,
				toHeader, createViaHeader(), maxForwardsHeader);

		Header authContactHeader = headerFactory.createHeader("Contact",
				"<sip:" + fromIp + ":" + fromPort + ";transport=" + transport + ">;" +
				"methods=\"INVITE, MESSAGE, INFO, OPTIONS, BYE, CANCEL, NOTIFY, ACK, REFER, BENOTIFY\";" +
				"proxy=replace;+sip.instance=\"" + sipInstance + "\"");

		request.addHeader(authContactHeader);
		request.addHeader(userAgentHeader);
		request.addHeader(authSuportedHeader);

        this.authRequest = request;

        return request;
 	}

	private Request create1AuthRequest() throws Exception {
        log.debug("sending REGISTER phase 1");
        return createAuthRequest();
 	}

	private Request create2AuthRequest() throws ParseException, InvalidArgumentException, SipException {
        log.debug("sending REGISTER phase 2");

        ((CSeqHeader)authRequest.getHeader("CSeq")).setSeqNumber(nextCSeq());
        ((FromHeader)authRequest.getHeader("From")).setTag(nextTag());
        authRequest.removeHeader("Via");
        authRequest.addHeader(createViaHeader().get(0));
		String authHeaderStr = "NTLM qop=\"auth\", " +
							   "realm=\""+ authRealm +"\", " +
							   "targetname=\"" + authTargetName + "\", " +
							   "gssapi-data=\"\", " +
							   "version=4";
		AuthorizationHeader authHeader = headerFactory.createAuthorizationHeader(authHeaderStr);
		authRequest.addHeader(authHeader);
		authRequest.addHeader(authEventHeader);

        return this.authRequest;
	}

	private Request create3AuthRequest(Response response) throws Exception {
        log.debug("sending REGISTER phase 3");

        long cSeq = nextCSeq();
        ((CSeqHeader)authRequest.getHeader("CSeq")).setSeqNumber(cSeq);
        ((FromHeader)authRequest.getHeader("From")).setTag(nextTag());
        authRequest.removeHeader("Via");
        authRequest.addHeader(createViaHeader().get(0));

        String gssapiData = extractAuthOpaqueAndGssapiData(response);
		if (gssapiData == null)
			throw new SipException("No gssapi-data in response packet from the server, see previous error");

		Type2Message type2 = new Type2Message(Base64.decode(gssapiData));
		Type3Message type3 = new Type3Message(type2, authUserName, authPassword, authAdDomain,
                InetAddress.getLocalHost().getCanonicalHostName());
		/* 1. Authentication protocol ("NTLM", "Kerberos", or "tcpDSK")
		 * 2. crand value as an eight-digit random hexadecimal number
		 * 3. cnum value as a decimal number
		 * 4. realm parameter value without quotes as it appears in the challenge message sent by the
		 * 		server when the SA was created
		 * 5. targetname parameter value without quotes as it appears in the challenge message sent by
		 * 		the server when the SA was created
		 * 6. The value of the Call-ID header field from the message
		 * 7. The sequence number from the CSeq header field
		 * 8. The method from the CSeq header field
		 * 9. The URI in the From header field
		 * 10.The tag parameter value from the From header field
		 * 11.If the authenticating server protocol version is 3 or above, the URI in the To header field
		 * 12.The tag parameter value from the To header field
		 * 13.If the authenticating server protocol version is 3 or above, the "sip" URI from the P-
		 * 		Asserted-Identity or P-Preferred-Identity header field
		 * 14.If the authenticating server protocol version is 3 or above, the "tel" URI from the P-
		 * 		Asserted-Identity or P-Preferred-Identity header field
		 * 15.The value of the Expires header field
		 * 16.If the message is a response, the response code value as a decimal string.
		 */

		String crand = getRandomHexStr(4);
		String callId = ((CallIdHeader)authRequest.getHeader("Call-ID")).getCallId();
        String fromTag = ((FromHeader)authRequest.getHeader("From")).getTag();
        long cnum = nextCnum();
        String msg = "<NTLM>" +                         //1. NTLM
                "<" + crand + ">" +                     //2. crand
                "<" + cnum + ">" +                      //3. cnum
                "<"+ authRealm +">" +                   //4. Realm
                "<" + authTargetName + ">" +            //5. target
                "<" + callId + ">" +                    //6. Call ID
                "<" + cSeq + ">" +                      //7. cSec sequence
                "<REGISTER>" +                          //8. Type of the message
                "<sip:" + fromUser + "@" + fromHost + ">" + //9. From
                "<" + fromTag + ">" +                   //10. From tag
                "<sip:" + fromUser + "@" + fromHost + ">" + //11. From
                "<>" +                                  //12. To Tag
                "<>" +                                  //13. Tag
                "<>" +                                  //14. Tag
                "<>";                                   //15. Expires

		String myGssapiData = Base64.encode(type3.toByteArray(type2));
        this.signKey = type3.getClientSignKey();
        this.sealKey = type3.getClientSealKey();
        String signing = toHex(Type3Message.getSigning(signKey, sealKey, msg));

		String authHeaderStr = "NTLM qop=\"auth\", " +
							"opaque=\"" + authOpaque + "\", " +
							"realm=\""+ authRealm +"\", " +
							"targetname=\"" + authTargetName + "\", " +
							"gssapi-data=\"" + myGssapiData	+"\", " +
							"version=4, " +
							"crand=\"" + crand + "\", " +
							"cnum=\"" + cnum + "\", " +
							"response=\"" + signing + "\"";

		AuthorizationHeader authHeader = headerFactory.createAuthorizationHeader(authHeaderStr);
        authRequest.removeHeader("Authorization");
		authRequest.addHeader(authHeader);
        authRequest.addHeader(authAllowEventsHeader);

        return authRequest;
    }

    private String user(String sip) {
        return sip.substring(0, sip.indexOf("@"));
    }

    private String domain(String sip) {
        return sip.substring(sip.indexOf("@") + 1);
    }

    private Request createSubscribeRequest(String toUser) throws Exception {
        log.debug("sending SUBSCRIBE request");

        // RFC3856 pidf+xml and single category enhanced presence
        // http://msdn.microsoft.com/en-us/library/dd944569(v=office.12).aspx
        SipURI requestURI = addressFactory.createSipURI(user(toUser), domain(toUser));
        // batched enhanced presence
        // SipURI requestURI = addressFactory.createSipURI(null, toHost);
        requestURI.setTransportParam(transport);

        String fromTag = nextTag();
        FromHeader fromHeader = headerFactory.createFromHeader(fromAddress, fromTag);
        // RFC3856 pidf+xml and single category enhanced presence
        // 'transport' is set in requestURI - cannot reuse
        ToHeader toHeader = headerFactory.createToHeader(
                addressFactory.createAddress(addressFactory.createSipURI(user(toUser), domain(toUser))), null);
        // batched enhanced presence
        // ToHeader toHeader = headerFactory.createToHeader(fromAddress, null);
        CallIdHeader callIdHeader = headerFactory.createCallIdHeader(getRandomHexStr(16));
        CSeqHeader cSeqHeader = headerFactory.createCSeqHeader(nextCSeq(), Request.SUBSCRIBE);

        Request request = messageFactory.createRequest(
                requestURI, Request.SUBSCRIBE, callIdHeader,
                cSeqHeader, fromHeader, toHeader, createViaHeader(), maxForwardsHeader);

        request.addHeader(myContactHeader);
        request.addHeader(userAgentHeader);
        addHeaders(request, subscribeHeaders);

        // RFC3856 pidf+xml request would be empty
        String content = "<batchSub xmlns=\"http://schemas.microsoft.com/2006/01/sip/batch-subscribe\" "
            + "uri=\"sip:" + fromUser + "@" + fromHost + "\" name=\"\">"
            + "<action name=\"subscribe\" id=\"" + fromTag + "\">" // any random subscription id
            + "<adhocList>"
            + "<resource uri=\"sip:" + toUser + "\"/>"
            + "</adhocList>"
            + "<categoryList xmlns=\"http://schemas.microsoft.com/2006/09/sip/categorylist\">"
            // only interested in peer state
            // + "<category name=\"services\"/>"
            + "<category name=\"state\"/>"
            + "</categoryList>"
            + "</action>"
            + "</batchSub>";

        ContentTypeHeader contentTypeHeader = headerFactory.createContentTypeHeader("application", "msrtc-adrl-categorylist+xml");
        request.setContent(content, contentTypeHeader);

        // RFC3856 pidf+xml and single category enhanced presence
         request.addHeader(createAuthHeader(toUser, request));
        // batched enhanced presence
        // request.addHeader(createAuthHeader(fromUser, request));

        return request;
	}

	private Request createInviteRequest(String toUser) throws Exception {
        log.debug("sending INVITE request");

        // 480 error if To is set - why?
        SipURI requestURI = addressFactory.createSipURI(null, domain(toUser));

        FromHeader fromHeader = headerFactory.createFromHeader(fromAddress, nextTag());
        SipURI toAddress = addressFactory.createSipURI(user(toUser), domain(toUser));
        Address toNameAddress = addressFactory.createAddress(toAddress);
        ToHeader toHeader = headerFactory.createToHeader(toNameAddress, null);
        String callId = getRandomHexStr(16);
        CallIdHeader callIdHeader = headerFactory.createCallIdHeader(callId);
        CSeqHeader cSeqHeader = headerFactory.createCSeqHeader(nextCSeq(), Request.INVITE);
        // if chat window is still open on the client side and Core is restarted,
        // then Dialog/callId is lost and OC client rejects our INVITE with
        // 488 Not Acceptable Here
        // Ms-client-diagnostics: 52035; reason="This client has an IM session with the same conversation ID"
        Header msConversationId = headerFactory.createHeader("Ms-Conversation-Id", callId);

        ContentTypeHeader contentTypeHeader = headerFactory.createContentTypeHeader("application", "sdp");
        String sdp =
              "v=0\r\n"	+
              "o=- 0 0 IN IP4 " + fromIp + "\r\n" +
              "s=session\r\n" +
              "c=IN IP4 " + fromIp + "\r\n" +
              "t=0 0\r\n" +
              "m=message " + proxyPort + " sip sip:" + fromUser + "@" + fromHost + "\r\n" +
              "a=accept-types:text/plain multipart/alternative text/rtf text/html text/x-msmsgsinvite\r\n";

        Request request = messageFactory.createRequest(
                requestURI, Request.INVITE, callIdHeader,
                cSeqHeader, fromHeader, toHeader, createViaHeader(), maxForwardsHeader, contentTypeHeader, sdp);

        request.addHeader(myContactHeader);
        request.addHeader(userAgentHeader);
        request.addHeader(msConversationId);
        request.addHeader(createAuthHeader(toUser, request));
        addHeaders(request, inviteHeaders);

        return request;
	}

	private Request createAckRequestViaDialog(String toUser, Request request) throws Exception {
        log.debug("sending ACK request via Dialog");

		request.addHeader(userAgentHeader);
        request.removeHeader("Proxy-Authorization");
        request.addHeader(createAuthHeader(toUser, request));

        return request;
    }

	private Request createMessageRequestViaDialog(String toUser, String message, Request request) throws Exception {
        log.debug("sending MESSAGE request via Dialog");

 		request.addHeader(userAgentHeader);
        request.removeHeader("Proxy-Authorization");
		request.addHeader(createAuthHeader(toUser, request));

        // TODO from Camel Exchange header
		ContentTypeHeader contentTypeHeader = defaultContentTypeHeader;
		request.setContent(message, contentTypeHeader);

		return request;
	}

	private Request createByeRequestViaDialog(String toUser, Request request) throws Exception {
        log.debug("sending BYE request via Dialog");

 		request.addHeader(userAgentHeader);
        request.removeHeader("Proxy-Authorization");
		request.addHeader(createAuthHeader(toUser, request));

        return request;
    }

    /* http://msdn.microsoft.com/en-us/library/dd946897(v=office.12).aspx
     */
    ProxyAuthorizationHeader createAuthHeader(String toUser, String callId, long cSeq, String method, String fromTag, String toTag, Integer expires, Integer respCode) throws Exception {
        String crand = getRandomHexStr(4);
        long cnum = nextCnum();
        String msg =
            "<NTLM>" +                                  //1. NTLM
            "<" + crand + ">" +                         //2. crand
            "<" + cnum + ">" +                          //3. cnum
            "<"+ authRealm +">" +                       //4. Realm
            "<" + authTargetName + ">" +                //5. target
            "<" + callId + ">" +                        //6. Call ID
            "<" + cSeq + ">" +                          //7. qSec sequence
            "<" + method + ">" +                        //8. Type of the message
            "<sip:" + fromUser + "@" + fromHost + ">" + //9. From
            "<" + fromTag + ">" +                       //10.From tag
            "<sip:" + toUser + ">" +                    //11.To
            "<" + toTag + ">" +                         //12.To Tag
            "<>" +                                      //13.Tag
            "<>" +                                      //14.Tag
            "<" + ((expires != null) ? expires : "") + ">" +  //15.Expires
            ((respCode != null) ? "<" + respCode + ">" : ""); //16.Response code

        String signing = toHex(Type3Message.getSigning(signKey,sealKey, msg));

        String authHeaderStr = "NTLM qop=\"auth\", " +
            "opaque=\"" + authOpaque + "\", " +
            "realm=\""+ authRealm +"\", " +
            "targetname=\"" + authTargetName + "\", " +
            "crand=\"" + crand + "\", " +
            "cnum=\"" + cnum + "\", " +
            "response=\"" + signing + "\"";

        ProxyAuthorizationHeader authHeader = headerFactory.createProxyAuthorizationHeader(authHeaderStr);
        return authHeader;
    }

    ProxyAuthorizationHeader createAuthHeader(String toUser, Message message) throws Exception {
        String fromTag = ((FromHeader)message.getHeader("From")).getTag();
        String toTag = ((ToHeader)message.getHeader("To")).getTag();
        if (toTag == null)
            toTag = "";
        CSeqHeader cSeqHeader = (CSeqHeader)message.getHeader("CSeq");
        long cSeq = cSeqHeader.getSeqNumber();
        String method = cSeqHeader.getMethod();
        String callId = ((CallIdHeader)message.getHeader("Call-ID")).getCallId();
        ExpiresHeader expiresHeader = message.getExpires();
        Integer expires = null;
        if (expiresHeader != null)
            expires = expiresHeader.getExpires();
        Integer respCode = null;
        if (message instanceof Response)
            respCode = ((Response)message).getStatusCode();
        return createAuthHeader(toUser, callId, cSeq, method, fromTag, toTag, expires, respCode);
    }
}

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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/* http://msdn.microsoft.com/en-us/library/dd905844(v=office.12).aspx */
public class MSUUID {
    private static final String namespace = "fcacfb03-8a73-46ef-91b1-e5ebeeaba4fe";
    private byte[] uuid = new byte[16];

    public MSUUID(String id) throws NumberFormatException {
        // Jug, thanks!
        if (id.length() != 36)
            throw new NumberFormatException("UUID has to be represented by the standard 36-char representation");

        for (int i = 0, j = 0; i < 36; ++j) {
            // Need to bypass hyphens:
            switch (i) {
            case 8:
            case 13:
            case 18:
            case 23:
                if (id.charAt(i) != '-') {
                    throw new NumberFormatException("UUID has to be represented by the standard 36-char representation");
                }
                ++i;
            }
            char c = id.charAt(i);

            if (c >= '0' && c <= '9') {
                uuid[j] = (byte) ((c - '0') << 4);
            } else if (c >= 'a' && c <= 'f') {
                uuid[j] = (byte) ((c - 'a' + 10) << 4);
            } else if (c >= 'A' && c <= 'F') {
                uuid[j] = (byte) ((c - 'A' + 10) << 4);
            } else {
                throw new NumberFormatException("Non-hex character '"+c+"'");
            }

            c = id.charAt(++i);

            if (c >= '0' && c <= '9') {
                uuid[j] |= (byte) (c - '0');
            } else if (c >= 'a' && c <= 'f') {
                uuid[j] |= (byte) (c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                uuid[j] |= (byte) (c - 'A' + 10);
            } else {
                throw new NumberFormatException("Non-hex character '"+c+"'");
            }
            ++i;
        }
    }

    public static String generate(String epid) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MSUUID uuid = new MSUUID(namespace);
        MessageDigest hash = MessageDigest.getInstance("SHA1");
        uuid.swap();
        hash.update(uuid.uuid);
        hash.update(epid.getBytes("ASCII"));
        uuid.uuid = hash.digest(); // 20 bytes, but anyway...
        uuid.swap();
        uuid.mod();
        return uuid.toString();
    }

    /* this the most critical part the MS stuff differs from all other UUID tools
     * the time_low, time_mid, and time_hi_and_version fields are read as numbers
     * and placed in byte array as little-endian integers, so we must swap out BE
     * loaded data
     */
    private void swap () {
        byte b;
        // time_low
        b = uuid[0];
        uuid[0] = uuid[3];
        uuid[3] = b;
        b = uuid[1];
        uuid[1] = uuid[2];
        uuid[2] = b;
        // time_mid
        b = uuid[4];
        uuid[4] = uuid[5];
        uuid[5] = b;
        // time_hi_and_version
        b = uuid[6];
        uuid[6] = uuid[7];
        uuid[7] = b;
    }

    /* perform masking as specified in UUID specification */
    private final static int INDEX_TYPE = 6;
    private final static int INDEX_VARIATION = 8;
    private void mod() {
        uuid[INDEX_TYPE] &= (byte) 0x0F;
        uuid[INDEX_TYPE] |= (byte) (5 << 4); // v5
        uuid[INDEX_VARIATION] &= (byte) 0x3F;
        uuid[INDEX_VARIATION] |= (byte) 0x80;
    }

    private final static String hexChars = "0123456789abcdef";
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(36);
        for (int i = 0; i < 16; ++i) {
            switch (i) {
                case 4:
                case 6:
                case 8:
                case 10:
                    sb.append('-');
            }
            int hex = uuid[i] & 0xFF;
            sb.append(hexChars.charAt(hex >> 4));
            sb.append(hexChars.charAt(hex & 0x0f));
        }
        return sb.toString();
    }
}

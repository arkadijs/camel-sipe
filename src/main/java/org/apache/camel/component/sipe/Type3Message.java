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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import jcifs.ntlmssp.NtlmMessage;
import jcifs.ntlmssp.Type2Message;
import jcifs.util.RC4;


public class Type3Message extends NtlmMessage {

	private static final String RPC_UNICODE_ENCODING = "UnicodeLittleUnmarked";
	private static final SecureRandom RANDOM = new SecureRandom();
	private byte[] lmResponse;
	private byte[] ntResponse;
	private String domain;
	private String user;
	private String passwd;
	private byte[] serverChallenge;
	private String workstation;
	private byte[] masterKey = null;
	private byte[] sessionKey = null;
	private static String encoding = "UTF-16LE";
	private byte[] lm_challenge_response;
	private byte[] nt_challenge_response;
	private byte[] encrypted_random_session_key;
	private byte[] clientSignKey;
	private	byte[] clientSealKey;
	
	public byte[] getClientSignKey() {
		return clientSignKey;
	}

	public byte[] getClientSealKey() {
		return clientSealKey;
	}

	private static byte[] lmHash(String password) throws Exception {
		byte[] oemPassword = password.toUpperCase().getBytes(encoding);
		int length = Math.min(oemPassword.length, 14);
		byte[] keyBytes = new byte[14];
		System.arraycopy(oemPassword, 0, keyBytes, 0, length);
		Key lowKey = createDESKey(keyBytes, 0);
		Key highKey = createDESKey(keyBytes, 7);
		byte[] magicConstant = "KGS!@#$%".getBytes(encoding);
		Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
		des.init(Cipher.ENCRYPT_MODE, lowKey);
		byte[] lowHash = des.doFinal(magicConstant);
		des.init(Cipher.ENCRYPT_MODE, highKey);
		byte[] highHash = des.doFinal(magicConstant);
		byte[] lmHash = new byte[16];
		System.arraycopy(lowHash, 0, lmHash, 0, 8);
		System.arraycopy(highHash, 0, lmHash, 8, 8);
		return lmHash;
	}

	private static byte[] lmResponse(byte[] hash, byte[] challenge)
			throws Exception {
		byte[] keyBytes = new byte[21];
		System.arraycopy(hash, 0, keyBytes, 0, 16);
		Key lowKey = createDESKey(keyBytes, 0);
		Key middleKey = createDESKey(keyBytes, 7);
		Key highKey = createDESKey(keyBytes, 14);
		Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
		des.init(Cipher.ENCRYPT_MODE, lowKey);
		byte[] lowResponse = des.doFinal(challenge);
		des.init(Cipher.ENCRYPT_MODE, middleKey);
		byte[] middleResponse = des.doFinal(challenge);
		des.init(Cipher.ENCRYPT_MODE, highKey);
		byte[] highResponse = des.doFinal(challenge);
		byte[] lmResponse = new byte[24];
		System.arraycopy(lowResponse, 0, lmResponse, 0, 8);
		System.arraycopy(middleResponse, 0, lmResponse, 8, 8);
		System.arraycopy(highResponse, 0, lmResponse, 16, 8);
		return lmResponse;
	}

	private static byte[] ntlmHash(String password) throws Exception {
		byte[] unicodePassword = password.getBytes("UnicodeLittleUnmarked");
		MessageDigest md4 = MessageDigest.getInstance("MD5");
		return md4.digest(unicodePassword);
	}

	private static Key createDESKey(byte[] bytes, int offset) {
		byte[] keyBytes = new byte[7];
		System.arraycopy(bytes, offset, keyBytes, 0, 7);
		byte[] material = new byte[8];
		material[0] = keyBytes[0];
		material[1] = (byte) (keyBytes[0] << 7 | (keyBytes[1] & 0xff) >>> 1);
		material[2] = (byte) (keyBytes[1] << 6 | (keyBytes[2] & 0xff) >>> 2);
		material[3] = (byte) (keyBytes[2] << 5 | (keyBytes[3] & 0xff) >>> 3);
		material[4] = (byte) (keyBytes[3] << 4 | (keyBytes[4] & 0xff) >>> 4);
		material[5] = (byte) (keyBytes[4] << 3 | (keyBytes[5] & 0xff) >>> 5);
		material[6] = (byte) (keyBytes[5] << 2 | (keyBytes[6] & 0xff) >>> 6);
		material[7] = (byte) (keyBytes[6] << 1);
		oddParity(material);
		return new SecretKeySpec(material, "DES");
	}

	private static void oddParity(byte[] bytes) {
		for (int i = 0; i < bytes.length; i++) {
			byte b = bytes[i];
			boolean needsParity = (((b >>> 7) ^ (b >>> 6) ^ (b >>> 5)
					^ (b >>> 4) ^ (b >>> 3) ^ (b >>> 2) ^ (b >>> 1)) & 0x01) == 0;
			if (needsParity) {
				bytes[i] |= (byte) 0x01;
			} else {
				bytes[i] &= (byte) 0xfe;
			}
		}
	}

	public static byte[] getLMResponse(String password, byte[] challenge)
			throws Exception {
		byte[] lmHash = lmHash(password);
		return lmResponse(lmHash, challenge);
	}

	public static byte[] getNTLMResponse(String password, byte[] challenge)
			throws Exception {
		byte[] ntlmHash = ntlmHash(password);
		return lmResponse(ntlmHash, challenge);
	}

	public Type3Message(Type2Message type2, String user, String password,
			String domain, String workstation) throws Exception {
		// setting default flags
		setFlags(1116766805);
		setDomain(domain);
		setUser(user);
		this.passwd = password;
		this.serverChallenge = type2.getChallenge();
		setWorkstation(workstation);
        setLMResponse(getLMResponse(password, type2.getChallenge()));
        setNTResponse(getNTLMResponse(password, type2.getChallenge()));
		setSessionKey(getRandomBytes(16));
	}

	public byte[] getLMResponse() {
		return lmResponse;
	}

	public void setLMResponse(byte[] lmResponse) {
		this.lmResponse = lmResponse;
	}

	public byte[] getNTResponse() {
		return ntResponse;
	}

	public void setNTResponse(byte[] ntResponse) {
		this.ntResponse = ntResponse;
	}

	public String getDomain() {
		return domain;
	}

	public void setDomain(String domain) {
		this.domain = domain;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public String getWorkstation() {
		return workstation;
	}

	public void setWorkstation(String workstation) {
		this.workstation = workstation;
	}

	public byte[] getMasterKey() {
		return masterKey;
	}

	public byte[] getSessionKey() {
		return sessionKey;
	}

	public void setSessionKey(byte[] sessionKey) {
		this.sessionKey = sessionKey;
	}

	public byte[] toByteArray() {
		return null;

	}

	public byte[] toByteArray(Type2Message type2) throws NoSuchAlgorithmException {
		String domainName = getDomain();
		byte[] domain = null;
		if (domainName != null && domainName.length() != 0) {
			try {
				domain = domainName.getBytes(encoding);
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		}
		int domainLength = (domain != null) ? domain.length : 0;
		String userName = getUser();
		byte[] user = null;
		if (userName != null && userName.length() != 0) {
			try {
				user = userName.getBytes(encoding);
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		}
		int userLength = (user != null) ? user.length : 0;
		String workstationName = getWorkstation();
		byte[] workstation = null;
		if (workstationName != null && workstationName.length() != 0) {
			try {
				workstation = workstationName.toUpperCase().getBytes(encoding);
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		}
		int workstationLength = (workstation != null) ? workstation.length : 0;

		//##############################SIGNING###############################
		// test
		// hexToByte("EB0B8069E6FBB633", this.serverChallenge);
		// clientChallenge is 8 bytes long
		byte[] clientChallenge = getRandomBytes(8);
		// hexToByte("D54EDD51623119DC", clientChallenge);

		byte[] response_key_lm = new byte[16];
		byte[] response_key_nt = new byte[16];
		// NTLM V2 logic goes here
		try {
			response_key_lm = NTOWFv2(this.passwd, this.user,	this.domain);
			System.arraycopy(response_key_lm, 0, response_key_nt, 0, 16);

			// System.out.println("response_key_lm=" + toHex(response_key_lm));
			// System.out.println("response_key_nt=" + toHex(response_key_nt));
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		// System.out.println("target_info=" + toHex(type2.getTargetInformation()));

		// calculating response, should be new method!!!!
		int target_info_len = type2.getTargetInformation().length;
		int temp_len = 8 + 8 + 8 + 4 + target_info_len + 4;
		byte[] temp2 = new byte[temp_len + 8];
		// setting bytes array to zero
		setBytesToValue(temp2, (byte) 0);
		temp2[8 + 0] = 1;
		temp2[8 + 1] = 1;
		// setting time value
		byte[] timeBytes = new byte[8];
		long now = System.currentTimeMillis();
		now += 11644473600000l; // milliseconds from January 1, 1601 -> epoch.
		now *= 10000; // tenths of a microsecond.

		convertLongToBytes(convertToLe(now), timeBytes);
		// System.out.println("timeBytes="
		//		+ toHex(timeBytes));
		// hexToByte("AAFBCD64912DCB01", timeBytes);

		System.arraycopy(timeBytes, 0, temp2, 8 + 8, 8);
		// client challenge
		System.arraycopy(clientChallenge, 0, temp2, 8 + 16, 8);
		// target_info
		System.arraycopy(type2.getTargetInformation(), 0, temp2, 8 + 28,target_info_len);
		// server challenge
		System.arraycopy(this.serverChallenge, 0, temp2, 0, 8);

		// System.out.println("temp2=" + toHex(temp2));
		byte[] nt_proof_st = new byte[16];
		try {
			SecretKeySpec keySpec = new SecretKeySpec(response_key_nt, "HmacMD5");
			Mac mac = Mac.getInstance(keySpec.getAlgorithm());
			mac.init(keySpec);
			nt_proof_st = mac.doFinal(temp2);
		} catch (Exception ex) {
		}
		// System.out.println("nt_proof_str="+ toHex(nt_proof_st));

		// another method creating nt challenge response
		nt_challenge_response = new byte[temp_len + 16];
		System.arraycopy(nt_proof_st, 0, nt_challenge_response, 0, 16);
		System.arraycopy(temp2, 8, nt_challenge_response, 16, temp_len);
		// System.out.println("nt_challenge_response="	+ toHex(nt_challenge_response));

		byte[] session_base_key = new byte[16];
		try {
			SecretKeySpec keySpec = new SecretKeySpec(response_key_nt,"HmacMD5");
			Mac mac = Mac.getInstance(keySpec.getAlgorithm());
			mac.init(keySpec);
			session_base_key = mac.doFinal(nt_proof_st);
		} catch (Exception ex) {
		}
		// System.out.println("session_base_key="+ toHex(session_base_key));

		// another method creating lm_challenge_response
		byte[] tmp = new byte[16];
		System.arraycopy(this.serverChallenge, 0, tmp, 0, 8);
		System.arraycopy(clientChallenge, 0, tmp, 8, 8);
		lm_challenge_response = new byte[24];
		try {
			SecretKeySpec keySpec = new SecretKeySpec(response_key_lm,"HmacMD5");
			Mac mac = Mac.getInstance(keySpec.getAlgorithm());
			mac.init(keySpec);
			byte[] mac_res = mac.doFinal(tmp);
			System.arraycopy(mac_res, 0, lm_challenge_response, 0, 16);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		System.arraycopy(clientChallenge, 0, lm_challenge_response, 16, 8);
		// System.out.println("lm_challenge_response=" + toHex(lm_challenge_response));

		// creating key exchange key
		byte[] key_exchange_key = new byte[16];
		System.arraycopy(session_base_key, 0, key_exchange_key, 0, 16);
		// System.out.println("key_exchange_key=" + toHex(key_exchange_key));

		byte[] exported_session_key = getRandomBytes(16);
		// hexToByte("66AD3061AAF79ECC3C72701F5A0BB34B",
		// exported_session_key);
		encrypted_random_session_key = new byte[16];
		RC4 rc4 = new RC4(key_exchange_key);
		rc4.update(exported_session_key, 0, 16,	encrypted_random_session_key, 0);
		// System.out.println("encrypted_random_session_key="+ toHex(encrypted_random_session_key));

        clientSignKey = getSignKey(exported_session_key, true);
        clientSealKey = getSealKey(exported_session_key, true);

		//##############################SIGNING_END###############################

		// first 72 bytes describes positions of information
		int lmLength = (lm_challenge_response != null) ? lm_challenge_response.length : 0;
		int ntLength = (nt_challenge_response != null) ? nt_challenge_response.length : 0;
		int struct_len = 72;
		byte[] type3 = new byte[struct_len + domain.length + user.length
				+ workstation.length + lm_challenge_response.length
				+ nt_challenge_response.length
				+ encrypted_random_session_key.length];
		System.arraycopy(NTLMSSP_SIGNATURE, 0, type3, 0, 8);
		writeULong(type3, 8, 3);

		// flags assigning
		byte[] src = new byte[] { 85, -126, -104, 98 };
		System.arraycopy(src, 0, type3, 60, 4);
		// version information
		src = new byte[] { 5, 1, 40, 10, 0, 0, 0, 15 };
		System.arraycopy(src, 0, type3, 64, 8);

		// let's fill the packet in the correct order
		// then it would be possible to fill content correctly
		int offset = struct_len;
		writeSecurityBuffer(type3, 28, offset, domain);
		offset += domainLength;
		// maybe there can be a problem with capitalizing letters in the
		// username
		writeSecurityBuffer(type3, 36, offset, user);
		offset += userLength;
		writeSecurityBuffer(type3, 44, offset, workstation);
		offset += workstationLength;
		writeSecurityBuffer(type3, 12, offset, lm_challenge_response);
		offset += lmLength;
		writeSecurityBuffer(type3, 20, offset, nt_challenge_response);
		offset += ntLength;
		writeSecurityBuffer(type3, 52, offset, encrypted_random_session_key);

		// System.out.println("type3=" + toHex(type3));
		return type3;
	}
	
	static void setBytesToValue(byte[] byteArr, byte val) {
		for (int i = 0; i < byteArr.length; i++) {
			byteArr[i] = val;
		}
	}

	static void convertLongToBytes(long val, byte[] retByteArr) {
		for (int i = 0; i < 8; i++) {
			retByteArr[7 - i] = (byte) (val >>> (i * 8));
		}
	}

    static void writeULong(byte[] dest, int offset, int ulong) {
        dest[offset] = (byte) (ulong & 0xff);
        dest[offset + 1] = (byte) (ulong >> 8 & 0xff);
        dest[offset + 2] = (byte) (ulong >> 16 & 0xff);
        dest[offset + 3] = (byte) (ulong >> 24 & 0xff);
    }

    static void writeUShort(byte[] dest, int offset, int ushort) {
        dest[offset] = (byte) (ushort & 0xff);
        dest[offset + 1] = (byte) (ushort >> 8 & 0xff);
    }

    static void writeSecurityBuffer(byte[] dest, int offset, int bodyOffset,
            byte[] src) {
        int length = (src != null) ? src.length : 0;
        if (length == 0) return;
        writeUShort(dest, offset, length);
        writeUShort(dest, offset + 2, length);
        writeULong(dest, offset + 4, bodyOffset);
        System.arraycopy(src, 0, dest, bodyOffset, length);
    }

	public static long convertToLe(long long_) {
		ByteBuffer buf = ByteBuffer.allocate(8);
		buf.order(ByteOrder.BIG_ENDIAN);
		buf.putLong(Long.valueOf(long_));
		buf.order(ByteOrder.LITTLE_ENDIAN);
		return buf.getLong(0);
	}

	public static String toHex(byte[] bytes){
        if (bytes == null)
            return null;
        StringBuilder result = new StringBuilder(bytes.length*2);
        for (byte bb : bytes)
            result.append(Integer.toString((bb & 0xff) + 0x100, 16).substring(1));
        return result.toString();
	}

	public static byte[] getRandomBytes(int length){
		byte[] rand = new byte[length];
		RANDOM.nextBytes(rand);
		return rand;
	}

	public static String getRandomHexStr(int length){
		byte[] randBytes = getRandomBytes(length);
		return toHex(randBytes);
	}

	public static String getRandomIntStr(){
		return Integer.valueOf(Math.abs(RANDOM.nextInt())).toString();
	}

	public static byte[] NTOWFv2( String passwd, String username, String domain ) throws Exception {
        MessageDigest md4 = sun.security.provider.MD4.getInstance();
        byte[] unicodePasswd = passwd.getBytes( RPC_UNICODE_ENCODING );
        byte[] passwdDigest = md4.digest( unicodePasswd );
        Mac mac = Mac.getInstance("HmacMD5");
        SecretKey key = new SecretKeySpec( passwdDigest, "HmacMD5" );
        mac.init( key );
        String concat = username.toUpperCase() + domain;
        return mac.doFinal( concat.getBytes( RPC_UNICODE_ENCODING ) );
	}

	public static byte[] getSignKey(byte[] random_session_key, boolean client) throws NoSuchAlgorithmException{
		String magic = client?"session key to client-to-server signing key magic constant":"session key to server-to-client signing key magic constant";
		int len = magic.length();
		int key_len = 16;

		byte[] md5_input = new byte[key_len + len + 1];
	    System.arraycopy(random_session_key, 0, md5_input, 0, key_len);
	    System.arraycopy(magic.getBytes(), 0, md5_input, key_len, len);

	    MessageDigest md5 = MessageDigest.getInstance("MD5");
	    md5.update(md5_input);
	    byte[] sign_key = md5.digest();
	    // System.out.println("sign_key=" + toHex(sign_key));
	    return sign_key;
	}

	public static byte[] getSealKey(byte[] random_session_key, boolean client) throws NoSuchAlgorithmException{
		String magic = client?"session key to client-to-server sealing key magic constant":"session key to server-to-client sealing key magic constant";
		int len = magic.length();
		//128-bit key (Extended session security)
		int key_len = 16;

		byte[] md5_input = new byte[key_len + len + 1];
	    System.arraycopy(random_session_key, 0, md5_input, 0, key_len);
	    System.arraycopy(magic.getBytes(), 0, md5_input, key_len, len);
	    MessageDigest md5 = MessageDigest.getInstance("MD5");
	    md5.update(md5_input);
	    byte[] seal_key = md5.digest();

	    // System.out.println("seal_key=" + toHex(seal_key));
	    return seal_key;
	}

	public static byte[] getSigning(byte[] sign_key, byte[] seal_key, String msg) throws NoSuchAlgorithmException, InvalidKeyException{
		// making seal_key_
		byte[] tmp2 = new byte[16 + 4];
		System.arraycopy(seal_key, 0, tmp2, 0, 16);
		// assigning sequence number 100
		// TODO: hard coded!!!!
		tmp2[16] = 100;
		// System.out.println("tmp2=" + toHex(tmp2));
		MessageDigest md5 = MessageDigest.getInstance("MD5");
	    md5.update(tmp2);
	    byte[] seal_key_ = md5.digest();
	    // System.out.println("seal_key_=" + toHex(seal_key_));

	    // getting MD5 hash to make new seal_key, because NTLMSSP_NEGOTIATE_DATAGRAM is set to true
		byte result[] = new byte[16];
		result[0] = 1;
		result[12] = 100;

		// System.out.println("msg=" + msg);
		byte[] tmp = new byte[msg.getBytes().length + 4];
		tmp[0] = 100;
		System.arraycopy(msg.getBytes(), 0, tmp, 4, msg.getBytes().length);

		//Generate a key for the HMAC-MD5 keyed-hashing algorithm; see RFC 2104 // In practice, you would save this key.
		SecretKeySpec keySpec = new SecretKeySpec( sign_key, "HmacMD5");
		Mac mac = Mac.getInstance(keySpec.getAlgorithm());
		mac.init(keySpec);
		byte[] hmac = mac.doFinal(tmp);
		// System.out.println("hmac=" + toHex(hmac));
		// If desired, convert the digest into a string
		//String digestB64 = new sun.misc.BASE64Encoder().encode(digest);
		//RC4K(seal_key_, seal_key_len, hmac, 8, result+4);

		// when NTLMSSP_NEGOTIATE_KEY_EXCH flag is set to true we need to use RC4K algorithm
		RC4 rc = new RC4(seal_key_);
		rc.update(hmac, 0, 8, result, 4);
		// System.out.println("SIGNING=" + toHex(result));
		return result;
	}
}

package com.digi.xbee.api.packet.common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.digi.xbee.api.models.XBee16BitAddress;
import com.digi.xbee.api.models.XBee64BitAddress;
import com.digi.xbee.api.packet.APIFrameType;
import com.digi.xbee.api.packet.XBeeAPIPacket;
import com.digi.xbee.api.packet.raw.RX64Packet;
import com.digi.xbee.api.utils.ByteUtils;
import com.digi.xbee.api.utils.HexUtils;

public class NodeIdentificationIndicatorPacket extends XBeeAPIPacket {
	
	// Constants.
	private static final int MIN_API_PAYLOAD_LENGTH = 30; // 1 (Frame type) + 8 (32-bit address) + 2 (16-bit address) + 1 (receive options)
														  // + 2 (16-bit remote) + 8 (64-bit remote) + 2 (16-bit parent) + 1 (dev type)
														  // + 1 (source event) + 2 (Digi profile) + 2 (manufacturer ID)
		

	// Variables.
	private final XBee64BitAddress sourceAddress64;
	private final XBee16BitAddress sourceAddress16;

	private final int receiveOptions;
	
	private final XBee64BitAddress remoteAddress64;
	private final XBee16BitAddress remoteAddress16;
	
	private final String NIString;
	
	public int getReceiveOptions() {
		return receiveOptions;
	}

	public XBee64BitAddress getRemoteAddress64() {
		return remoteAddress64;
	}

	public XBee16BitAddress getRemoteAddress16() {
		return remoteAddress16;
	}

	public String getNIString() {
		return NIString;
	}

	public XBee16BitAddress getParentAddress16() {
		return parentAddress16;
	}

	public int getDeviceType() {
		return deviceType;
	}

	public String getDigiProfileID() {
		return digiProfileID;
	}

	public String getManufacturerID() {
		return manufacturerID;
	}

	public int getDeviceTypeIdentifier() {
		return deviceTypeIdentifier;
	}

	private final XBee16BitAddress parentAddress16;
	
	private final int deviceType;
	
	private final int sourceEvent;
	
	private final String digiProfileID;
	private final String manufacturerID;
	
	private final int deviceTypeIdentifier;
	
	private byte[] rfData;

	private Logger logger;
	
	/**
	 * Creates a new {@code NodeIdentificationIndicatorPacket} object from the 
	 * given payload.
	 * 
	 * @param payload The API frame payload. It must start with the frame type 
	 *                corresponding to a Node Identification Indicator packet ({@code 0x95}).
	 *                The byte array must be in {@code OperatingMode.API} mode.
	 * 
	 * @return Parsed ZigBee Receive packet.
	 * 
	 * @throws IllegalArgumentException if {@code payload[0] != APIFrameType.NODE_IDENTIFICATION_INDICATOR.getValue()} or
	 *                                  if {@code payload.length < }{@value #MIN_API_PAYLOAD_LENGTH} or
	 *                                  if {@code receiveOptions < 0} or
	 *                                  if {@code receiveOptions > 255}.
	 * @throws NullPointerException if {@code payload == null}.
	 */
	public static NodeIdentificationIndicatorPacket createPacket(byte[] payload) {
		if (payload == null)
			throw new NullPointerException("Node Identification Indicator packet payload cannot be null.");
		
		// 1 (Frame type) + 8 (32-bit address) + 2 (16-bit address) + 1 (receive options)
		  // + 2 (16-bit remote) + 8 (64-bit remote) + 2 (16-bit parent) + 1 (dev type)
		  // + 1 (source event) + 2 (Digi profile) + 2 (manufacturer ID)
		if (payload.length < MIN_API_PAYLOAD_LENGTH)
			throw new IllegalArgumentException("Incomplete Node Identification Indicator packet.");
		
		if ((payload[0] & 0xFF) != APIFrameType.NODE_IDENTIFICATION_INDICATOR.getValue())
			throw new IllegalArgumentException("Payload is not a Node Identification Indicator packet.");
				
		// payload[0] is the frame type.
		int index = 1;
		
		// 2 bytes of 16-bit address.
		XBee64BitAddress sourceAddress64 = new XBee64BitAddress(Arrays.copyOfRange(payload, index, index + 8));
		index = index + 8;
		
		// 2 bytes of 16-bit address.
		XBee16BitAddress sourceAddress16 = new XBee16BitAddress(payload[index] & 0xFF, payload[index + 1] & 0xFF);
		index = index + 2;
		
		// Receive options
		int receiveOptions = payload[index] & 0xFF;
		index = index + 1;
		
		// Get data.
		byte[] data = null;
		if (index < payload.length)
			data = Arrays.copyOfRange(payload, index, payload.length);
		
		return new NodeIdentificationIndicatorPacket(sourceAddress64, sourceAddress16, receiveOptions, data);
	}

	protected NodeIdentificationIndicatorPacket(XBee64BitAddress sourceAddress64, XBee16BitAddress sourceAddress16, int receiveOptions, byte[] rfData) {
		super(APIFrameType.NODE_IDENTIFICATION_INDICATOR);

		if (sourceAddress64 == null)
			throw new NullPointerException("64-bit source address cannot be null.");
		if (sourceAddress16 == null)
			throw new NullPointerException("16-bit source address cannot be null.");
		if (receiveOptions < 0 || receiveOptions > 255)
			throw new IllegalArgumentException("Receive options value must be between 0 and 255.");

		this.sourceAddress64 = sourceAddress64;
		this.sourceAddress16 = sourceAddress16;
		this.receiveOptions = receiveOptions;
		this.rfData = rfData;
		
		int index = 0;
		
		// 2 bytes of 16-bit address.
		remoteAddress16 = new XBee16BitAddress(rfData[index] & 0xFF, rfData[index + 1] & 0xFF);
		index = index + 2;
		
		// 2 bytes of 64-bit address.
		remoteAddress64 = new XBee64BitAddress(Arrays.copyOfRange(rfData, index, index + 8));
		index = index + 8;
		
		int endIndex;
		for(endIndex=index; endIndex < rfData.length; endIndex++){
			if(rfData[endIndex] == 0x00){
				break;
			}
		}
		
		NIString = new String(Arrays.copyOfRange(rfData, index, endIndex));
		
		index = endIndex+1;
		
		// 2 bytes of 16-bit address.
		parentAddress16 = new XBee16BitAddress(rfData[index] & 0xFF, rfData[index + 1] & 0xFF);
		index = index + 2;
		
		deviceType = rfData[index] & 0xFF;
		index = index + 1;
		
		sourceEvent = rfData[index] & 0xFF;
		index = index + 1;
		
		digiProfileID = HexUtils.prettyHexString(Arrays.copyOfRange(rfData, index, index + 2));
		index = index + 2;
		
		manufacturerID = HexUtils.prettyHexString(Arrays.copyOfRange(rfData,  index, index +2));
		index = index + 2;
		
		deviceTypeIdentifier = ByteUtils.byteArrayToInt(Arrays.copyOfRange(rfData,  index, rfData.length));
		
		
		
		
		
		this.logger = LoggerFactory.getLogger(RX64Packet.class);
	}

	@Override
	protected byte[] getAPIPacketSpecificData() {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		try {
			os.write(sourceAddress64.getValue());
			os.write(sourceAddress16.getValue());
			os.write(receiveOptions);
			if (rfData != null)
				os.write(rfData);
		} catch (IOException e) {
			logger.error(e.getMessage(), e);
		}
		return os.toByteArray();
	}

	@Override
	public boolean needsAPIFrameID() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isBroadcast() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	protected LinkedHashMap<String, String> getAPIPacketParameters() {
		LinkedHashMap<String, String> parameters = new LinkedHashMap<String, String>();

		parameters.put("64-bit source address", HexUtils.prettyHexString(sourceAddress64.toString()));
		parameters.put("16-bit source address", HexUtils.prettyHexString(sourceAddress16.toString()));
		parameters.put("Receive options", HexUtils.prettyHexString(HexUtils.integerToHexString(receiveOptions, 1)));
		parameters.put("16-bit remote address", HexUtils.prettyHexString(remoteAddress16.toString()));
		parameters.put("64-bit remote address", HexUtils.prettyHexString(remoteAddress64.toString()));
		parameters.put("Node identifier", NIString);
		parameters.put("16-bit parent address", HexUtils.prettyHexString(parentAddress16.toString()));
		parameters.put("Device type", HexUtils.prettyHexString(HexUtils.integerToHexString(deviceType, 1)));
		parameters.put("Source event", HexUtils.prettyHexString(HexUtils.integerToHexString(sourceEvent, 1)));
		parameters.put("Digi profile ID", digiProfileID);
		parameters.put("Manufacturer ID", manufacturerID);
		parameters.put("Device type identifier", HexUtils.integerToHexString(deviceTypeIdentifier, 4));
		
		return parameters;
	}

}

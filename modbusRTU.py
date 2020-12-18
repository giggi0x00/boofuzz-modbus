# coding: utf8

import boofuzz
from boofuzz import *
import struct
'''
Modbus-TCP boofuzz python

'''
def crc16(data):
        crc_table=[0x0000,0xC0C1,0xC181,0x0140,0xC301,0x03C0,0x0280,0xC241,0xC601,0x06C0,0x0780,0xC741,0x0500,0xC5C1,0xC481,0x0440,0xCC01,0x0CC0,0x0D80,0xCD41,0x0F00,0xCFC1,0xCE81,0x0E40,0x0A00,0xCAC1,0xCB81,0x0B40,0xC901,0x09C0,0x0880,0xC841,0xD801,0x18C0,0x1980,0xD941,0x1B00,0xDBC1,0xDA81,0x1A40,0x1E00,0xDEC1,0xDF81,0x1F40,0xDD01,0x1DC0,0x1C80,0xDC41,0x1400,0xD4C1,0xD581,0x1540,0xD701,0x17C0,0x1680,0xD641,0xD201,0x12C0,0x1380,0xD341,0x1100,0xD1C1,0xD081,0x1040,0xF001,0x30C0,0x3180,0xF141,0x3300,0xF3C1,0xF281,0x3240,0x3600,0xF6C1,0xF781,0x3740,0xF501,0x35C0,0x3480,0xF441,0x3C00,0xFCC1,0xFD81,0x3D40,0xFF01,0x3FC0,0x3E80,0xFE41,0xFA01,0x3AC0,0x3B80,0xFB41,0x3900,0xF9C1,0xF881,0x3840,0x2800,0xE8C1,0xE981,0x2940,0xEB01,0x2BC0,0x2A80,0xEA41,0xEE01,0x2EC0,0x2F80,0xEF41,0x2D00,0xEDC1,0xEC81,0x2C40,0xE401,0x24C0,0x2580,0xE541,0x2700,0xE7C1,0xE681,0x2640,0x2200,0xE2C1,0xE381,0x2340,0xE101,0x21C0,0x2080,0xE041,0xA001,0x60C0,0x6180,0xA141,0x6300,0xA3C1,0xA281,0x6240,0x6600,0xA6C1,0xA781,0x6740,0xA501,0x65C0,0x6480,0xA441,0x6C00,0xACC1,0xAD81,0x6D40,0xAF01,0x6FC0,0x6E80,0xAE41,0xAA01,0x6AC0,0x6B80,0xAB41,0x6900,0xA9C1,0xA881,0x6840,0x7800,0xB8C1,0xB981,0x7940,0xBB01,0x7BC0,0x7A80,0xBA41,0xBE01,0x7EC0,0x7F80,0xBF41,0x7D00,0xBDC1,0xBC81,0x7C40,0xB401,0x74C0,0x7580,0xB541,0x7700,0xB7C1,0xB681,0x7640,0x7200,0xB2C1,0xB381,0x7340,0xB101,0x71C0,0x7080,0xB041,0x5000,0x90C1,0x9181,0x5140,0x9301,0x53C0,0x5280,0x9241,0x9601,0x56C0,0x5780,0x9741,0x5500,0x95C1,0x9481,0x5440,0x9C01,0x5CC0,0x5D80,0x9D41,0x5F00,0x9FC1,0x9E81,0x5E40,0x5A00,0x9AC1,0x9B81,0x5B40,0x9901,0x59C0,0x5880,0x9841,0x8801,0x48C0,0x4980,0x8941,0x4B00,0x8BC1,0x8A81,0x4A40,0x4E00,0x8EC1,0x8F81,0x4F40,0x8D01,0x4DC0,0x4C80,0x8C41,0x4400,0x84C1,0x8581,0x4540,0x8701,0x47C0,0x4680,0x8641,0x8201,0x42C0,0x4380,0x8341,0x4100,0x81C1,0x8081,0x4040]

        crc_hi=0xFF
        crc_lo=0xFF

        for w in data:
                index=crc_lo ^ ord(w)
                crc_val=crc_table[index]
                crc_temp=crc_val/256
                crc_val_low=crc_val-(crc_temp*256)
                crc_lo=crc_val_low ^ crc_hi
                crc_hi=crc_temp

        crc=crc_hi*256 +crc_lo
        
        return struct.pack("<H", crc)


def main():
	#just for debugging
	target_host = '127.0.01'
	target_port = 5555

	# tcp_connection = SocketConnection(host=target_host, port=target_port, proto='tcp')
	session = Session(sleep_time=2.000,receive_data_after_fuzz=True, target=Target(connection=SerialConnection(port="/dev/ttyACM0",baudrate=9600)))

	s_initialize('read_holding_registers')
	if s_block_start("modbus_head"):
		s_byte(0xff,name='unit Identifier',fuzzable=False)

		if s_block_start('read_holding_registers_block'):
			s_byte(0x01,name='read_holding_registers')
			s_word(0x0000,name='start address')
			s_word(0x0000,name='quantity')
		s_block_end('read_holding_registers_block')

	s_checksum("modbus_head",algorithm=crc16, fuzzable=False);
	s_block_end("modbus_head")

	s_initialize("read_coil_memory")
	if s_block_start("modbus_head"):
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('read_coil_memory_block'):
			s_byte(0x01,name='read_coil_memory')
			s_word(0x0000,name='start address')
			s_word(0x0000,name='quantity')
		s_block_end('read_coil_memory_block')
	s_checksum("modbus_head",algorithm=crc16, fuzzable=False);
	s_block_end("modbus_head")

	s_initialize('ReadDiscreteInputs')
	if s_block_start("modbus_head"):
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('ReadDiscreteInputsRequest'):
			s_byte(0x02,name='funcCode',fuzzable=False)
			s_word(0x0000,name='start_address')
			s_random(value=str("0x0000"),name='quantity',min_length=4,max_length=1000,num_mutations=100,fuzzable=True)
		s_block_end('ReadDiscreteInputsRequest')
		s_checksum("modbus_head",algorithm=crc16, fuzzable=False);
	s_block_end("ReadDiscreteInputs")

	s_initialize('WriteSingleCoil')
	if s_block_start("modbus_head"):
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('WriteSingleCoilRequest'):
			s_byte(0x05,name='funcCode',fuzzable=False)
			s_word(0x0000,name='start_address')
			#s_word(0x0000,name='coil value')
			s_random(value=str("\x00\x00"),name='coil value',min_length=4,max_length=100,num_mutations=500,fuzzable=True)
		s_block_end('WriteSingleCoilRequest')
		s_checksum("modbus_head",algorithm=crc16, fuzzable=False);
	s_block_end("WriteSingleCoil")




	s_initialize('WriteSingleRegister')
	if s_block_start("modbus_head"):
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('WriteSingleRegisterRequest'):
			s_byte(0x06,name='funcCode',fuzzable=False)
			s_word(0x0000,name='start_address')
			#s_word(0x0000,name='coil value')
			s_random(value=str("\x00\x00"),name='coil value',min_length=4,max_length=100,num_mutations=500,fuzzable=True)
		s_block_end('WriteSingleRegisterRequest')
		s_checksum("modbus_head",algorithm=crc16, fuzzable=False);
	s_block_end("WriteSingleRegister")



	s_initialize('WriteMultipleCoils')
	if s_block_start("modbus_head"):
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('WriteMultipleCoilsRequest'):
			s_byte(0x0f,name='func_code',fuzzable=False)
			s_word(0x0000,name='data address')
			s_word(0x0000,name='number of coils')
			s_size("outputsValue",fuzzable=False, length=1) #da non provare a randomizzare
			if s_block_start("outputsValue"):
				s_random(value=str("\x00"),name='outputsValueWMC',min_length=1,max_length=40,num_mutations=20,fuzzable=True)
				s_block_end("outputsValue")
		s_block_end("WriteMultipleCoilsRequest")
		s_checksum("modbus_head",algorithm=crc16, fuzzable=False);
	s_block_end("WriteMultipleCoils")

	s_initialize('WriteMultipleRegisters')
	if s_block_start("modbus_head"):
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('WriteMultipleRRegisters'):
			s_byte(0x10,name='func_code',fuzzable=False)
			s_word(0xFDEF,name='data address',fuzzable=False)
			s_word(0x0008,name='quantity',fuzzable=False)
			s_size("byte_count",fuzzable=True, length=1) 
			#s_word(0x10,name='size',fuzzable=False)
			if s_block_start("byte_count"):
				s_random(value=str("\x00"),name='byte_count_pwd',min_length=10,max_length=1000,num_mutations=100,fuzzable=True)
				s_block_end("byte_count")
		s_block_end("WriteMultipleRRegisters")
		s_checksum("modbus_head",algorithm=crc16, fuzzable=False);
	s_block_end("WriteMultipleRegisters")

	s_initialize('Read_File_Record')
	if s_block_start("modbus_head"):
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('Read_File_RecordR'):
			s_byte(0x14,name='func_code',fuzzable=False)
			s_word(0x07,name='byte_count',fuzzable=True)
			s_word(0x00,name='sub',fuzzable=False)
			s_random(value=str("0x0000"),name='byte_count_pwd',min_length=3,max_length=1000,num_mutations=100,fuzzable=True)
			s_word(0x0000,name='record_number',fuzzable=True)
			s_word(0x0000,name='record_length',fuzzable=True)
			#s_word(0x10,name='size',fuzzable=False)
		s_block_end("Read_File_RecordR")
		s_checksum("modbus_head",algorithm=crc16, fuzzable=False);
	s_block_end("Read_File_Record")

	
	session.connect(s_get('Read_File_Record'))
	session.connect(s_get('WriteMultipleRegisters'))
	session.connect(s_get('WriteMultipleCoils'))
	session.fuzz()

if __name__ == '__main__':
	main()
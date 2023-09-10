#!/usr/bin/python3
# Copyright 2018 David O'Rourke <david.orourke@gmail.com>
# Copyright 2022 MakeMHz LLC <contact@makemhz.com>
# Based on ciso from https://github.com/jamie/ciso

import os
import struct
import sys
import shutil
import platform
import subprocess
import math
import multiprocessing
import multiprocessing.shared_memory
import signal
import datetime
import lz4.frame
import json

CISO_MAGIC = 0x4F534943 # CISO
CISO_HEADER_SIZE = 0x18 # 24
CISO_BLOCK_SIZE = 0x800 # 2048
CISO_HEADER_FMT = '<LLQLBBxx' # Little endian
CISO_PLAIN_BLOCK = 0x80000000

TITLE_MAX_LENGTH = 40
CISO_SPLIT_SIZE = 0xFFBF6000
CHUNK_SIZE      = 128 * 1024
CHUNK_NUM_SECT  = int(CHUNK_SIZE / CISO_BLOCK_SIZE)

MP_NUM_CHUNKS = 64 # number of chunks to read for multiprocessing
MP_CHUNK_SIZE = MP_NUM_CHUNKS * CHUNK_SIZE
MP_CHUNK_SECT = MP_CHUNK_SIZE / CISO_BLOCK_SIZE

CMP_LIST_SMH_PAD  = 4 # pad bytes for each sector in compressed list shm
CMP_LIST_SMH_PAD_SIZE = (CISO_BLOCK_SIZE + CMP_LIST_SMH_PAD) * CHUNK_NUM_SECT * MP_NUM_CHUNKS
SHM_IN_SECT_NAME  = 'ciso_shm_in_sectors'
SHM_CMP_SECT_NAME = 'ciso_shm_cmp_sectors'

#assert(struct.calcsize(CISO_HEADER_FMT) == CISO_HEADER_SIZE)

image_offset = 0
is_redump_converted = False

def get_terminal_size(fd=sys.stdout.fileno()):
	columns, lines = os.get_terminal_size()
	return (lines, columns)

def update_progress(progress, speed = 0):
	console_height, console_width = get_terminal_size()

	speed   = sizeof_fmt(speed) + "/s"
	percent = progress * 100

	static_str_len = 14 # len("Progress:   - ")
	percent_str    = "{:.0f}%".format(percent)
	barLength      = console_width - static_str_len - len(percent_str) - len(speed) - 1
	block          = math.ceil(barLength * progress)
	block_str      = "█" * block
	bar_len_rem    = barLength - block
	rem_str        = "░" * bar_len_rem

	if percent_str == "100%":
		rem_str = "█" * bar_len_rem

	text = "\rProgress: {blocks} {percent} - {speed}".format(
			blocks=block_str + rem_str,
			percent=percent_str,
			speed=speed)

	sys.stdout.write(text)
	sys.stdout.flush()

# https://stackoverflow.com/a/1094933
def sizeof_fmt(num, suffix="B"):
	for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
		if abs(num) < 1024.0:
			return f"{num:3.1f}{unit}{suffix}"
		num /= 1024.0
	return f"{num:.1f}Yi{suffix}"

def check_file_size(f):
	global image_offset

	f.seek(0, os.SEEK_END)
	file_size = f.tell() - image_offset
	ciso = {
			'magic': CISO_MAGIC,
			'ver': 2,
			'block_size': CISO_BLOCK_SIZE,
			'total_bytes': file_size,
			'total_blocks': int(file_size / CISO_BLOCK_SIZE),
			'align': 2,
			}
	f.seek(image_offset, os.SEEK_SET)
	return ciso

def write_cso_header(f, ciso):
	f.write(struct.pack(CISO_HEADER_FMT,
		ciso['magic'],
		CISO_HEADER_SIZE,
		ciso['total_bytes'],
		ciso['block_size'],
		ciso['ver'],
		ciso['align']
		))

def write_block_index(f, block_index):
	for index, block in enumerate(block_index):
		try:
			f.write(struct.pack('<I', block))
		except Exception as e:
			print("Writing block={} with data={} failed.".format(
				index, block))
			print(e)
			sys.exit(1)

def detect_iso_type(f):
	global image_offset

	# Detect if the image is a REDUMP image
	f.seek(0x18310000)
	buffer = f.read(20)
	if buffer == b"MICROSOFT*XBOX*MEDIA":
		print("REDUMP image detected")
		image_offset = 0x18300000
		return

	# Detect if the image is a raw XDVDFS image
	f.seek(0x10000)
	buffer = f.read(20)
	if buffer == b"MICROSOFT*XBOX*MEDIA":
		image_offset = 0
		return

	# Print error and exit
	print("ERROR: Could not detect ISO type.")
	sys.exit(1)

# Pad file size to ATA block size * 2
def pad_file_size(f):
	f.seek(0, os.SEEK_END)
	size = f.tell()
	f.write(struct.pack('<B', 0x00) * (0x400 - (size & 0x3FF)))

def child_sigint(signalnum, frame):
	me = multiprocessing.current_process()
	if me:
		me.close()

def is_redump(iso_file):
	with open(iso_file, 'rb') as f:
		# Detect if the image is a REDUMP image
		f.seek(0x18310000)
		buffer = f.read(20)
		if buffer == b"MICROSOFT*XBOX*MEDIA":
			return True
	return False

def convert_to_xiso(iso_file):
	os_name = platform.system()
	if os_name == 'Windows':
		print("Calling extract-xiso.exe...\n")
		iso_file = conert_to_xiso_win(iso_file)
		print("")
	elif os_name == 'Darwin':
		pass
	elif os_name == 'Linux':
		pass
	return iso_file

def conert_to_xiso_win(iso_file):
	abs_file  = os.path.abspath(iso_file)
	basename  = os.path.basename(abs_file)
	dirname   = os.path.dirname(abs_file)
	old_file  = abs_file + '.old'
	basename_split = os.path.splitext(basename)[0]
	xiso_file = dirname + '/' + basename_split + '.xiso.iso'

	extract_iso_exe = os.path.dirname(os.path.abspath(__file__)) + '/' + 'extract-xiso.exe'

	if not os.path.isfile(extract_iso_exe):
		return iso_file

	if os.path.isfile(old_file):
		os.remove(old_file)

	cmd = (
		extract_iso_exe,
		'-r',
		'-m',
		abs_file
	)

	res = subprocess.run(cmd, shell=True)

	if os.path.isfile(xiso_file):
		os.remove(xiso_file)

	shutil.move(abs_file, xiso_file)
	shutil.move(old_file, abs_file)

	return xiso_file

def compress_chunk(chunk):
	signal.signal(signal.SIGINT, child_sigint)
	try:
		# cache a single instance of the lz4 context, per process
		if not hasattr(compress_chunk, 'lz4_context'):
			compress_chunk.lz4_context = lz4.frame.create_compression_context()
		if not hasattr(compress_chunk, 'inshm'):
			compress_chunk.inshm = multiprocessing.shared_memory.SharedMemory(name=SHM_IN_SECT_NAME)
		if not hasattr(compress_chunk, 'cmpshm'):
			compress_chunk.cmpshm = multiprocessing.shared_memory.SharedMemory(name=SHM_CMP_SECT_NAME)

		inshm  = compress_chunk.inshm
		cmpshm = compress_chunk.cmpshm
		lz4_context = compress_chunk.lz4_context
		compressed_sizes = []
		out_bytes = bytearray()

		in_offset  = chunk * CHUNK_SIZE
		out_offset = chunk * CHUNK_NUM_SECT * CMP_LIST_SMH_PAD + in_offset

		chunk_data  = bytearray(inshm.buf[in_offset: in_offset + CHUNK_SIZE])
		num_sectors = math.ceil(len(chunk_data) / CISO_BLOCK_SIZE)

		for sector in range(num_sectors):
			sector_offset = sector * CISO_BLOCK_SIZE
			raw_data = chunk_data[sector_offset: sector_offset + CISO_BLOCK_SIZE]

			# Compress block
			# Compressed data will have the gzip header on it, we strip that.
			lz4.frame.compress_begin(lz4_context, compression_level=lz4.frame.COMPRESSIONLEVEL_MAX,
				auto_flush=True, content_checksum=False, block_checksum=False, block_linked=False, source_size=False)
			compressed_data = lz4.frame.compress_chunk(lz4_context, raw_data, return_bytearray=True)
			lz4.frame.compress_flush(lz4_context)

			out_bytes += compressed_data
			compressed_size = len(compressed_data)
			compressed_sizes.append(compressed_size)

		cmpshm.buf[out_offset: out_offset + len(out_bytes)] = out_bytes
		return compressed_sizes

	except:
		me = multiprocessing.current_process()
		if me:
			me.close()

def compress_iso(infile):
	global is_redump_converted

	pool   = multiprocessing.Pool()
	inshm  = multiprocessing.shared_memory.SharedMemory(name=SHM_IN_SECT_NAME, create=True, size=MP_CHUNK_SIZE)
	cmpshm = multiprocessing.shared_memory.SharedMemory(name=SHM_CMP_SECT_NAME, create=True, size=CMP_LIST_SMH_PAD_SIZE)

	start_time = datetime.datetime.now().timestamp()
	xiso_should_rm = False

	if is_redump(infile):
		print("Converting to XISO...")
		abs_xiso_file = os.path.abspath(convert_to_xiso(infile))
		abs_infile    = os.path.abspath(infile)
		if abs_xiso_file != abs_infile and os.path.isfile(abs_xiso_file) and os.path.isfile(abs_infile):
			is_redump_converted = True
			infile = abs_xiso_file

	# Replace file extension with .cso
	fout_1 = open(os.path.splitext(infile)[0] + '.1.cso', 'wb')
	fout_2 = None

	with open(infile, 'rb') as fin:
		print("Compressing '{}'".format(infile))

		# Detect and validate the ISO
		detect_iso_type(fin)

		ciso = check_file_size(fin)
		for k, v in ciso.items():
			print("{}: {}".format(k, v))

		write_cso_header(fout_1, ciso)
		block_index = [0x00] * (ciso['total_blocks'] + 1)

		# Write the dummy block index for now.
		write_block_index(fout_1, block_index)

		write_pos = len(block_index) * 4 + CISO_HEADER_SIZE
		align_b = 1 << ciso['align']
		align_m = align_b - 1

		# Alignment buffer is unsigned char.
		alignment_buffer = struct.pack('<B', 0x00) * 64

		# Progress counters
		blocks_total   = ciso['total_blocks'] + 1
		percent_period = ciso['total_blocks'] / 100
		percent_cnt    = 0

		split_fout      = fout_1
		out_bytes       = bytearray()
		mp_chunks_total = math.ceil(ciso['total_bytes'] / MP_CHUNK_SIZE)

		chunks_range = range(MP_NUM_CHUNKS)

		# read in several chunks at once
		for mp_chunk in range(mp_chunks_total):
			mp_chunk_data     = fin.read(MP_CHUNK_SIZE)
			mp_chunk_data_len = len(mp_chunk_data)
			map_range         = chunks_range

			if mp_chunk_data_len != MP_CHUNK_SIZE:
				map_range = range(math.ceil(mp_chunk_data_len / CHUNK_SIZE))

			inshm.buf[0: mp_chunk_data_len] = mp_chunk_data

			try:
				# compress several chunks at once
				compressed_sizes = pool.map(compress_chunk, map_range)
			except:
				pool.terminate()
				pool.join()
				sys.exit()

			inshm_bytes  = bytearray(inshm.buf)
			cmpshm_bytes = bytearray(cmpshm.buf)

			for chunk, compressed_sizes_list in enumerate(compressed_sizes):
				chunk_offset     = chunk * CHUNK_SIZE
				cmp_chunk_offset = chunk * CHUNK_NUM_SECT * CMP_LIST_SMH_PAD + chunk_offset
				cmp_sect_offset  = 0

				for sector, compressed_size in enumerate(compressed_sizes_list):
					block = int(MP_CHUNK_SECT * mp_chunk) + (CHUNK_NUM_SECT * chunk) + sector

					if block >= ciso['total_blocks']:
						break

					raw_block_offset = sector * CISO_BLOCK_SIZE

					# Check if we need to split the ISO (due to FATX limitations)
					# TODO: Determine a better value for this.
					if write_pos > CISO_SPLIT_SIZE:
						# Create new file for the split
						fout_2     = open(os.path.splitext(infile)[0] + '.2.cso', 'wb')
						split_fout = fout_2

						# Reset write position
						write_pos = 0

					# Write alignment
					align = int(write_pos & align_m)
					if align:
						align = align_b - align
						out_bytes += alignment_buffer[:align]
						write_pos += align

					# Mark offset index
					block_index[block] = write_pos >> ciso['align']

					# Ensure compressed data is smaller than raw data
					# TODO: Find optimal block size to avoid fragmentation
					if (compressed_size + 12) >= CISO_BLOCK_SIZE:
						offset = chunk_offset + raw_block_offset
						out_bytes += inshm_bytes[offset: offset + CISO_BLOCK_SIZE]

						# Next index
						write_pos += CISO_BLOCK_SIZE
					else:
						offset = cmp_chunk_offset + cmp_sect_offset
						out_bytes += cmpshm_bytes[offset: offset + compressed_size]

						# LZ4 block marker
						block_index[block] |= 0x80000000

						# Next index
						write_pos += compressed_size

					cmp_sect_offset += compressed_size

					if len(out_bytes) >= CHUNK_SIZE or write_pos > CISO_SPLIT_SIZE:
						split_fout.write(out_bytes)
						out_bytes.clear()

					# Progress bar
					percent_float = block / blocks_total
					percent = round(percent_float * 100, 1)
					if percent > percent_cnt:
						# fin read speed
						speed = block * CISO_BLOCK_SIZE / (datetime.datetime.now().timestamp() - start_time)
						update_progress(percent_float, speed)
						percent_cnt = percent

		# flush left-over bytes
		split_fout.write(out_bytes)

		# TODO: Pad file to ATA block size

		# end for block
		# last position (total size)
		# NOTE: We don't actually need this, but we're keeping it for legacy reasons.
		block_index[-1] = write_pos >> ciso['align']

		# write header and index block
		print("\nWriting block index")
		fout_1.seek(CISO_HEADER_SIZE, os.SEEK_SET)
		write_block_index(fout_1, block_index)

	# end open(infile)
	pad_file_size(fout_1)
	fout_1.close()

	if fout_2:
		pad_file_size(fout_2)
		fout_2.close()

	if is_redump_converted:
		os.remove(infile)

def is_xbe_file(xbe, offset = 0):
	if not os.path.isfile(xbe):
		return False

	with open(xbe, 'rb') as xbe_file:
		xbe_file.seek(offset)
		magic = xbe_file.read(4)

		if magic != b'XBEH':
			return False

	return True

def get_iso_root_dir_offset_and_size(iso_file):
	global image_offset

	iso_header_offset    = 0x10000
	root_dir_sect_offset = 0x14
	sector_size          = 0x800

	with open(iso_file, 'rb') as f:
		detect_iso_type(f)

		f.seek(image_offset + iso_header_offset + root_dir_sect_offset)
		root_dir_sect    = struct.unpack('<I', f.read(4))[0]
		root_dir_offset  = image_offset + root_dir_sect * sector_size
		root_dir_size    = struct.unpack('<I', f.read(4))[0]

	return root_dir_offset, root_dir_size

def get_file_offset_in_iso(iso_file, search_file):
	global image_offset

	file_offset, file_size = get_iso_root_dir_offset_and_size(iso_file)

	for item in search_file.split('\\'):
		file_offset, file_size = get_iso_entry_offset_and_size(iso_file, item, file_offset, file_size)

		if file_offset == 0 or file_size == 0:
			return 0

		file_offset += image_offset

	return file_offset

def get_iso_entry_offset_and_size(iso_file, search_file, dir_offset, dir_size):
	dir_ent_size = 0xe
	sector_size  = 0x800
	dword        = 4

	search_file = search_file.casefold()

	with open(iso_file, 'rb') as f:
		# seek to dir
		dir_sectors = math.ceil(dir_size / sector_size)
		f.seek(dir_offset)

		dir_bytes        = f.read(dir_sectors * sector_size)
		dir_sector_bytes = [dir_bytes[i: i + sector_size] for i in range(0, len(dir_bytes), sector_size)]

		# loop through dir entries
		for sector_bytes in dir_sector_bytes:
			cur_pos = 0

			while True:
				cur_pos_diff = sector_size - cur_pos

				if cur_pos_diff <= 1:
					break

				dir_ent  = sector_bytes[cur_pos: cur_pos + dir_ent_size]
				cur_pos += dir_ent_size
				l_offset = struct.unpack('<H', dir_ent[0:2])[0]

				if l_offset == 0xffff:
					break

				r_offset     = struct.unpack('<H', dir_ent[2:4])[0]
				start_sector = struct.unpack('<I', dir_ent[4:8])[0]
				file_size    = struct.unpack('<I', dir_ent[8:12])[0]
				attribs      = struct.unpack('<B', dir_ent[12:13])[0]
				filename_len = struct.unpack('<B', dir_ent[13:14])[0]
				filename     = sector_bytes[cur_pos: cur_pos + filename_len].decode('utf-8')

				#print("entry: %04X %04X %08X %02X" % (l_offset, r_offset, start_sector, attribs), file_size, filename_len, filename)

				# entries are aligned on 4 byte bounderies
				next_offset = (dword - ((dir_ent_size + filename_len) % dword)) % dword
				cur_pos += filename_len + next_offset

				# our entry was found, return the offset
				if filename.casefold() == search_file:
					ret_offset = start_sector * sector_size
					return ret_offset, file_size

	# entry wasn't found
	return 0, 0

# returns array with section header and raw bytes
def get_xbe_section_bytes(xbe_file, search_section, xbe_offset = 0):
	xbe_header_size     = 0x1000
	section_header_size = 0x38
	base_addr_offset    = 0x104
	cert_addr_offset    = 0x118
	num_sections_offset = 0x11c
	sect_headers_offset = 0x120

	ret_header_bytes = None
	ret_raw_bytes    = None

	with open(xbe_file, 'rb') as f:
		f.seek(xbe_offset)
		header_bytes = f.read(xbe_header_size * 10)

		base_addr         = struct.unpack('<I', header_bytes[base_addr_offset: base_addr_offset + 4])[0]
		cert_addr         = struct.unpack('<I', header_bytes[cert_addr_offset: cert_addr_offset + 4])[0]
		num_sections      = struct.unpack('<I', header_bytes[num_sections_offset: num_sections_offset + 4])[0]
		sect_headers_addr = struct.unpack('<I', header_bytes[sect_headers_offset: sect_headers_offset + 4])[0]

		# section headers
		for i in range(0, num_sections):
			offset = sect_headers_addr - base_addr + i * section_header_size
			sect_header_bytes = header_bytes[offset: offset + section_header_size]

			flags     = sect_header_bytes[0:4]
			rv_addr   = sect_header_bytes[4:8]
			rv_size   = sect_header_bytes[8:12]
			raw_addr  = sect_header_bytes[12:16]
			raw_size  = sect_header_bytes[16:20]
			name_addr = sect_header_bytes[20:24]

			raw_addr  = struct.unpack('<I', raw_addr)[0]
			raw_size  = struct.unpack('<I', raw_size)[0]
			name_addr = struct.unpack('<I', name_addr)[0]

			name_offset = name_addr - base_addr
			name = readcstr(header_bytes, name_offset)

			# title image section
			if name == search_section:
				ret_header_bytes = sect_header_bytes
				f.seek(xbe_offset + raw_addr)
				ret_raw_bytes = f.read(raw_size)
				break

	return ret_header_bytes, ret_raw_bytes

# read C-style strings
def readcstr(bytes, start):
	end = bytes.find(b'\0', start)
	sub = bytes[start: end]

	return sub.decode()

def format_title_bytes(title):
	title = title[0: TITLE_MAX_LENGTH].strip()
	title = title.ljust(TITLE_MAX_LENGTH, "\x00")
	title_bytes = title.encode('utf-16-le')

	return title_bytes

def get_timage_data_from_iso(iso_file, title_id = 0, title = None, version = None):
	xbe_file = 'default.xbe'

	if title_id:
		# Forza Motorsport + XBLA
		if title_id == 0x584C8014 and title == 'CDX':
			xbe_file = 'Forza.xbe'
		# NCAA Football 2005 + Top Spin
		elif title_id == 0x584C000F and title == 'CDX':
			xbe_file = 'NCAA\\DEFAULT.XBE'
		# Hitman 2: Silent Assassin (Rev 2)
		elif title_id == 0x45530009 and title == 'CDX':
			xbe_file = 'hm2.xbe'
		# Star Wars: The Clone Wars + Tetris Worlds
		elif title_id == 0x584C000D and title == 'CDX':
			xbe_file = 'CW\\default.xbe'
		# Ninja Gaiden Video + Dead or Alive X-Treme Beach Volleyball Video + DOA 3 Bonus Materials
		elif title_id == 0x54438005 and title == 'Xbox Demos':
			xbe_file = 'Doa3\\doa3b.xbe'
		# Outlaw Golf: 9 Holes of X-Mas
		elif title_id == 0x5655801B and title == 'Xbox Demos':
			xbe_file = 'OGXmas\\OLGDemo.xbe'
		# Outlaw Golf: Holiday Golf
		elif title_id == 0x53538005 and title == 'Xbox Demos':
			xbe_file = 'OGXmas\\OLGDemo.xbe'
		# Sega GT 2002 + Jet Set Radio Future
		elif title_id == 0x4D53003D and title == 'Xbox Demos':
			xbe_file = 'SegaGT.xbe'
		# World Series Baseball
		elif title_id == 0x5345000E:
			xbe_file = 'wsb2k3_xbox_rel.xbe'
		# NCAA College Basketball 2K3
		elif title_id == 0x53450018:
			xbe_file = 'game.xbe'

	xbe_offset = get_file_offset_in_iso(iso_file, xbe_file)
	return get_xbe_section_bytes(iso_file, '$$XTIMAGE', xbe_offset)

def gen_attach_xbe(iso_file):
	base_dir      = os.path.dirname(os.path.abspath(iso_file))
	#base_dir      = os.path.dirname(os.path.abspath(__file__))
	in_file_name  = os.path.dirname(os.path.abspath(__file__)) + '/attach_cso.xbe'
	out_file_name = base_dir + '/default.xbe'

	if not is_xbe_file(in_file_name):
		return

	xbe_offset = get_file_offset_in_iso(iso_file, 'default.xbe')

	if xbe_offset == 0:
		return

	# https://www.caustik.com/cxbx/download/xbe.htm
	title_img_sect_name   = '$$XTIMAGE'
	num_new_sections      = 1
	xbe_header_size       = 0x1000
	section_header_size   = 0x38
	base_addr_offset      = 0x104
	xbe_img_size_offset   = 0x10c
	cert_addr_offset      = 0x118
	num_sections_offset   = 0x11c
	sect_headers_offset   = 0x120
	sect_rv_addr_offset   = 0x4
	sect_rv_size_offset   = 0x8
	sect_raw_addr_offset  = 0xc
	sect_raw_size_offset  = 0x10
	sect_name_addr_offset = 0x14
	sect_name_ref_offset  = 0x18
	sect_head_ref_offset  = 0x1c
	sect_tail_ref_offset  = 0x20
	sect_digest_offset    = 0x24
	cert_title_id_offset  = 0x8
	cert_title_offset     = 0xc
	cert_title_ver_offset = 0xac

	title_img_sect_header_bytes = None
	title_img_sect_raw_bytes    = None

	# pull data from source xbe
	with open(iso_file, 'rb') as f:
		f.seek(xbe_offset)
		header_bytes = f.read(xbe_header_size * 10)

		base_addr = struct.unpack('<I', header_bytes[base_addr_offset: base_addr_offset + 4])[0]
		cert_addr = struct.unpack('<I', header_bytes[cert_addr_offset: cert_addr_offset + 4])[0]

		# title
		offset = cert_addr - base_addr + cert_title_offset
		title_bytes = header_bytes[offset: offset + TITLE_MAX_LENGTH * 2]

		# title id
		offset = cert_addr - base_addr + cert_title_id_offset
		title_id_bytes = header_bytes[offset: offset + 4]

		#title version
		offset = cert_addr - base_addr + cert_title_ver_offset
		title_ver_bytes = header_bytes[offset: offset + 4]

	title_id  = struct.unpack("<I", title_id_bytes)[0]
	title_ver = struct.unpack("<I", title_ver_bytes)[0]

	title_id_decoded  = "%08X" % title_id
	title_ver_decoded = "%08X" % title_ver
	title_decoded     = title_bytes.decode('utf-16-le').replace('\0', '')

	sect_header_bytes, title_img_sect_raw_bytes = get_timage_data_from_iso(iso_file, title_id, title_decoded, title_ver)

	if sect_header_bytes != None:
		title_img_sect_header_bytes = bytearray(sect_header_bytes)

	# we got a blank title id, fallback to iso name
	if title_id == 0:
		title = os.path.splitext(os.path.basename(iso_file))[0]
		title_bytes = format_title_bytes(title)
	else:
		# Parse JSON and set title, fallback to filename
		if not hasattr(gen_attach_xbe, 'repack_dict'):
			json_file = os.path.dirname(os.path.abspath(__file__)) + '/Titles.json'
			repack_list = open(json_file)
			gen_attach_xbe.repack_dict = json.load(repack_list)
			repack_list.close()

		repack_dict = gen_attach_xbe.repack_dict

		title_found = False
		for ref_json in repack_dict:
			if ref_json['Title ID'] == title_id_decoded and ref_json['Version'] == title_ver_decoded:
				ref_title = ref_json['XBE Title']
				title = ref_title.split('(', 1)[0][:-1]
				title_bytes = format_title_bytes(title)
				title_found = True
				break

		if not title_found:
			title = os.path.splitext(os.path.basename(iso_file))[0]
			title_bytes = format_title_bytes(title)

	title_decoded = title_bytes.decode('utf-16-le').replace('\0', '')
	title_bytes   = title_bytes[0:TITLE_MAX_LENGTH * 2]

	print("Generating default.xbe - Title ID:", title_id_decoded, '- Version:', title_ver_decoded, '- Title:', title_decoded)

	# patch output xbe
	with open(in_file_name, 'rb') as f:
		out_bytes = bytearray(f.read())

	base_addr = struct.unpack('<I', out_bytes[base_addr_offset: base_addr_offset + 4])[0]
	cert_addr = struct.unpack('<I', out_bytes[cert_addr_offset: cert_addr_offset + 4])[0]
	xbe_size  = struct.unpack('<I', out_bytes[xbe_img_size_offset: xbe_img_size_offset + 4])[0] - base_addr

	# title
	title_offset = cert_addr - base_addr + cert_title_offset
	out_bytes[title_offset: title_offset + TITLE_MAX_LENGTH * 2] = title_bytes

	# title id
	title_id_offset = cert_addr - base_addr + cert_title_id_offset
	out_bytes[title_id_offset: title_id_offset + 4] = title_id_bytes

	# title version
	title_ver_offset = cert_addr - base_addr + cert_title_ver_offset
	out_bytes[title_ver_offset: title_ver_offset + 4] = title_ver_bytes

	# title image
	# patch gore incoming
	if title_img_sect_header_bytes != None and title_img_sect_raw_bytes != None:
		num_sections      = struct.unpack('<I', out_bytes[num_sections_offset: num_sections_offset + 4])[0]
		sect_headers_addr = struct.unpack('<I', out_bytes[sect_headers_offset: sect_headers_offset + 4])[0]

		title_img_sect_name_len = len(title_img_sect_name)
		title_img_size  = len(title_img_sect_raw_bytes)
		old_sect_offset = sect_headers_addr - base_addr
		old_section     = out_bytes[old_sect_offset: old_sect_offset + section_header_size * num_sections]
		new_sect_addr   = xbe_header_size - section_header_size * num_sections - title_img_sect_name_len - num_new_sections - section_header_size
		new_sect_len    = xbe_header_size - new_sect_addr

		# patch title img section header
		new_sect_digest_addr = new_sect_addr + section_header_size * num_sections + sect_digest_offset
		new_sect_name_addr   = new_sect_addr + new_sect_len - title_img_sect_name_len - 1
		title_img_sect_header_bytes[sect_rv_addr_offset: sect_rv_addr_offset + 4]     = struct.pack('<I', xbe_size + base_addr)
		title_img_sect_header_bytes[sect_rv_size_offset: sect_rv_size_offset + 4]     = struct.pack('<I', title_img_size)
		title_img_sect_header_bytes[sect_raw_addr_offset: sect_raw_addr_offset + 4]   = struct.pack('<I', xbe_size)
		title_img_sect_header_bytes[sect_raw_size_offset: sect_raw_size_offset + 4]   = struct.pack('<I', title_img_size)
		title_img_sect_header_bytes[sect_name_addr_offset: sect_name_addr_offset + 4] = struct.pack('<I', new_sect_name_addr + base_addr)
		title_img_sect_header_bytes[sect_name_ref_offset: sect_name_ref_offset + 4]   = bytearray(4)
		title_img_sect_header_bytes[sect_digest_offset: sect_digest_offset + 20]      = bytearray(20)
		title_img_sect_header_bytes[sect_head_ref_offset: sect_head_ref_offset + 4]   = struct.pack('<I', new_sect_digest_addr + base_addr)
		title_img_sect_header_bytes[sect_tail_ref_offset: sect_tail_ref_offset + 4]   = struct.pack('<I', new_sect_digest_addr + 2 + base_addr)

		# placed at the end of the xbe header
		out_bytes[new_sect_addr: new_sect_addr + new_sect_len] = (
			old_section +
			title_img_sect_header_bytes +
			bytearray(title_img_sect_name.encode()) +
			b'\0'
		)

		# patch new data in xbe header
		out_bytes[num_sections_offset: num_sections_offset + 4] = struct.pack('<I', num_sections + num_new_sections)
		out_bytes[sect_headers_offset: sect_headers_offset + 4] = struct.pack('<I', new_sect_addr + base_addr)
		out_bytes[xbe_img_size_offset: xbe_img_size_offset + 4] = struct.pack('<I', xbe_size + title_img_size + base_addr)

		out_bytes += title_img_sect_raw_bytes

	with open(out_file_name, 'wb') as f:
		f.write(out_bytes)

	return title_decoded

# move output files to sub-folder
def move_output_files(iso_file, output_name = '', len_limit = 255):
	global is_redump_converted

	base_dir      = os.path.dirname(os.path.abspath(iso_file))
	#base_dir      = os.path.dirname(os.path.abspath(__file__))
	iso_base_name = os.path.splitext(os.path.basename(iso_file))[0]
	out_file_name = base_dir + '/default.xbe'

	if not output_name:
		output_name = os.path.splitext(os.path.basename(iso_file))[0]
		output_name = output_name.strip()

	keepcharacters   = (' ', '.', '_', '-')
	safe_title       = "".join(c for c in output_name if c.isalnum() or c in keepcharacters).rstrip()
	safe_title_trunc = safe_title[0:len_limit - 6]

	cso_1_ext = '.1.cso'
	cso_2_ext = '.2.cso'

	cios1_file = iso_base_name + cso_1_ext
	cios2_file = iso_base_name + cso_2_ext

	if is_redump_converted:
		cios1_file = iso_base_name + '.xiso' + cso_1_ext
		cios2_file = iso_base_name + '.xiso' + cso_2_ext

	out_dir    = base_dir + '/' + safe_title
	ciso1      = base_dir + '/' + cios1_file
	ciso2      = base_dir + '/' + cios2_file
	new_file   = out_dir  + '/' + os.path.basename(out_file_name)
	new_cios1  = out_dir  + '/' + safe_title_trunc + cso_1_ext
	new_cios2  = out_dir  + '/' + safe_title_trunc + cso_2_ext

	if not os.path.isdir(out_dir):
		os.makedirs(out_dir)
	if os.path.isfile(out_file_name) and os.path.isfile(new_file):
		os.remove(new_file)
	if os.path.isfile(ciso1) and os.path.isfile(new_cios1):
		os.remove(new_cios1)
	if os.path.isfile(ciso2) and os.path.isfile(new_cios2):
		os.remove(new_cios2)
	if os.path.isfile(out_file_name) and not os.path.isfile(new_file):
		shutil.move(out_file_name, new_file)
	if os.path.isfile(ciso1) and not os.path.isfile(new_cios1):
		shutil.move(ciso1, new_cios1)
	if os.path.isfile(ciso2) and not os.path.isfile(new_cios2):
		shutil.move(ciso2, new_cios2)

def main(argv):
	global is_redump_converted

	for i in range(1, len(argv)):
		infile = argv[i]
		compress_iso(infile)
		title = gen_attach_xbe(infile)

		if title:
			move_output_files(infile, title, 42)

		is_redump_converted = False

		print("")

if __name__ == '__main__':
	multiprocessing.freeze_support()
	sys.exit(main(sys.argv))

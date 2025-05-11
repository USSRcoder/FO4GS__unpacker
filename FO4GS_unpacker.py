import pefile,hashlib,zlib,sys,os,array

print('\nFO4GS Unpacker. 07.05.2025\n')

def help():
    print('Usage :',sys.argv[0], 'installer.exe','[-v] [-e<dir>]')
    print('\t-x<dir> - \teXtract to dir')
    print('\t-v      - \tVerbose on')
    print('\t*Default files list mode.')
    exit();

g_verbose = 0
g_odir = ''
g_extract_dir = ''
g_fn = ''
g_sections = []
_ofs = -1
_crcb = ''
_key = ''

g_arg_len = len(sys.argv)-1
i = g_arg_len
while i > 0:
    if (sys.argv[i][0:1]=='-' or sys.argv[i][0:1]=='/'):
        if (sys.argv[i][1:2]=='?' or sys.argv[i][1:2]=='h'):
            help()
        elif sys.argv[i][1:2]=='v':
            g_verbose = 1
        elif sys.argv[i][1:2]=='x':
            g_odir = sys.argv[i][2:]
            g_extract_dir = g_odir
            if g_extract_dir[:-1] != '\\':
                g_extract_dir += '\\'

    else:
        g_fn = sys.argv[i]
    i-=1

if (g_fn==''): 
    help()


# digest
#
salt = bytes.fromhex('7F3BD50670064905BB8E8E918EC08D98979A8CE0D1D0AD9B949B9D8CE08C989BE09B888C8E9F9D8C979192E0909F8C98AD9B949B9D8CE08C989BE089918E95979299E09C978E9B9D8C918E879ECE9B9F8E998D9ECE9B97929D9A97949B909F8C989ECE9B97929D9A97949B9D918B928C9ECE9B97929D9A97949B9D939CD19DD29B889BD29E9F8C9B888C9C0000000000')

def dig5(x): 
    return hashlib.md5(x.encode()).hexdigest().upper()
def dig1(x): 
    return hashlib.sha1(x.encode()).hexdigest().upper()

# write output
#
def write_to_fn(fn, buf, H =""):
    if (g_odir != ''):
        pth = os.path.dirname(fn)
        os.makedirs(g_extract_dir + pth, exist_ok=True)
        with open(g_extract_dir + fn, "wb") as output_file:
            output_file.write(buf)
def print_stat(H, fname, sz, attr='', dta='', _beg = "", _end = "\n"):
    if (g_verbose):
        print (f"{_beg}", H.ljust(40), sz.rjust(10), attr.rjust(3), fname.ljust(16), dta, end = _end);
    else:
        print (f"{_beg}", sz.rjust(10), fname.ljust(16), end = _end)

# PE section stuff
#
def remove_processed_sections(x):
    if x in g_sections: g_sections.remove(x)
def resbyname(x):
  for entry in rt_res_directory.directory.entries:
    nam = str(entry.name)
    if x == nam: # Get the RVA and size of the data
      data_rva = entry.directory.entries[0].data.struct.OffsetToData
      size = entry.directory.entries[0].data.struct.Size
      data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
      return data
  return None

# DEcryptor
#

# original, from c source
def setdw(V, ofs, val):
    x = struct.pack('I', val);    V[ofs + 0] = x[0];    V[ofs + 1] = x[1];    V[ofs + 2] = x[2];    V[ofs + 3] = x[3];
def getdw(V, ofs):
    return ( (V[ofs+3] << 24) |      (V[ofs+2] << 16) |      (V[ofs+1] << 8) |      (V[ofs+0] << 0)     )
def xorfn(key, buf):
  V1 = bytearray(0xFF*4)
  V2 = bytearray(0xFF*4)
  v1p = 0;v12 = 0;v19 = 0
  key = key.encode('ascii')
  while v12 <= 0xFF:
    V1[v1p:] = struct.pack('I', v12)
    v1p += 4
    if v19 > len(key)-1: v19=0
    V2[4*v12:] = struct.pack('I', key[v19])
    v19 += 1
    v12 += 1
  v13 = 0; v12 = 0;
  while v12 <= 0xFF:
    v13 = (getdw(V2, 4 * v12) + getdw(V1, 4 * v12) + v13)&0xff;
    v16 = getdw(V1, 4 * v12)
    setdw(V1, 4 * v12, getdw(V1, 4 * v13) )
    setdw(V1, 4 * v13, v16)
    v12+=1
  v12 = 0;v13 = 0;v20 = 0
  a2 = len(buf)
  while a2 - 1 >= v20:
    v12 = (v12+1)&0xff
    v13 = (getdw(V1,4 * v12) + v13)&0xff
    v16 = getdw(V1,4 * v12);
    setdw(V1,4 * v12, getdw(V1,4 * v13))
    setdw(V1,4 * v13,v16)
    v14 = (getdw(V1,4 * v13) + getdw(V1,4 * v12) )&0xff;
    v17 = getdw(V1,4 * v14)
    buf[v20] = (buf[v20] ^ v17)&0xff
    v20 += 1
    print(chr(13), int(v20 /a2 * 100),  end='    ')
  return buf

# xorfn, optimized by GPT
def xorfn(key, buf, callback=None, cargs=()):
    # Initialize arrays as uint32 (equivalent to original DWORD)
    V1 = array.array('I', [0]) * (0xFF + 1)  # 256 uint32 elements
    V2 = array.array('I', [0]) * (0xFF + 1)
    
    v12 = 0
    v19 = 0
    key_bytes = key.encode('ascii')
    key_len = len(key_bytes)
    
    # Initialization phase (fill V1 and V2)
    while v12 <= 0xFF:
        V1[v12] = v12  # Direct uint32 assignment
        if v19 >= key_len:
            v19 = 0  # Cycle key bytes if needed
        V2[v12] = key_bytes[v19]  # Only LSB matters (upper bytes zeroed)
        v19 += 1
        v12 += 1
    
    # Scrambling phase (RC4-like permutation)
    v13 = 0
    v12 = 0
    while v12 <= 0xFF:
        v13 = (V2[v12] + V1[v12] + v13) & 0xFF  # Mod 256
        # Single-operation swap (no temp variables needed)
        V1[v12], V1[v13] = V1[v13], V1[v12]
        v12 += 1
    
    # XOR phase (main processing)
    buf_array = bytearray(buf)  # Mutable copy
    v12 = 0
    v13 = 0
    
    for v20 in range(len(buf_array)):
        v12 = (v12 + 1) & 0xFF
        v13 = (V1[v12] + v13) & 0xFF
        
        # Swap V1[v12] and V1[v13]
        V1[v12], V1[v13] = V1[v13], V1[v12]
        
        # Calculate XOR byte (using only LSB)
        v14 = (V1[v13] + V1[v12]) & 0xFF
        xor_byte = V1[v14] & 0xFF  # Extract LSB
        
        buf_array[v20] ^= xor_byte

        # Optional progress indicator
        if callback is not None:
            if v20 % 10000 == 0:
                if 'cargs2' not in locals(): cargs2 = list(cargs);
                cargs2[2] = f"{(v20 / len(buf_array)) * 100:.1f}%"
                cargs2[6] = "\r"
                callback(*tuple(cargs2))

    #last print_stat - print size
    if callback is not None:
        callback(*cargs)

    return bytes(buf_array)

# main
#
print('Processing', g_fn, ('to folder ' + g_extract_dir) if g_odir!='' else '')

#load PE
#
pe =  pefile.PE(g_fn, fast_load=True)
pe.parse_data_directories( directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']] )

# parse salt by (search in .data by hardcoded salt[16:-4]) "signature
#
for section in pe.sections:
  if section.Name.decode().strip('\x00') == '.data':
    _ofs = section.get_data().find(salt[16:-4]) - 16
    if _ofs > 0:
        salt = section.get_data()[(_ofs):(_ofs)+144]
        if (g_verbose):print('Salt'.ljust(7), ':', salt.hex()[:16])

if (_ofs < 0):
    print('Error:', ' `salt` signature not found.')
    exit();

# Collect PE  data
#
rt_string_idx = [
  entry.id for entry in 
  pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])

# Get the directory entry
#
rt_res_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

# For each of the entries
#
for entry in rt_res_directory.directory.entries:
  nam = str(entry.name)
  if (len(nam) < 0xB):
    _key = nam
  else:
    _crcb += nam
    g_sections.insert(len(nam),nam) #section to process

# main key
#
K = hashlib.md5(salt[0:4]+salt[4:8]).hexdigest().upper()
if (g_verbose): print('Key     :', K)

# crc check
#
_crcb = _crcb[::-1] #reverse
_sum = dig5(dig5(_crcb))[:10]

if (g_verbose):
    if _key == _sum:
        print('crc OK  :', _key, '/',_sum)
    else:
        print('crc ERR :', _key, '/',_sum)

    print()
    print('digest keys: ')
    print('map     :',  dig5(dig5(K))  ) # 9E427811E6D84EEDB2B2CA37BBB0A5CA -> 5AD1885A4899968C7AACCC23A965DE17
    print('script  :',  dig5(dig5(dig5(K)))  ) 
    print('p1      :',  dig1(K) ) 
    print('p2      :',  dig5(K) ) 
    print()

remove_processed_sections(dig5(K) )
remove_processed_sections(dig1(K) ) 
remove_processed_sections(dig5(dig5(K)) )
remove_processed_sections(dig5(dig5(dig5(K))) )


# script1 (in resource section name = RC_DATA/dig1(K) )
#
data = resbyname(dig1(K))
if data:
    try:
        src = bytearray(data)
        src = xorfn(K, src)
        print_stat(dig1(K), 'p1.bin', str(len(src)), 's', src if g_verbose else '')
        write_to_fn('p1.bin', src, dig1(K))

    except Exception as e: print (dig1(K), '         p1.bin', 'error', e);

# script2
#
data = resbyname(dig5(K))
if data:
    try:
        src = bytearray(data)
        src = xorfn(K, src)
        print_stat(dig5(K), 'p2.bin', str(len(src)),  's', src if g_verbose else '')
        write_to_fn('p2.bin', src)

    except Exception as e: print (dig5(K), '        p2.bin', 'error', e);

# MAP
#
data = resbyname(dig5(dig5(K)))
if data:
    try:
        decompressed_data = zlib.decompress(data)
        print_stat(dig5(dig5(K)), 'map.bin', str(len(decompressed_data)), 's', decompressed_data[:16].hex()+'...' if g_verbose else '')
        write_to_fn('map.bin', decompressed_data)

    except Exception as e:print (dig5(dig5(K)), '        map.bin', 'error', e);

# files list
#
data = resbyname(dig5(dig5(dig5(K))))
if data:
    src = xorfn(K, bytearray(data))
    #print ('script:', src.decode('utf-16'));
    print_stat(dig5(dig5(dig5(K))), 'script.txt', str(len(src)), 's', '')
    write_to_fn('script.txt', src)

    scr = src.decode('utf-16')
    x = 0
    i = 0
    z = 0
    while i < len(scr):
        if (scr[i] == '*'): z += 1
        if (scr[i] == '*') & (z % 2 == 0):
            #print(scr[x:i+1])
            fn = scr[x:i+1].split(':')[0]
            attr = scr[x:i+1].split(':')[1]
            siz = scr[x:i+1].split('*')[1]
            
            # Gen two digest strings, from filename 
            # sha1 and sha1 reversed 
            # 
            resname = dig1(fn)
            resname_rv = dig1(fn)[::-1]

            if (int(attr) & 16 !=0) or int(siz) == 0:
                print_stat('', fn, '0', 'DIR', '')
            else:
                r1 = resname in g_sections
                r2 = resname_rv in g_sections
                if (r1):
                    if (g_odir == ''):
                        print_stat(resname, fn, str(siz), attr, '')
                    else:
                        try:
                            #xor -> save
                            var = resbyname(resname)
                            var = xorfn(K, bytearray(var), 
                                print_stat, cargs=(resname, fn, str(siz), attr, '', "", "\n")
                            )

                            write_to_fn(fn, var)

                        except Exception as e: print('Error with xor decompress ', resname, e)

                    remove_processed_sections(resname)

                elif (r2):
                    if (g_odir == ''):
                        print_stat(resname_rv, fn, str(siz), attr, '')
                    else:
                        try:
                            #xor -> decompress -> save
                            var = resbyname(resname_rv)
                            var = xorfn(K, bytearray(var),
                                print_stat, cargs=(resname_rv, fn, str(siz), attr, '', "", "\n")
                            )
                            var = var[16:]
                            decompressed_data = zlib.decompress(var)
                            write_to_fn(fn, decompressed_data)
                        except Exception as e: print('Error with xor/zlib decompress ', resname_rv, e)

                    remove_processed_sections(resname_rv)

                else:
                    print('nof found                               ', fn,attr,siz)

            x = i+1
        i += 1
else:
    print (dig5(dig5(dig5(K))),'        script.txt')

# unparsed files 
#
if len(g_sections): 
    print ('\nUnknown files:')
    for entry in g_sections:
        print('u ',entry)

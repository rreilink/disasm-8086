import struct
import collections


if __package__:
    from .optable import *
else:
    from optable import *

class Source:
    def __init__(self, data, base_address = 0):
        self._data = data
        self._base_address = base_address
        self._pos = 0
    
    def seek(self, addres):
        '''
        Move the current position to the specified address
        '''
        self._pos = addres-self._base_address
    
    def read(self, n=1):
        '''
        Read n bytes from the source
        
        Raises StopIteration when the source is exhausted
        '''
        
        r = self._data[self._pos:self._pos+n]
        self._pos+=n
        if len(r)<n:
            raise StopIteration(
                f'read of {n} bytes from address '
                f'0x{self._pos+self._base_address:x} is out of range '
                f'of the binary file')
            
        return r
        
    def read_format(self, format):
        '''
        Reads data from source and converts it into a value as specified by
        the format string, which must be a struct format for a single value.
        
        If format is empty, None is returned
        '''
        if format:
            format = '<' + format # Always big-endian (8086)
            return struct.unpack(format, self.read(struct.calcsize(format)))[0]
        else:
            return None
    
    def pos(self):
        '''
        Get the current address
        '''
        return self._pos + self._base_address
    
    def __getitem__(self, slice):
        '''
        Get a slice of the file; the start and stop of the slice specify the 
        start and stop address
        '''
        start, stop, stride = slice.indices(len(self._data)+self._base_address)
        start_idx=start - self._base_address
        stop_idx=stop - self._base_address
        if start_idx<0 or stop_idx>=len(self._data):
            raise IndexError(
                f'access to [0x{start:x}-0x{stop-1:x}] is '
                f'out of range of the binary file')
        return self._data[start_idx:stop_idx]



    
class Disassembler:
    POINTER = {8: 'BYTE PTR', 16: 'WORD PTR', 32: 'DWORD PTR'}

    address_mode = ('bx+si', 'bx+di', 'bp+si', 'bp+di', 'si', 'di', 'bp', 'bx')
    reg8 = ('al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh')
    reg16 = ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di')
    segreg = ('es', 'cs', 'ss', 'ds', '?', '?', '?', '?') # '?' is invalid
    regs = {8: reg8, 16: reg16, 32: reg16, 'seg': segreg}


    def __init__(self, binary=b'', base_address=0, symbols={}):
        self.setdata(binary, base_address)
        self.symbols = symbols

    def setdata(self, binary, base_address):
        self.src = Source(binary, base_address)
        
    @staticmethod
    def signedhex(v):
        'return +0x... for positive v and -0x... for negative v'
        return ('+' if v>=0 else '') + hex(v)

    def conv_address(self, a):
        symbol = self.symbols.get(a)
        return ('0x%08x' % a) + (f' <{symbol}>' if symbol else '')
    
    def parsearg(self, arg, otherarg, pc, mode, displacement, data, segprefix):
        if arg.literal is not None:
            return arg.literal
        if arg.data:
            return hex(data)
    
        m = mode>>6
        rm = mode & 7

        if arg.cls == 'Reg':
            return self.regs[arg.bits][(mode>>3)&7]

        elif arg.cls == 'MemOffs':
            # Pointer type if the other argument is not a register
            r = '' if otherarg.cls=='Reg' else self.POINTER[arg.bits] + ' '
            
            r += f'{segprefix or "ds:"}{hex(displacement)}'
            return r
        elif arg.cls in ['RegMem', 'Mem']:
            if m==3:
                # register; arg.bits determines which set of registers
                return self.regs[arg.bits][rm]        
                
            ptr = self.POINTER[arg.bits]
                
            if (m==0) and (rm == 6):
                segprefix = segprefix or 'ds:'
                address = hex(displacement)
            else:
                dispStr = '' if displacement is None else self.signedhex(displacement)
                address = f'[{self.address_mode[rm]}{dispStr}]'
                
            return f'{ptr} {segprefix}{address}'
        elif arg.displacement:
            return self.conv_address((pc + displacement)&0xffff)


        raise RuntimeError # Should not happen
            
    
    def disassemble_next(self):
        '''
        Disassemble the next instruction in the source
        '''
         
        addr = self.src.pos()
        segprefix = ''
        prefix = ''
        while True:
            op = self.src.read_format('B')
            mnemonic, arg1, arg2, isPrefix = optable[op]
            if not isPrefix:
                break
            if mnemonic.startswith('seg'):
                segprefix = mnemonic[3:]+':'
            else:
                prefix += mnemonic + ' '
    
        if isinstance(arg1, str):
            arg1 = ArgType(arg1, False, 0, 0, False)
        if isinstance(arg2, str):
            arg2 = ArgType(arg2, False, 0, 0, False)
            
        # Determine the displacement size (none or 8 or 16 bits)
        displacement = ''
        mode = 0
        if arg1.hasAddrModeByte or arg2.hasAddrModeByte:
            mode = self.src.read_format('B')
            if mode>>6 == 1:
                displacement = 'b' # 8-bit displacement
            elif (mode>>6 == 2) or ((mode>>6==0) and (mode & 7) ==6):
                displacement = 'h' # 16-bit displacement
        else:
            displacement = arg1.displacement or arg2.displacement # At most one argument has a displacement
        

        # Read the data (none or 8, 16 or 32 bits, signed or unsigned)
        data = arg1.data or arg2.data # At most one argument has data
        
        # Special cases
        if ((mode>>3) & 7) == 0:
            if op == 0xf6:      # test mem/reg8
                data = 'B'
                arg2 = argImm8
            elif op == 0xf7:    # test mem/reg16
                data = 'H'
                arg2 = argImm16
        
        if op == 0xff and ((mode>>3) & 7) in (3, 5): #jmp/call DWORD PTR
            arg1 = argMem32

        # Determine the mnemonic, some op-codes cover multiple mnemomic based on
        # the mode byte
        if isinstance(mnemonic, tuple):
            mnemonic = mnemonic[(mode>>3) & 7]
        
        if not mnemonic: # Invalid instruction
            return addr, self.src[addr:self.src.pos()], '', '', ''
    
        # Read the displacement and the data
        displacement = self.src.read_format(displacement)
        data = self.src.read_format(data)
    
        pc = self.src.pos()
        arg1str = self.parsearg(arg1, arg2, pc, mode, displacement, data, segprefix)
        arg2str = self.parsearg(arg2, arg1, pc, mode, displacement, data, segprefix)
        
        args = arg1str + ((',' + arg2str) if arg2str else '')
        
        # Expand lodsb/lodsw/stosb/stosw to explicit forms
        mnemonic, args = {
            ('lodsb', ''): ('lods', 'al,BYTE PTR ds:[si]'),
            ('lodsw', ''): ('lods', 'ax,WORD PTR ds:[si]'),
            ('stosb', ''): ('stos', 'BYTE PTR es:[di],al'),
            ('stosw', ''): ('stos', 'WORD PTR es:[di],ax'),
    
            }.get((mnemonic, args), (mnemonic, args))
    
        
        return addr, self.src[addr:pc], prefix, mnemonic, args
    
    def formatline(self, address, data, prefix, mnemonic, arguments):
        '''
        Format the output of disassemble_next
        Override to customize the output
        '''
        dataStr = ' '.join('%02x' % d for d in data)
            
        return f'{address:08x} {dataStr:26s} {(prefix + mnemonic):6s} {arguments}'.rstrip()
    
    def disassemble(self, start_address):
        '''
        
        '''
        self.src.seek(start_address)
        while True:
            instr = self.disassemble_next()
            yield self.formatline(*instr)

if __name__=='__main__':
    import argparse, sys
    def address(v):
        if v.startswith('0x'):
            v = int(v[2:], 16)
        else:
            v = int(v)
        if v<0:
            raise ValueError
        return v
            
    def range(v):
        start, _, end = v.partition(':')
        
        return address(start), address(end) if end else None
        
    parser = argparse.ArgumentParser(
        description='Disassemble 8086 instruction code',
        epilog='All addresses can be specified as decimal or, when starting with 0x, as hexadecimal (e.g. 0x1000)')

    parser.add_argument('-b', '--base', nargs=1, default='0', type=address, help='The base address of the binary file')
    parser.add_argument('-o', '--out', nargs='?', type=argparse.FileType('w'), help='The output file to be written')
    parser.add_argument('-r', '--range', nargs='*', type=range, help='Range of addresses to be disassembled, in the format start[:end] (end is included)')
    parser.add_argument('binfile', type=argparse.FileType('rb'), help='The binary file to be processed')
    result=parser.parse_args()
    
    # Read the binary file
    data = result.binfile.read()
    result.binfile.close()
    
    # Calculate the indices in the file for each of the specified ranges
    range_idxs = []
    base = result.base[0]
    
    for start, end in result.range or [(base, None)]:
        start_idx = start - base
        end_idx = len(data) if end is None else end - base + 1
        if start_idx<0 or end_idx>len(data):
            
            parser.error(f"Invalid range: {start}:{'' if end is None else end} ({hex(start)}:{'' if end is None else hex(end)}) is outside the binary file")
        range_idxs.append((start_idx,end_idx))

    outfile = result.out or sys.stdout



    
    disassembler = Disassembler()
    for start, end in range_idxs:
        disassembler.setdata(data[start:end], base+start)
        for line in disassembler.disassemble(base+start):
            outfile.write(line+'\n')


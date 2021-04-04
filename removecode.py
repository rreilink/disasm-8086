'''
This script removes all (possibly proprietary) code from the disassembled file,
but leaves the remarks and symbols
'''
import re
import argparse
import struct
from zlib import crc32
from disassembler import Disassembler


   
  


REMOVE, RESTORE = 1, 2             # pass1 modes
COPY, INSTRUCTION, DW = 1, 2, 3    # line types

class ProcessError(Exception):
    pass


class Processor:
    # There are some mnemonics which do the same, generate the same machine code,
    # but are referred to with different names (e.g. je == jc ).
    #
    # If any of the mnemonics is found which is not the one which disasm8086 outputs,
    # a numeric value is stored into the cleaned file, which allows restoring the
    # original instruction later.
    #
    # key = the instruction as generated, value = list of alternative names for the same
    EQUIVALENT_INSTRUCTIONS = {
        'jz': ['je'],
        'jb': ['jc', 'jnae'],
        'jnz': ['jne'], 
        'jae': ['jnc', 'jnb'],
        'jpe': ['jp'],
        'jpo': ['jnp'],
        'loopz':['loope'],
        'loopnz':['loopne']
        }
        
    def __init__(self, binary, base_address):
        self.disasm = Disassembler(binary, base_address, {})
        
    def parselabel(self, line):
        m = re.match(r'^([A-Za-z0-9_][A-Za-z0-9_\?]*):', line)
        return m and m.group(1)
        
    def parseequ(self, line):
        m = re.match(r'^=\s+(0x[0-9a-f]+)\s+([A-Za-z0-9_][A-Za-z0-9_\?]*)$', line)
        return m and m.groups()
    
    def pass1(self, lines, mode):
        '''
        Go over all input lines, and
        - split them into the code part and the comment part
        - determine the code type:
            COPY = literal copy to output
            DW = .dw
            INSTRUCTION = instruction)
        - build symbols dictionary of {address:name}
        
        This part is the same for both removing and restoring, except that
        in case of removing, the address labels are used to determine the address
        and in case of restoring, the disassembly address counter is used
        '''
        outlines = []
        startaddress = None
        label = None
        symbols = {}
        output = []
        for total_line in lines:
            code,_ , comment = total_line.partition(';')
            code = code.rstrip()
            found_equ = self.parseequ(code)
            found_label = self.parselabel(code)
            if found_label:
                label = found_label
            
            linetype = COPY
            
            if found_equ:
                symbols[int(found_equ[0], 16)] = found_equ[1]
                
            if code and not found_equ and not found_label:
                if mode==REMOVE or startaddress is None:
                    address = re.match('([0-9a-f]{8})( |$)', code)
                    if not address:
                        raise ProcessError(f'\nCould not parse address from line: {code}')
    
                    address = int(address.group(1), 16)
                    if startaddress is None:
                        startaddress = address
                        self.disasm.src.seek(address)
                
                is_dw = code[36:39] == '.dw'
                
                if mode==RESTORE:
                    # TODO: also keep track of this while removing? to make sure adresses match
                    # When restoring, the current address is not derived from the
                    # input lines, but by disassembling the binary
                    if is_dw:
                        address = self.disasm.src.pos()
                        self.disasm.src.read(2)
                    else:
                        address, data, prefix, mnemonic, arguments = self.disasm.disassemble_next()                
                
                
                if label:
                    symbols[address] = label
                    label = None
                
                linetype = DW if is_dw else INSTRUCTION
                
            output.append((linetype, code, comment, total_line))
        
        self.disasm.symbols = symbols.copy()
        self.disasm.src.seek(startaddress)
        
        return output
        
    def restore(self, lines):
        result = []
        checkline = lines[0]
        try:
            assert checkline.startswith('check: ')
            start, end, check=map(lambda x:int(x,16), checkline[8:].split())
        except:
            raise ProcessError(f'Could not parse checkline {checkline!r}')
        
        if crc32(self.disasm.src[start:end+1]) != check:
            raise ProcessError(f'Checksum from 0x{start:08x}-0x{end:08x} does not match')
        
        
        for typ, code, comment, total_line in self.pass1(lines[1:], RESTORE):
            if typ == COPY:
                result.append(total_line)
                continue
                
            if typ == DW:
                address, data, prefix, mnemonic, arguments = self.dw_next()
            else: # instruction
                address, data, prefix, mnemonic, arguments = self.disasm.disassemble_next()
                eq_idx = code[36:39].strip()
                if eq_idx:
                    mnemonic = self.EQUIVALENT_INSTRUCTIONS[mnemonic][int(eq_idx)-1]
                
            line = self.disasm.formatline(address, data, prefix, mnemonic, arguments)
                
            line = line + total_line[len(line):]
            result.append(line)
        
        return result
    
    def dw_next(self):
        'Parse the next two bytes from self.disasm as a .dw data line'
        address = self.disasm.src.pos()
        data = self.disasm.src.read(2)
        value = struct.unpack('<H', data)[0]
        mnemonic = '.dw'
        symbol = self.disasm.symbols.get(value)
        arguments = f'0x{value:04x}'+ (f' <{symbol}>' if symbol else '')

        return address, data, '', '.dw', arguments
        
    def remove(self, lines):
        result = []
        first = True
        pass1_result = self.pass1(lines, REMOVE)
        start = self.disasm.src.pos()
        for typ, code, comment, total_line in pass1_result:
            if typ == COPY:
                result.append(total_line)
                continue
                
            if typ == DW:
                address, data, prefix, mnemonic, arguments = self.dw_next()
            else:
                address, data, prefix, mnemonic, arguments = self.disasm.disassemble_next()

            d = self.disasm.formatline(address, data, prefix, mnemonic, arguments)
            
            if typ == INSTRUCTION:
                equivalents = self.EQUIVALENT_INSTRUCTIONS.get(mnemonic, [])
                mnemonic = ''
                if d!=code: # Try equivalent instructions
                    for eq_idx, eq in enumerate(equivalents, 1):
                        d_equiv = self.disasm.formatline(address, data, prefix, eq, arguments)
                        if d_equiv == code:
                            d = d_equiv
                            mnemonic = str(eq_idx)
                            break

            if d!=code:
                raise ProcessError(
                    f'The following line could not be recreated:\n'
                    f'Original: {code!r}\nRecreated:{d!r}')

            r = ('%08x' % address if first else '*')
            if mnemonic:
                r = r.ljust(36) + mnemonic
            
            result.append(r+(' ' * (len(d)-len(r))) + total_line[len(d):])
            
            first = False
        end = self.disasm.src.pos()
        check = crc32(self.disasm.src[start:end])
        checkline = f'check: {start:08x} {end-1:08x} {check:08x}\n'
        return [checkline] + result


if __name__=='__main__':
    import sys
    import argparse
    
    def address(v):
        if v.startswith('0x'):
            v = int(v[2:], 16)
        else:
            v = int(v)
        if v<0:
            raise ValueError
        return v
        
    parser = argparse.ArgumentParser(
        description='Remove code from 8086 instruction listings, keeping comments and labels',
        epilog='All addresses can be specified as decimal or, when starting with 0x, as hexadecimal (e.g. 0x1000)')

    parser.add_argument('mode', choices=['remove', 'restore'])
    parser.add_argument('-b', '--base', nargs=1, default='0', type=address, help='The base address of the binary file')
    parser.add_argument('binary', type=argparse.FileType('rb'), help='The binary file to be processed')
    parser.add_argument('input', nargs='?', type=argparse.FileType('r'), help='The instruction listing to be processed')
    parser.add_argument('output', nargs='?', type=argparse.FileType('w'), help='File to write the output to')
    result = parser.parse_args()
    
    base = result.base[0]
    binary = result.binary.read()
    input = (result.input or sys.stdin).read()
    input_lines = input.splitlines(keepends=True)
    
    try:
        if result.mode=='remove':
            phase = 'remove'
            p = Processor(binary, base)
            output = ''.join(p.remove(input_lines))
            
            phase = 'verify'
            # Create new processor to make sure no state is latently kept
            p = Processor(binary, base)
            verify_lines = p.restore(output.splitlines(keepends=True))
            verify = ''.join(verify_lines)
            if verify != input:
            
                for i, v in zip(input_lines, verify_lines):
                    if i!=v:
                        raise ProcessError(f'Verify failed:\nOriginal:{i!r}\nRestored:{v!r}')
                
                #Either one is longer, should not happen
                assert False # if verify!=input, at least one line should be different

        else:
            phase = 'restore'
            p = Processor(binary, base)
            output = ''.join(p.restore(input_lines))
        
        (result.output or sys.stdout).write(output)
        
        
    except Exception as e:
        errstr = str(e) or repr(e)
        parser.error(f'\nThe following error occurred during the {phase} phase:\n{errstr}')
        

    

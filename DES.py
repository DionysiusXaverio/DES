# Author Name: Dionysius Xaverio

from BitVector import *
import sys
import string

class DES():

    # generate 48-bit permutation result using Expansion permutation:
    expansion_permutation = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9,
                            10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17,
                            18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25,
                            26, 27, 28, 27, 28, 29, 30, 31, 0]

    # key permutations:
    key_permutation_1 = [56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
                        9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
                        62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
                        13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3]

    key_permutation_2 = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11,
                        3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46,
                        54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52,
                        45, 41, 49, 35, 28, 31]

    shifts_for_round_key_gen = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # S-boxes:
    s_boxes = {i: None for i in range(8)}

    s_boxes[0] = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]

    s_boxes[1] = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]

    s_boxes[2] = [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]

    s_boxes[3] = [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]

    s_boxes[4] = [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]

    s_boxes[5] = [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]]

    s_boxes[6] = [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]]

    s_boxes[7] = [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]

    # P-box permutation
    p_box_permutation = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]

    def get_encryption_key(self, key_string):
        key = BitVector(textstring=key_string)
        key = key.permute(self.key_permutation_1)
        return key

    def generate_round_keys(self, encryption_key):
        round_keys = []
        key = encryption_key.deep_copy()
        for round_count in range(16):
            [LeftKey, RightKey] = key.divide_into_two()
            shift = self.shifts_for_round_key_gen[round_count]
            LeftKey << shift
            RightKey << shift
            key = LeftKey + RightKey
            round_key = key.permute(self.key_permutation_2)
            round_keys.append(round_key)
        return round_keys
    
    def substitute(self, expand_half_block):
        output = BitVector(size=32)
        segment = [expand_half_block[x * 6:x * 6 + 6] for x in range(8)]
        for index in range(len(segment)):
            row = 2 * segment[index][0] + segment[index][-1]
            column = int(segment[index][1:-1])
            output[index * 4:index * 4 + 4] = BitVector(intVal=self.s_boxes[index][row][column], size=4)
        return output

    def __init__ ( self , key ):
        with open(key) as key_file:
            key_text = key_file.read()

        encryption_key = self.get_encryption_key(key_text) # generate 56-bit encryption key
        self.round_keys = self.generate_round_keys(encryption_key) # generate round keys 

    # Inputs : message_file (str), outfile (str)
    # Return : void
    def encrypt ( self , message_file , outfile ):
        # encrypts the contents of the message file and writes the ciphertext to the outfile
        bv = BitVector(filename=message_file) 
        output_file = open(outfile, 'w')
        while bv.more_to_read:
            bitvec = bv.read_bits_from_file(64) # process 8 bytes
            if bitvec.length() % 64 != 0:
                bitvec.pad_from_right(64 - bitvec.length() % 64)
            [LE, RE] = bitvec.divide_into_two()
            if bitvec.length() > 0:
                for round_key in self.round_keys:  
                    newLE = RE.deep_copy()  
                    RE = RE.permute(self.expansion_permutation) # permute 32 bits to 48 bits  
                    out_xor = RE ^ round_key # XOR with round key
                    s_output = self.substitute(out_xor) # substitute with S boxes
                    p_output = s_output.permute(self.p_box_permutation)  # permute with P box permutation
                    RE = LE ^ p_output                              
                    LE = newLE                                      
            bitvec = RE + LE                                        
            output_file.write(bitvec.get_bitvector_in_hex())
        output_file.close()


    # Inputs : encrypted_file (str), outfile (str)
    # Return : void
    def decrypt ( self , encrypted_file , outfile ):
        # decrypts contents of encrypted_file and writes the recovered plaintext to the outfile
        with open(encrypted_file, 'r') as file:
            bv = BitVector(hexstring = file.read())
        output_file = open(outfile, 'w')
        num_iter = round(bv.length()/64)
        for x in range(num_iter):
            bitvec = bv[(x*64):(x*64)+64]
            [LE, RE] = bitvec.divide_into_two()
            if bitvec.length() > 0:
                for round_key in self.round_keys[::-1]: # reverse the direction of round keys
                    newLE = RE.deep_copy()  
                    RE = RE.permute(self.expansion_permutation)          
                    out_xor = RE ^ round_key                        
                    s_output = self.substitute(out_xor)                  
                    p_output = s_output.permute(self.p_box_permutation)  
                    RE = LE ^ p_output                              
                    LE = newLE                                      
            bitvec = RE + LE                                        
            output_file.write(bitvec.get_bitvector_in_ascii())
        output_file.close()

    def encrypt_img( self , input_file , outfile ):
        with open(input_file, 'rb') as file1:
            # read the first three lines of the PPM header
            header_length = file1.readline()
            header_length2 = file1.readline()
            header_length3 = file1.readline()
        bv = BitVector(filename=input_file)
        output_file = open(outfile, 'wb')
        # write the header to the first three lines of the output file
        output_file.write(header_length)
        output_file.write(header_length2)
        output_file.write(header_length3)
        while bv.more_to_read:
            bitvec = bv.read_bits_from_file(64)
            if bitvec.length() % 64 != 0:
                bitvec.pad_from_right(64 - bitvec.length() % 64)
            [LE, RE] = bitvec.divide_into_two()
            if bitvec.length() > 0:
                for round_key in self.round_keys:
                    newLE = RE.deep_copy()
                    RE = RE.permute(self.expansion_permutation)
                    out_xor = RE ^ round_key
                    s_output = self.substitute(out_xor)
                    p_output = s_output.permute(self.p_box_permutation)
                    RE = LE ^ p_output
                    LE = newLE
            bitvec = RE + LE 
            bitvec.write_to_file(output_file)
        output_file.close()

if __name__ == '__main__':

    option = sys.argv[1]
    input_file = sys.argv[2]
    key_file = sys.argv[3]
    outfile = sys.argv[4]

    cipher = DES(key=key_file)
    if option == '-e':
        cipher.encrypt(input_file, outfile)
    elif option == '-d':
        cipher.decrypt(input_file, outfile)
    elif option == '-i':
        cipher.encrypt_img(input_file, outfile)

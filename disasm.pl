#!/usr/bin/perl
use strict;

# Huge table of known opcodes
my %opcodes_alt = (
	"81" => [ "expansion" ],
	"83" => [ "expansion" ],
	"ff" => [ "expansion" ],
	"f7" => [ "expansion" ],
	"d1" => [ "expansion" ],
	"0f" => [ "start_byte" ],
	"05" => [ "add", ["eax","imm32"] ], # ADD EAX, imm32
	"01" => [ "add", ["r/m","reg"] ], # 01 /r - ADD r/m32, r32
	"03" => [ "add", ["reg","r/m"] ], # 03 /r - ADD r32, r/m32
	"25" => [ "and", ["eax","imm32"] ], # 25 ld - AND EAX, imm32
	"21" => [ "and", ["r/m","reg"] ], # 21 /r - AND r/m32, r32
	"23" => [ "and", ["reg","r/m"] ], # 23 /r - AND r32, r/m32
	"e8" => [ "call", ["rel32"] ], # e8 cd - CALL rel32
	"3d" => [ "cmp", ["eax","imm32"] ], # 3d lw - CMP EAX, imm32
	"39" => [ "cmp", ["r/m","reg"] ], # 39 /r - CMP r/m32, r32
	"3b" => [ "cmp", ["reg","r/m"] ], # 3b /r - CMP r32, r/m32
	#"48" => [ "dec", "O" ], # 48+rd - DEC r32
	"6b" => [ "imul", ["reg","r/m","imm8"] ], # 6b /r lb - IMUL r32, r/m32, imm8
	"69" => [ "imul", ["reg","r/m","imm32"] ], # 69 /r ld - IMUL r32, r/m32, imm32
	"e9" => [ "jmp", ["rel32"] ], 
	"8d" => [ "lea", ["reg","r/m"] ],
	"89" => [ "mov", ["r/m","reg"] ], # 89 /r - MOV r/m32,r32
	"8b" => [ "mov", ["reg","r/m"] ], # 8b /r - MOV r32,r/m32
	"a1" => [ "mov", ["eax","moffs32"] ], # a1 - MOV eax, moffs32
	"a3" => [ "mov", ["moffs32","eax"] ], # a3 - MOV moffs32, eax
	"b8" => [ "mov", ["eax","imm32"] ], # b8 - MOV EAX, IMM32 (?)
	"b9" => [ "mov", ["ecx","imm32"] ], # b9 - MOV ECX, IMM32(?)
	"bb" => [ "mov", ["ebx","imm32"] ], # bb - MOV EBX, IMM32(?)
	"c7" => [ "mov", ["r/m","imm32"] ], # c7 /0 - MOV r/m32, imm32
	"90" => [ "nop", [] ],
	"0d" => [ "or", ["eax","imm32"] ],
	"09" => [ "or", ["r/m","reg"] ], # 09 /r
	"0b" => [ "or", ["reg","r/m"] ],
	"8f" => [ "pop", ["r/m"] ],
	#"f3 0f b8" => [ "popcnt", "RM" ], # f3 0f b8 /r
	"c3" => [ "retn", [] ], # c3 - RET near
	"cb" => [ "retf", [] ], # cb - RET far
	"c2" => [ "retn", ["imm16"] ], # c2 - RETN imm16
	"ca" => [ "retf", ["imm16"] ], # ca - RETF imm16
	"1d" => [ "sbb", ["imm32"] ], # 1d -> SBB EAX, imm32
	"19" => [ "sbb", ["r/m","reg"] ], # 19 /r - SBB r/m32, r32
	"1b" => [ "sbb", ["reg","r/m"] ], # 1b /r - SBB r32, r/m32
	"a9" => [ "test", ["imm32"] ], # a9 - TEST EAX, imm32
	"85" => [ "test", ["r/m","reg"] ], # 85 /r - TEST r/m32, r32
	"35" => [ "xor", ["imm32"] ], # 35 - XOR EAX, imm32
	"31" => [ "xor", ["r/m","reg"] ], # 31 /r - XOR r/m32, r32
	"33" => [ "xor", ["reg","r/m"] ], # 33 /r - XOR r32, r/m32
	"75" => [ "jnz", ["rel8"]],
	"74" => [ "jz", ["rel8"]],
	"eb" => [ "jmp", ["rel8"]],
	"e9" => [ "jmp", ["rel32"]],
	"ea" => [ "jmp", ["ptr16:32"]],
	
);

# Extended opcodes
my %start_bytes = (
	"0f" => { "c8" => [ "bswap", ["reg"] ], # 0f c8 + rd - BSWAP r32
			  "1f" => [ "nop", "M" ], # 0f 1f /0
			  "af" => [ "imul", ["reg","r/m"] ], # 0f af /r - IMUL r32, r/m32
			  "84" => [ "jz", ["rel32"]],
			  "85" => [ "jnz", ["rel32"]],
			  "be" => [ "movsx", ["reg","r/m"]],
			  "bf" => [ "movsx", ["reg","r/m"]],
			  "b6" => [ "movzx", ["reg","r/m"]],
			  "b7" => [ "movzx", ["reg","r/m"]]
	},
	"f2" => { "a7" => [ "repne cmps", "NP" ], # f2 a7 - REPNE CMPS m32, m32
			} 
	
);

# More extended opcodes
my %expansions = (
	"81" => { "110" => [ "xor", ["r/m","imm32"] ], # 81 /6 - XOR r/m32, imm32
			  "011" => [ "sbb", ["r/m","imm32"] ], # 81 /3 - SBB r/m32, imm32
			  "001" => [ "or", ["r/m","imm32"] ],  # 81 /1 ld
			  "111" => [ "cmp", ["r/m","imm32"] ], # 81 /7 ld - CMP r/m32, imm32
			  "100" => [ "and", ["r/m","imm32"] ], # 81 /4 ld - AND r/m32, imm32
			  "000" => [ "add", ["r/m","imm32"] ], # 81 /0 - ADD r/m32, imm32
			},
	"83" => { "110" => [ "xor", ["r/m","imm8"] ], # 83 /6 - XOR r/m32, imm8
			  "011" => [ "sbb", ["r/m","imm8"] ], # 83 /3 - SBB r/m32, imm8
			  "001" => [ "or", ['r/m","imm8'] ],  # 83 /1 lb
			  "100" => [ "and", ["r/m","imm8"] ], # 83 /4 lb - AND r/m32, imm8 -- ex.: 83 
			  "000" => [ "add", ["r/m","imm8"] ], # 83 /0 - ADD r/m32, imm8 -- ex.: 83 c1 ed -> c1 = 11000001 = /0 ecx
			  "111" => [ "cmp", ["r/m","imm8"] ], # 83 /7 lb - CMP r/m32, imm8
        	},
	"f7" => { "000" => [ "test", ["r/m","imm32"] ], # f7 /0 - TEST r/m32, imm32
			  "010" => [ "not", "M" ], # f7 /2
			  "100" => [ "mul", "M" ], # f7 /4
			  "011" => [ "neg", "M" ], # f7 /3
			  "101" => [ "imul", ["r/m"] ], # f7 /5 - IMUL r/m32
			  "111" => [ "idiv", ["r/m"] ], # f7 /7 - IDIV r/m32
			},
	"ff" => { "010" => [ "call", ["r/m"] ], # ff /2 - CALL r/m32
			  "001" => [ "dec", ["r/m"] ], # ff /1 - DEC r/m32
			  "000" => [ "inc", ["r/m"] ], # ff /0 - INC r/m32
			  "110" => [ "push", ["r/m"] ], # ff /6 - PUSH r/m32
			  "100" => [ "jmp", ["r/m"] ], # ff /4 jmp r/m32
			  "101" => [ "jmp", ["m16:32"] ], # ff /5 jmp m16:32
			},
	"d1" => { "100" => [ "shl", ["r/m","1"] ],
			  "111" => [ "sar", ["r/m","1"] ],
			  "101" => [ "shr", ["r/m","1"] ]
		    },
);

# Information for the modr/m bit
my %mods = (
	"00" => "[reg]",
	"01" => "[reg+byte]",
	"10" => "[reg+dword]",
	"11" => "reg"
);

# Register lookup
my %regs = (
	"000" => "eax",
	"001" => "ecx",
	"010" => "edx",
	"011" => "ebx",
	"100" => "esp",
	"101" => "ebp",
	"110" => "esi",
	"111" => "edi"
);

# Lookup in the modr/m table
my %bit_addr;

# mod 00
$bit_addr{ $_ } = "[eax]"  for qw(00 08 10 18 20 28 30 38);
$bit_addr{ $_ } = "[ecx]"  for qw(01 09 11 19 21 29 31 39);
$bit_addr{ $_ } = "[edx]"  for qw(02 0a 12 1a 22 2a 32 3a);
$bit_addr{ $_ } = "[ebx]"  for qw(03 0b 13 1b 23 2b 33 3b);
$bit_addr{ $_ } = "sib"    for qw(04 0c 14 1c 24 2c 34 3c);
$bit_addr{ $_ } = "disp32" for qw(05 0d 15 1d 25 2d 35 3d);
$bit_addr{ $_ } = "[esi]"  for qw(06 0e 16 1e 26 2e 36 3e);
$bit_addr{ $_ } = "[edi]"  for qw(07 0f 17 1f 27 2f 37 3f);

# mod 01
$bit_addr{ $_ } = "[eax+disp8]"  for qw(40 48 50 58 60 68 70 78);
$bit_addr{ $_ } = "[ecx+disp8]"  for qw(41 49 51 59 61 69 71 79);
$bit_addr{ $_ } = "[edx+disp8]"  for qw(42 4a 52 5a 62 6a 72 7a);
$bit_addr{ $_ } = "[ebx+disp8]"  for qw(43 4b 53 5b 63 6b 73 7b);
$bit_addr{ $_ } = "sib+disp8"    for qw(44 4c 54 5c 64 6c 74 7c);
$bit_addr{ $_ } = "[ebp+disp8]"  for qw(45 4d 55 5d 65 6d 75 7d);
$bit_addr{ $_ } = "[esi+disp8]"  for qw(46 4e 56 5e 66 6e 76 7e);
$bit_addr{ $_ } = "[edi+disp8]"  for qw(47 4f 57 5f 67 6f 77 7f);

# mod 10
$bit_addr{ $_ } = "[eax+disp32]"  for qw(80 88 90 98 a0 a8 b0 b8);
$bit_addr{ $_ } = "[ecx+disp32]"  for qw(81 89 91 99 a1 a9 b1 b9);
$bit_addr{ $_ } = "[edx+disp32]"  for qw(82 8a 92 9a a2 aa b2 ba);
$bit_addr{ $_ } = "[ebx+disp32]"  for qw(83 8b 93 9b a3 ab b3 bb);
$bit_addr{ $_ } = "sib+disp32"    for qw(84 8c 94 9c a4 ac b4 bc);
$bit_addr{ $_ } = "[ebp+disp32]"  for qw(85 8d 95 9d a5 ad b5 bd);
$bit_addr{ $_ } = "[esi+disp32]"  for qw(86 8e 96 9e a6 ae b6 be);
$bit_addr{ $_ } = "[edi+disp32]"  for qw(87 8f 97 9f a7 af b7 bf);

# mod 11
$bit_addr{ $_ } = "eax"  for qw(c0 c8 d0 d8 e0 e8 f0 f8);
$bit_addr{ $_ } = "ecx"  for qw(c1 c9 d1 d9 e1 e9 f1 f9);
$bit_addr{ $_ } = "edx"  for qw(c2 ca d2 da e2 ea f2 fa);
$bit_addr{ $_ } = "ebx"  for qw(c3 cb d3 db e3 eb f3 fb);
$bit_addr{ $_ } = "esp"  for qw(c4 cc d4 dc e4 ec f4 fc);
$bit_addr{ $_ } = "ebp"  for qw(c5 cd d5 dd e5 ed f5 fd);
$bit_addr{ $_ } = "esi"  for qw(c6 ce d6 de e6 ee f6 fe);
$bit_addr{ $_ } = "edi"  for qw(c7 cf d7 df e7 ef f7 ff);

# SIB byte lookup table
my %sib_addr;

# mod 00
$sib_addr{ $_ } = "[eax]"  for qw(00 08 10 18 20 28 30 38);
$sib_addr{ $_ } = "[ecx]"  for qw(01 09 11 19 21 29 31 39);
$sib_addr{ $_ } = "[edx]"  for qw(02 0a 12 1a 22 2a 32 3a);
$sib_addr{ $_ } = "[ebx]"  for qw(03 0b 13 1b 23 2b 33 3b);
$sib_addr{ $_ } = "none"   for qw(04 0c 14 1c 24 2c 34 3c);
$sib_addr{ $_ } = "[ebp]"  for qw(05 0d 15 1d 25 2d 35 3d);
$sib_addr{ $_ } = "[esi]"  for qw(06 0e 16 1e 26 2e 36 3e);
$sib_addr{ $_ } = "[edi]"  for qw(07 0f 17 1f 27 2f 37 3f);

# mod 01
$sib_addr{ $_ } = "[eax*2]"  for qw(40 48 50 58 60 68 70 78);
$sib_addr{ $_ } = "[ecx*2]"  for qw(41 49 51 59 61 69 71 79);
$sib_addr{ $_ } = "[edx*2]"  for qw(42 4a 52 5a 62 6a 72 7a);
$sib_addr{ $_ } = "[ebx*2]"  for qw(43 4b 53 5b 63 6b 73 7b);
$sib_addr{ $_ } = "none"     for qw(44 4c 54 5c 64 6c 74 7c);
$sib_addr{ $_ } = "[ebp*2]"  for qw(45 4d 55 5d 65 6d 75 7d);
$sib_addr{ $_ } = "[esi*2]"  for qw(46 4e 56 5e 66 6e 76 7e);
$sib_addr{ $_ } = "[edi*2]"  for qw(47 4f 57 5f 67 6f 77 7f);

# mod 10
$sib_addr{ $_ } = "[eax*4]"  for qw(80 88 90 98 a0 a8 b0 b8);
$sib_addr{ $_ } = "[ecx*4]"  for qw(81 89 91 99 a1 a9 b1 b9);
$sib_addr{ $_ } = "[edx*4]"  for qw(82 8a 92 9a a2 aa b2 ba);
$sib_addr{ $_ } = "[ebx*4]"  for qw(83 8b 93 9b a3 ab b3 bb);
$sib_addr{ $_ } = "none"     for qw(84 8c 94 9c a4 ac b4 bc);
$sib_addr{ $_ } = "[ebp*4]"  for qw(85 8d 95 9d a5 ad b5 bd);
$sib_addr{ $_ } = "[esi*4]"  for qw(86 8e 96 9e a6 ae b6 be);
$sib_addr{ $_ } = "[edi*4]"  for qw(87 8f 97 9f a7 af b7 bf);

# mod 11
$sib_addr{ $_ } = "[eax*8]"  for qw(c0 c8 d0 d8 e0 e8 f0 f8);
$sib_addr{ $_ } = "[ecx*8]"  for qw(c1 c9 d1 d9 e1 e9 f1 f9);
$sib_addr{ $_ } = "[edx*8]"  for qw(c2 ca d2 da e2 ea f2 fa);
$sib_addr{ $_ } = "[ebx*8]"  for qw(c3 cb d3 db e3 eb f3 fb);
$sib_addr{ $_ } = "none"     for qw(c4 cc d4 dc e4 ec f4 fc);
$sib_addr{ $_ } = "[ebp*8]"  for qw(c5 cd d5 dd e5 ed f5 fd);
$sib_addr{ $_ } = "[esi*8]"  for qw(c6 ce d6 de e6 ee f6 fe);
$sib_addr{ $_ } = "[edi*8]"  for qw(c7 cf d7 df e7 ef f7 ff);

# Exit if the file is bad
my $infile = $ARGV[0];
die "Invalid input file" unless $infile;

# Read the file in as binary
my $binary = read_file( $infile );
my $len = length( $binary );

# Initialize the current bite
my $current_byte = 0;

# Iterate through the file
my $print_line = "";
my @labels;
while( length( $binary ) > 0 ) {
	# Grab a byte
	my $byte = substr( $binary, 0, 2, "" );
	
	# Look up the instruction
	my $instruction = $opcodes_alt{ $byte }[0];
	my $instr_bytes;
	# Determine the instruction arguments
	my $op_args = $opcodes_alt{ $byte }[1];
	my $target_address;	
	
	# If the instruction can't be found..
	if( $instruction eq "" ) {
		# Check if it's a push instruction, 50+rd
		if( hex( $byte ) >= hex(50) && hex( $byte ) < hex(58) ) {
			# If so, indicate the push operation
			$instruction = "push";
			# Determine the target register
			my $target = substr( unpack( "B*", (hex( $byte ) - hex(50)) ), 5, 3 );
			my $args = $regs{ $target };
			$instruction .= " " . $args;
			$op_args = undef;
		} # Check if it's a pop instruction, 58+rd
		elsif( hex( $byte ) >= hex(58) && hex( $byte ) < hex(60) ) {
			$instruction = "pop";
			my $target = substr( unpack( "B*", (hex( $byte ) - hex(58)) ), 5, 3 );
			my $args = $regs{ $target };
			$instruction .= " " . $args;
			$op_args = undef;
		} # Check if it's an inc instruction, 40+rd
		elsif( hex( $byte ) >= hex(40) && hex( $byte ) < hex(48) ) {
			$instruction = "inc";
			my $target = 	substr( unpack( "B*", (hex( $byte ) - hex(40)) ), 5, 3 );
			my $args = $regs{ $target };
			$instruction .= " " . $args;
			$op_args = undef;
		} # Check if it's an dec instruction, 48+rd
		elsif( hex( $byte ) >= hex(48) && hex( $byte ) < hex(50) ) {
			$instruction = "dec";
			my $target = 	substr( unpack( "B*", (hex( $byte ) - hex(48)) ), 5, 3 );
			my $args = $regs{ $target };
			$instruction .= " " . $args;
			$op_args = undef;
		}
		else {
			# Skip the 00 bytes
			if( $byte == "00" ) {
				# Skip it
				next;
			}
			else {
				# Fail on an unrecognized upcode
				print "\nUnrecognized opcode: " . $byte . "\n";
				#exit;	
			}
		}
	}
	elsif( $instruction eq "expansion" ) {
		# Look up the expanded operation in the expansion table
		my $next_byte = substr( $binary, 0, 2 );
		my $reg_bytes = substr( unpack( "B*", pack( "H*", $next_byte ) ), 2, 3 );
		my $instruction_grp = $expansions{ $byte }{ $reg_bytes };
		$instruction = $$instruction_grp[0];
	    $op_args = $$instruction_grp[1];
	}
	elsif( $instruction eq "start_byte" ) {
		# Look up the expanded operation in the start byte table
		my $next_byte = substr( $binary, 0, 2 );
		my $instruction_grp = $start_bytes{ $byte }{ $next_byte };
		$instruction = $$instruction_grp[0];
	    $op_args = $$instruction_grp[1];
	}
	
	if( $instruction eq "call" ) {
		my $jump_addr = $current_byte;
		$jump_addr += (length($byte) / 2);
		my $addr;
		if( $$op_args[0] eq "rel8" ) {
			$jump_addr += 1;
			$addr = format_hex(substr( $binary, 0, 2 ));
			$jump_addr += hex($addr);
 		} elsif( $$op_args[0] eq "rel32" ) {
	 		$jump_addr += 4;
	 		$addr = format_hex(substr( $binary, 0, 8 ));
	 		$jump_addr += hex($addr);
 		}
 		
 		$target_address = sprintf("0x%x",$jump_addr);
 		
 		my $label = sprintf("%x", $jump_addr) . "-" . "offset_" . sprintf("0x%x", $jump_addr) . ":";
 		push( @labels, $label );
		
	}
	
	# Print out the current line so far
	$print_line .= sprintf( "    %2x: %2s ", $current_byte, $byte );
	
	# Add the instruction to the disassembled line
	my $disasm_line = $instruction . " ";
	
	# If the arguments are reg or r/m, get the modr/m byte
	if( $$op_args[0] eq "reg" || $$op_args[1] eq "reg" || $$op_args[0] eq "r/m" || $$op_args[1] eq "r/m") {
		$instr_bytes = substr( $binary, 0, 2, "" );	
		$current_byte++;
	}
	
	# Iterate through the arguments
	my $arg_count = 0;
	foreach( @$op_args ) {
		# Add a comma for each additional argument
		if( $arg_count > 0 ) {
			$disasm_line .= ", ";	
		}
		
		# Grab the modrm bytes from the instruction
		my $modrm_bytes = unpack( "B*", pack( "H*", $instr_bytes ) );
		my $modrm_value = "";
		if( $_ eq "reg" ) {
			# Get the reg value of the modr/m byte
			my @decoded_modrm = (decode_modrm( $modrm_bytes ));
			my $reg = $decoded_modrm[1];
			$disasm_line .= $reg;
		}
		elsif( $_ eq "r/m" ) {
			# Get the r/m value of the modr/m byte
			my $hex_value = unpack( "H*", pack( "B*", $modrm_bytes ) );
			my @decoded_modrm = (decode_modrm( $modrm_bytes ));
			my $rm_val = $decoded_modrm[2];
			if( $decoded_modrm[0] eq "10" ) {
				$disasm_line .= "[" . $rm_val . "+";	
			}
			
			# Lookup the arguments in the modr/m table
			$modrm_value = $bit_addr{ $hex_value };
			
			# If it's a 32 bit displacement, grab those bits
			if( $modrm_value =~ /disp32/ ) {
				$instr_bytes = substr( $binary, 0, 8, "" );
				$current_byte += 4;
				$disasm_line .= format_hex( $instr_bytes );
			}
			elsif( $modrm_value =~ /disp8/ ) {
				# Grab the 8 bits in an 8 bit displacement
				my $disp_bytes = substr( $binary, 0, 2, "" );
				$instr_bytes .= $disp_bytes; #format_hex( $disp_bytes );
				my $formatted_bytes = format_hex( $disp_bytes );
				# Increment the current byte
				$current_byte += 1;
				$modrm_value =~ s/disp8/$formatted_bytes/;
				$disasm_line .= $modrm_value; # . "+" . $formatted_bytes;
			}
			elsif( $modrm_value eq "sib" ) {
				# If it's a sib byte, get that
				my $sib_byte = substr( $binary, 0, 2, "" );
				my $offset_addr = substr( $binary, 0, 8, "" );
				# Increment the current byte
				$current_byte += 5;
				$instr_bytes .= format_hex( $offset_addr );
				$modrm_value = $sib_addr{ $sib_byte } . "+" . $offset_addr;
				$disasm_line .= $modrm_value;
			}
			else {
				# Otherwise, add the argument
				$disasm_line .= $modrm_value;
			}
			
			if( $decoded_modrm[0] eq "10" ) {
				$disasm_line .= "]";	
			}
		}
		elsif( $_ eq "imm32" || $_ eq "rel32" || $_ eq "moffs32" ) {
			# Grab a 4 byte argument if present
			$instr_bytes .= substr( $binary, 0, 8, "" );
			# Increment the current byte
			$current_byte += 4;
			
			my $formatted_string = format_hex( $instr_bytes );
			
			if( $instruction ne "call" ) {
			    if( $_ eq "moffs32" ) {
				    $formatted_string = "[" . $formatted_string . "]";
			    }
		    }
		    else {
			    $formatted_string = $target_address;
		    }
			$disasm_line .= $formatted_string;
		}
		elsif( $_ eq "imm16" || $_ eq "rel16" ) {
			# Grab a 2 byte argument if present
			$instr_bytes .= substr( $binary, 0, 4, "" );
			# Increment the current byte
			$current_byte += 2;
			$disasm_line .= format_hex( $instr_bytes );
		}
		elsif( $_ eq "imm8" || $_ eq "rel8" ) {
			# Grab a 1 byte argument if present
			$instr_bytes .= substr( $binary, 0, 2, "" );
			# Increment the current byte
			$current_byte++;
			$disasm_line .= format_hex( $instr_bytes );
		}
		else {
			# Add the argument
			$disasm_line .= $_;	
		}
		
		# Increase the number of arguments
		$arg_count++;
	}
	
	# Print out the instruction bytes
	$print_line .= sprintf( "%-16s", $instr_bytes );
	
	# Print out the disassembled line
	$print_line .= "\t" . $disasm_line . "\n";
	
	# Iterate to the next byte
	$current_byte++;

}

foreach( @labels ) {
	my @label_info = split("-", $_);
	print $label_info[1] . "\n";
	$print_line =~ s/\s*$label_info[0]:/\n$label_info[1]\n    $label_info[0]:/;
}

print $print_line;

# Format the hex
sub format_hex {
	my $hex = $_[0];
	my $counter = length( $hex );
	my $format_hex = "0x";
	
	while( $counter > 0 ) {
		$counter -= 2;
		$format_hex .= substr( $hex, $counter, 2 );
	}
	
	return $format_hex;
}

# Read a file as binary
sub read_file {
	my $infile = $_[0];
	open( IN, "< $infile" );
	binmode( IN );
	my $binary = unpack( 'H*', <IN> );
	close( IN );	
	
	return $binary;
}

# Decode the modr/m byte
sub decode_modrm {
	my $byte = $_[0];
	my $mod = substr( $byte, 0, 2 );
	my $reg = $regs{ substr( $byte, 2, 3 ) };
	my $rm = $regs{ substr( $byte, 5, 3 ) };
	
	my @modrm = ( $mod, $reg, $rm );
	return @modrm;
		
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#define BLOCK_SIZE		(512)
#define PARAGRAPH_SIZE	(16)
#define MAGIC			(0x5a4d)

/* 
 *	block == 512 byte
 *	paragraph == 16 byte
 *	info from http://www.delorie.com/djgpp/doc/exe
 *	alse frome http://www.tavi.co.uk/phobos/exeformat.html
 *
 * 00-01 	0x4d, 0x5a. This is the "magic number" of an EXE file. The first byte of the file is 0x4d and the second is 0x5a.
 * 02-03 	The number of bytes in the last block of the program that are actually used. 
 * 			If this value is zero, that means the entire last block is used (i.e. the effective value is 512).
 * 04-05 	Number of blocks in the file that are part of the EXE file. If [02-03] is non-zero, only that much of the last block is used.
 * 06-07 	Number of relocation entries stored after the header. May be zero.
 * 08-09 	Number of paragraphs in the header. The program's data begins just after the header, 
 * 			and this field can be used to calculate the appropriate file offset. The header includes the relocation entries. 
 * 			Note that some OSs and/or programs may fail if the header is not a multiple of 512 bytes.
 * 0A-0B 	Number of paragraphs of additional memory that the program will need. 
 * 			This is the equivalent of the BSS size in a Unix program. The program can't be loaded if there 
 * 			isn't at least this much memory available to it.
 * 0C-0D 	Maximum number of paragraphs of additional memory. Normally, the OS reserves all the remaining conventional memory 
 * 			for your program, but you can limit it with this field.
 * 0E-0F 	Relative value of the stack segment. This value is added to the segment the program was loaded at, 
 * 			and the result is used to initialize the SS register.
 * 10-11 	Initial value of the SP register.
 * 12-13 	Word checksum. If set properly, the 16-bit sum of all words in the file should be zero. Usually, this isn't filled in.
 * 14-15 	Initial value of the IP register.
 * 16-17 	Initial value of the CS register, relative to the segment the program was loaded at.
 * 18-19 	Offset of the first relocation item in the file.
 * 1A-1B 	Overlay number. Normally zero, meaning that it's the main program.
 **/
typedef struct _EXE_HEADER {
/* 00 ~ 01 */	uint16_t	e_signature; 			/* EXE文件标志 */
/* 02 ~ 03 */	uint16_t	e_bytes_in_last_block;	/* 文件最后一块的字节个数 */
/* 04 ~ 05 */	uint16_t	e_blocks_in_file;		/* 文件所占的块数（包括文件头）单位: 512字节/块 */
/* 06 ~ 07 */	uint16_t	e_num_relocs;			/* 重定位表的重定位项数 */
/* 08 ~ 09 */	uint16_t	e_header_paragraphs;	/* 文件头的长度 单位：16字节 */
/* 0A ~ 0B */	uint16_t	e_min_extra_paragraphs;	/* 程序运行所需最小内存 */
/* 0C ~ 0D */	uint16_t	e_max_extra_paragraphs;	/* 程序运行所需最大内存 */
/* 0E ~ 0F */	uint16_t	e_ss;					/* SS的相对段值 */
/* 10 ~ 11 */	uint16_t	e_sp;					/* SP初始值 */
/* 12 ~ 13 */	uint16_t	e_checksum;				/* 校验和 1的补码 */
/* 14 ~ 15 */	uint16_t	e_ip;					/* IP的初始值 */
/* 16 ~ 17 */	uint16_t	e_cs;					/* CS的相对值 */
/* 18 ~ 19 */	uint16_t	e_reloc_table_offset;	/* 重定位表在文件中的偏移值 */
/* 1A ~ 1B */	uint16_t	e_overlay_number;		/* 由MS-LINK产生的覆盖号 */
} __attribute__((packed)) EXE_HEADER; 
/* 28 byte */

typedef struct _EXE_RELOC {
	uint16_t	r_offset;	/* 段内偏移 */
	uint16_t	r_segment;	/* 相对段值 */
} __attribute__((packed)) EXE_RELOC;
// DOS exe的重定位过程发生在加载时???

int main(int argc, const char *argv[])
{
	if (argc != 2) {
		(void)fprintf(stderr, "Usage: %s + filename\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	FILE *fp;
	EXE_HEADER header;
	EXE_RELOC *preloc = NULL;

	if ((fp = fopen(argv[1], "rb")) == NULL) {
		(void)fprintf(stderr, "open file %s faild: %s\n", argv[1], strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (fread(&header, sizeof(header), 1, fp) != 1) {
		(void)fprintf(stderr, "something wrong when read exe header!!!\n");
		goto out;	
	}

	if (header.e_signature != MAGIC) {
		(void)fprintf(stderr, "Sorry, file %s is not a valid DOS exe.\n", argv[1]);	
		goto out;
	}
//	printf("sizeof(EXE_HEADER) = %zu\n", sizeof(EXE_HEADER));	/* 28 bytes */

	/* print exe header info */
	size_t hs = header.e_header_paragraphs * PARAGRAPH_SIZE;
	size_t wfz = header.e_bytes_in_last_block == 0
					? header.e_blocks_in_file * BLOCK_SIZE
					: (header.e_blocks_in_file - 1) * BLOCK_SIZE + header.e_bytes_in_last_block;
	printf("header size: %zu\n", hs);
	printf("whole file size: %zu\n", wfz); 
	printf("load memory size is whole file size - header size: %zu\n", wfz - hs);
	printf("memory limit: %hu ~ %hu\n", header.e_min_extra_paragraphs * PARAGRAPH_SIZE,
								header.e_max_extra_paragraphs * PARAGRAPH_SIZE);
	printf("relative SS: %04hx   SP: %04hx\n", header.e_ss, header.e_sp);
	printf("relative CS: %04hx   IP: %04hx\n", header.e_cs, header.e_ip);

	printf("relocs: %hu   offset: %hu\n", header.e_num_relocs, header.e_reloc_table_offset);
	preloc = malloc(header.e_num_relocs * sizeof(EXE_RELOC));
	if (preloc == NULL) {
		(void)fprintf(stderr, "malloc error [%s]\n", strerror(errno));	
		goto out;
	}
	fseek(fp, header.e_reloc_table_offset, SEEK_SET);
	for (size_t i = 0; i < header.e_num_relocs; i++) {
		if (fread(preloc + i, sizeof(EXE_RELOC), 1, fp) != 1) {
			(void)fprintf(stderr, "something wrong when read reloc!!!\n");
			goto out;	
		}
	}

	for (size_t i = 0; i < header.e_num_relocs; i++) {
		uint16_t r_refseg;
		/* 文件内偏移 */
		long offset = (preloc[i].r_segment << 4) + preloc[i].r_offset + hs;
		fseek(fp, offset, SEEK_SET);	
		if (fread(&r_refseg, sizeof(r_refseg), 1, fp) != 1) continue;
		printf("\t[%d]: segment: 0x%04hx, offset: 0x%04hx -> [0x%04hx]\n", i, 
					preloc[i].r_segment, preloc[i].r_offset, r_refseg);
	}
	
	exit(EXIT_SUCCESS);
out:
	if (fp) {
		fclose(fp);	
	}
	if (preloc) {
		free(preloc);	
	}
	exit(EXIT_FAILURE);
}


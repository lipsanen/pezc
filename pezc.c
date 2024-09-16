#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

typedef struct {
    uint8_t* addr;
    size_t size;
    const char* filename;
} file_s;

typedef struct {
    file_s pdf;
    file_s elf;
    file_s zip; 
    const char* output;
    bool store_zip;
    bool use_shell;
} args_s;

#pragma pack(1)
typedef struct {
    uint8_t start[0x18];
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf_header;

#pragma pack(1)
typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} program_header;


#pragma pack(1)
typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_address;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint8_t end[0x18];
} section_header;

#pragma pack(1)
typedef struct {
    char sig[4];
    uint16_t zip_version;
    uint16_t general_purpose;
    uint16_t compression_method;
    uint16_t file_modified;
    uint16_t file_modified_date;
    uint32_t crc_uncompressed;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_len;
    uint16_t extra_field_len;
} local_file_header;

#pragma pack(1)
typedef struct {
    char sig[4];
    uint16_t version;
    uint16_t extract_version;
    uint16_t general_purpose;
    uint16_t compression_method;
    uint16_t file_modified;
    uint16_t file_modified_date;
    uint32_t crc_uncompressed;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_len;
    uint16_t extra_field_len;
    uint16_t file_comment_len;
    uint16_t disk_num;
    uint16_t internal_file_attributes;
    uint32_t external_file_attributes;
    uint32_t relative_offset;
} central_directory_header;

typedef struct {
    uint32_t offset;
    uint32_t data_offset;
    const char* filename;
    void* comment;
    void* extra_field;
    central_directory_header header;
} zip_file_s;

typedef struct {
    uint8_t* addr;
    size_t size;
    size_t offset;
    zip_file_s files[3];
    size_t zip_file_count;
} output_file_s;

#pragma pack(1)
typedef struct {
    char sig[4];
    uint16_t disk_no;
    uint16_t disk_start;
    uint16_t num_records_disk;
    uint16_t num_records_total;
    uint32_t central_directory_size;
    uint32_t central_directory_offset;
    uint16_t comment_len;
} eocd;

#define ERROR(msg, ...) { fprintf(stderr, msg __VA_OPT__(,) __VA_ARGS__ ); exit(1); }
#define EXIT_IF_ERROR(value, expected, msg, ...) if(value != expected) { fprintf(stderr, msg __VA_OPT__(,) __VA_ARGS__ ); exit(1); }

static unsigned long crc32_compute_buf(const void *buf, size_t bufLen )
{
    static const unsigned long crcTable[256] = {
   0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,
   0x9E6495A3,0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,
   0xE7B82D07,0x90BF1D91,0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,
   0x6DDDE4EB,0xF4D4B551,0x83D385C7,0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,
   0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,0x3B6E20C8,0x4C69105E,0xD56041E4,
   0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,0x35B5A8FA,0x42B2986C,
   0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,0x26D930AC,
   0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
   0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,
   0xB6662D3D,0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,
   0x9FBFE4A5,0xE8B8D433,0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,
   0x086D3D2D,0x91646C97,0xE6635C01,0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,
   0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,0x65B0D9C6,0x12B7E950,0x8BBEB8EA,
   0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,0x4DB26158,0x3AB551CE,
   0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,0x4369E96A,
   0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
   0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,
   0xCE61E49F,0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,
   0xB7BD5C3B,0xC0BA6CAD,0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,
   0x9DD277AF,0x04DB2615,0x73DC1683,0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,
   0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,0xF00F9344,0x8708A3D2,0x1E01F268,
   0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,0xFED41B76,0x89D32BE0,
   0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,0xD6D6A3E8,
   0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
   0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,
   0x4669BE79,0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,
   0x220216B9,0x5505262F,0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,
   0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,
   0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,0x95BF4A82,0xE2B87A14,0x7BB12BAE,
   0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,0x86D3D2D4,0xF1D4E242,
   0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,0x88085AE6,
   0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
   0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,
   0x3E6E77DB,0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,
   0x47B2CF7F,0x30B5FFE9,0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,
   0xCDD70693,0x54DE5729,0x23D967BF,0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,
   0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D };
    unsigned long crc32;
    const unsigned long initial = 0;
    unsigned char *byteBuf;
    size_t i;

    /** accumulate crc32 for buffer **/
    crc32 = initial ^ 0xFFFFFFFF;
    byteBuf = (unsigned char*) buf;
    for (i=0; i < bufLen; i++) {
        crc32 = (crc32 >> 8) ^ crcTable[ (crc32 ^ byteBuf[i]) & 0xFF ];
    }
    return( crc32 ^ 0xFFFFFFFF );
}

static void output_write(output_file_s* output, const void* ptr, uint32_t size) {
    memcpy(output->addr + output->offset, ptr, size);
    output->offset += size;
}

static local_file_header create_local_file_header(void* ptr, uint32_t size, const char* filename) {
    local_file_header fields;
    memset(&fields, 0, sizeof(fields));
    memcpy(fields.sig, "PK\3\4", 4);
    fields.filename_len = strlen(filename);
    fields.crc_uncompressed = crc32_compute_buf(ptr, size);
    fields.compressed_size = fields.uncompressed_size = size;
    return fields;
}

static void write_zip_entry(output_file_s* output, file_s* entry) {
    local_file_header local_header = create_local_file_header(entry->addr, entry->size, entry->filename);
    zip_file_s file;	
    file.filename = entry->filename;
    file.offset = output->offset;

    output_write(output, &local_header, sizeof(local_header));
    output_write(output, (void*)entry->filename, local_header.filename_len);
    file.data_offset = output->offset;
    output_write(output, entry->addr, entry->size);
    
    memset(&file.header, 0, sizeof(file.header));
    memcpy(file.header.sig, "\x50\x4b\x1\x2", 4);
    
    file.header.relative_offset = file.offset;
    #define COPY_FIELD(field) file.header.field = local_header.field;
    COPY_FIELD(general_purpose);
    COPY_FIELD(compression_method);
    COPY_FIELD(file_modified);
    COPY_FIELD(file_modified_date);
    COPY_FIELD(crc_uncompressed);
    COPY_FIELD(compressed_size);
    COPY_FIELD(uncompressed_size);
    COPY_FIELD(filename_len);
    COPY_FIELD(extra_field_len);
    #undef COPY_FIELD
    
    output->files[output->zip_file_count] = file;
    ++(output->zip_file_count);
}

static void write_cdh_entry(output_file_s* output, zip_file_s* file) {
    output_write(output, &file->header, sizeof(file->header));
    output_write(output, (void*)file->filename, file->header.filename_len);
    output_write(output, (void*)file->extra_field, file->header.extra_field_len);
    output_write(output, (void*)file->comment, file->header.file_comment_len);
}

static void write_eocd(output_file_s* output, uint32_t cd_offset, uint16_t comment_len) {
    eocd header;
    memset(&header, 0, sizeof(header));
    memcpy(header.sig, "\x50\x4b\x5\x6", 4);
    header.num_records_disk = header.num_records_total = output->zip_file_count;
    header.central_directory_size = output->offset - cd_offset;
    header.central_directory_offset = cd_offset;
    header.comment_len = comment_len;
    output_write(output, &header, sizeof(header));
}

static bool has_extension(const char* path, const char* extension) {
    const char* a = strstr(path, extension);
    return a != NULL && strlen(a) == strlen(extension);
}

static bool is_elf_file(file_s* file) {
    return memcmp(file->addr, "\x7F""ELF", 4) == 0;
}

file_s mmap_file(const char* filepath) {
    file_s file;
    int fd = open(filepath, O_RDONLY);
    EXIT_IF_ERROR(fd > 0, 1, "Could not open file %s\n", filepath);

    struct stat elf_stat;
    EXIT_IF_ERROR(fstat(fd, &elf_stat), 0, "Call to fstat failed for file %s\n", filepath);

    file.size = elf_stat.st_size;
    file.addr = mmap(NULL, file.size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    file.filename = filepath;

    EXIT_IF_ERROR(file.addr != NULL, 1, "Call to mmap failed for file %s\n", filepath);

    return file;
}

static void print_help() {
    printf("pezc <executable file> <pdf file> [zip file] [other flags] -o <output_path>\n");
    printf("\t--store - store the zip file as a single file entry rather than combining it with the output file\n");
    printf("\t--shell - Use a shell script in the preamble of the file instead of doing ELF header magic\n");
    exit(0);
}

static args_s init_args(int argc, char** argv) {
    if(argc == 1) {
        print_help();
    }

    args_s args;
    memset(&args, 0, sizeof(args));
    for(size_t i=1; i < argc; ++i) {
        if(strcmp("--help", argv[i]) == 0) {
            print_help();
        } else if (strcmp("--shell", argv[i]) == 0) {
            args.use_shell = true;
            continue;
        } else if(strcmp("-o", argv[i]) == 0) {
            ++i;
            if (i >= argc) {
                fprintf(stderr, "Expected argument to -o\n");
                exit(1);
            }
            args.output = argv[i];
            continue;
        } else if(strcmp("--store", argv[i]) == 0) {
            args.store_zip = true;
            continue;
        }
        
        file_s file = mmap_file(argv[i]);
        
        if(has_extension(argv[i], ".pdf")) {
            printf("PDF file loaded from %s\n", argv[i]);
            args.pdf = file;
        } else if(has_extension(argv[i], ".zip")) {
            printf("Zip file loaded from %s\n", argv[i]);
            args.zip = file;
        } else if(is_elf_file(&file)) {
            printf("ELF file loaded from %s\n", argv[i]);
            args.elf = file;
        } else {
            ERROR("File needs to be either be a .zip, a .pdf or an ELF file\n");
        }
    }

    EXIT_IF_ERROR(args.output != NULL, 1, "Specify an output path with -o\n");
    EXIT_IF_ERROR(args.elf.addr != NULL, 1, "ELF file required\n");
    EXIT_IF_ERROR(args.pdf.addr != NULL, 1, "PDF file required\n");

    return args;
}

size_t find_pattern_backward(uint8_t* addr, const char* pattern, size_t start_offset, size_t end_offset){
    size_t len = strlen(pattern);
    size_t offset = end_offset - len;
    while(offset > start_offset) {
        if(memcmp(addr + offset, pattern, len) == 0) {
            return offset;
        }
        --offset;
    }

    ERROR("Unable to find pattern %s\n", pattern);
}

static uint64_t determine_extra_load_addr(program_header* header, size_t num) {
    // an address of 0 seems to crash when using that for the program header
    // select an address that is the highest address plus alignment
    uint64_t alignment = 4096;
    uint64_t high_addr = 0;
    for(size_t i=0; i < num; ++i) {
        uint64_t addr = header[i].p_paddr + header[i].p_memsz + header[i].p_align;
        addr = addr & ~(header[i].p_align - 1);
        addr += alignment - 1;
        addr = addr & ~(alignment - 1);
        if(addr > high_addr) {
            high_addr = addr;
        }
    }
    return high_addr;
}

size_t find_pattern_forward(file_s file, const char* pattern, size_t max_offset) {
    size_t len = strlen(pattern);
    size_t offset = 0;
    if(file.size < max_offset) {
        max_offset = file.size;
    }
    
    while(offset + len < max_offset) {
        if(memcmp(file.addr + offset, pattern, len) == 0) {
            return offset;
        }
        ++offset;
    }
    
    ERROR("Unable to find pattern %s\n", pattern);
}

static void fix_elf_offsets(output_file_s* output, const file_s* elf_file) {
    elf_header* output_elf_header = (elf_header*)output->addr;
    const elf_header* input_elf_header = (elf_header*)elf_file->addr;
    size_t sect_headers_size = input_elf_header->e_shentsize * input_elf_header->e_shnum;
    size_t output_prog_headers_size = input_elf_header->e_phentsize * (input_elf_header->e_phnum + 1);

    output_elf_header->e_phnum += 1;
    output_elf_header->e_phoff = output->offset;
    program_header* output_ph = (program_header*)(output->addr + output->offset);
    output_write(output, elf_file->addr + input_elf_header->e_phoff, output_prog_headers_size);

    output_elf_header->e_shoff = output->offset;
    section_header* output_sh = (section_header*)(output->addr + output->offset);
    output_write(output, elf_file->addr + input_elf_header->e_shoff, sect_headers_size);

    size_t elf_start_offset = output->offset + sect_headers_size + output_prog_headers_size + sizeof(local_file_header) + strlen(elf_file->filename);
    elf_start_offset += 0xFFF;
    elf_start_offset &= ~(0xFFF);

    for(size_t i=1; i < input_elf_header->e_shnum; ++i) {
        output_sh[i].sh_offset += elf_start_offset;
    }

    for(size_t i=0; i < input_elf_header->e_phnum; ++i) {
        // If program header type, then set program header offset
        if (output_ph[i].p_type == 6) {
            output_ph[i].p_offset = output_elf_header->e_phoff;
        } else if (output_ph[i].p_type == 0x3) {
            ERROR("The non-shell output format cannot handle dynamically linked binaries. Try a statically linked binary or use --shell instead.\n");
        }
        else {
            output_ph[i].p_offset += elf_start_offset;
        }
    }


    // Add a new program header
    // The program header itself needs to be loaded
    uint64_t load_addr = determine_extra_load_addr(output_ph, input_elf_header->e_phnum);
    size_t num = input_elf_header->e_phnum;
    const size_t ph_alignment = 4096;
    size_t load_seg_start = output_elf_header->e_phoff & ~(ph_alignment-1);
    size_t load_seg_end = output_elf_header->e_phoff + (output_elf_header->e_phnum * output_elf_header->e_phentsize) + ph_alignment; 
    load_seg_end = load_seg_end & ~(ph_alignment-1);

    output_ph[num].p_type = 1;
    output_ph[num].p_flags = 4;
    output_ph[num].p_offset = load_seg_start;
    output_ph[num].p_vaddr = load_addr;
    output_ph[num].p_paddr = load_addr;
    output_ph[num].p_filesz = load_seg_end - load_seg_start;
    output_ph[num].p_memsz = load_seg_end - load_seg_start;
    output_ph[num].p_align = ph_alignment;

    // the elf file itself should start at elf_start_offset
    // but the zip file entry should start before that, so that everything lines up
    elf_start_offset -= sizeof(local_file_header) + strlen(elf_file->filename);
    output->offset = elf_start_offset;
}

int main(int argc, char** argv) {
    args_s args = init_args(argc, argv);  

    elf_header* p_elf_header = (elf_header*)args.elf.addr;
    size_t sect_headers_size = p_elf_header->e_shentsize * p_elf_header->e_shnum;
    size_t prog_headers_size = p_elf_header->e_phentsize * p_elf_header->e_phnum;
    // Reserve a bit of extra space
    size_t extra_elf_space = 0x4000 + sizeof(elf_header) + sect_headers_size + prog_headers_size; 
    size_t bytes_needed = args.elf.size + args.pdf.size + args.zip.size + extra_elf_space;
    output_file_s output;
    memset(&output, 0, sizeof(output));

    output.addr = malloc(bytes_needed);
    output.size = bytes_needed;
    EXIT_IF_ERROR(output.addr != NULL, 1, "Failed to allocate %lu bytes\n", bytes_needed);

    // Two output options
    if(!args.use_shell) {
        // Fancy ELF header stuff, the output is a real ELF file
        output.offset = 0;
        output_write(&output, args.elf.addr, sizeof(elf_header));
        write_zip_entry(&output, &args.pdf);

        fix_elf_offsets(&output, &args.elf);
        write_zip_entry(&output, &args.elf);
    } else {
        // A less fancy self-extracting file
        // Puts a small shell script at the start of the file that extracts the binary from itself
        output.offset = 256;
        write_zip_entry(&output, &args.pdf);
        write_zip_entry(&output, &args.elf);

        uint32_t zip_files_offset = output.offset;

        // Add the data location and size to the shell script
        const char* preamble = "#!/bin/bash\ni=\"$(command -v \"$0\")\"\no=\"$i.elf\"\ntail -c +%u $i | head -c %u > $o\nchmod +x $o\n$o\nexit\n";
        output.offset = 0;
        char PREAMBLE_BUFFER[256];
        sprintf(PREAMBLE_BUFFER, preamble, output.files[1].data_offset + 1, (uint32_t)args.elf.size);
        output_write(&output, PREAMBLE_BUFFER, strlen(PREAMBLE_BUFFER));

        output.offset = zip_files_offset;
    }

    void* existing_cd_start = NULL;
    size_t existing_cd_size = 0;
    size_t existing_zip_entries = 0;

    // Write any zip entries from the zip file, if one was given
    if(args.zip.addr != NULL && !args.store_zip) {
        uint32_t current_offset = output.offset;
        // Go backwards from the end of the file to find the EOCD header
        size_t eocd_offset = find_pattern_backward(args.zip.addr, "\x50\x4b\x5\x6", 0, args.zip.size);
        eocd* eocd_ptr = (eocd*)(args.zip.addr + eocd_offset);
        existing_zip_entries = eocd_ptr->num_records_total;
        output.zip_file_count += eocd_ptr->num_records_total;
        existing_cd_size = eocd_ptr->central_directory_size;
        
        // We don't bother parsing the zip file, just write the content before the central directory to the file as is.
        output_write(&output, args.zip.addr, eocd_ptr->central_directory_offset);
        
        // Fix the central directory headers - need to increment everything by current_offset
        central_directory_header* header = existing_cd_start = (central_directory_header*)(args.zip.addr + eocd_ptr->central_directory_offset);
        for(size_t i=0; i < eocd_ptr->num_records_total; ++i) {
            header->relative_offset += current_offset;
            header = (central_directory_header*)((uint8_t*)header + 
                sizeof(central_directory_header) + header->filename_len + header->extra_field_len + header->file_comment_len);
        }
    } else if (args.zip.addr != NULL) {
        // --store flag used: Store the zip file as an entry
        write_zip_entry(&output, &args.zip);
    }

    uint32_t cd_offset = output.offset;
    for(size_t i=0; i < output.zip_file_count - existing_zip_entries; ++i) {
        write_cdh_entry(&output, &output.files[i]);
    }
    if (existing_cd_start) {
        output_write(&output, existing_cd_start, existing_cd_size);
    }

    // Write the end of the pdf file again in the zip file comment
    // This makes it a valid(ish) PDF file
    size_t offset = find_pattern_forward(args.pdf, "%PDF-1.", 1024);
    size_t eof_offset = find_pattern_backward(args.pdf.addr, "%%EOF", offset, args.pdf.size);
    size_t startxref = find_pattern_backward(args.pdf.addr, "startxref", offset, eof_offset);
    write_eocd(&output, cd_offset, args.pdf.size - startxref);
    output_write(&output, args.pdf.addr + startxref, args.pdf.size - startxref);

    FILE* output_file = fopen(args.output, "wb");
    EXIT_IF_ERROR(output_file != NULL, 1, "Unable to open output file %s\n", args.output);
    EXIT_IF_ERROR(fwrite(output.addr, output.offset, 1, output_file), 1, "fwrite failed\n");
    EXIT_IF_ERROR(fclose(output_file), 0, "fclose failed\n");
    EXIT_IF_ERROR(chmod(args.output, 0777), 0, "Failed to set permissions for file\n");
}

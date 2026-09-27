#include <stdio.h>
#include <windows.h>
#include <string.h>

const char* get_machine_name(WORD machine)
{
    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        return "x86";

    case IMAGE_FILE_MACHINE_AMD64:
        return "x64";

    case IMAGE_FILE_MACHINE_ARM64:
        return "ARM64";

    default:
        return "Unknown";
    }
}

void print_security_flags(WORD dllCharacteristics)
{
    printf("\n[Security]\n");

    printf("ASLR : %s\n",
        (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        ? "Enabled" : "Disabled");

    printf("DEP  : %s\n",
        (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        ? "Enabled" : "Disabled");

    printf("CFG  : %s\n",
        (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
        ? "Enabled" : "Disabled");
}

void print_section_permission(DWORD characteristics)
{
    printf("%c",
        (characteristics & IMAGE_SCN_MEM_READ) ? 'R' : '-');

    printf("%c",
        (characteristics & IMAGE_SCN_MEM_WRITE) ? 'W' : '-');

    printf("%c",
        (characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'X' : '-');
}

int main(int argc, char* argv[])
{
    FILE* fp;

    IMAGE_DOS_HEADER dosHeader;
    DWORD peSignature;
    IMAGE_FILE_HEADER fileHeader;

    WORD optionalMagic;

    DWORD entryPoint = 0;
    ULONGLONG imageBase = 0;
    WORD dllCharacteristics = 0;

    /*
        Usage:
        PEAnalyzer.exe test.exe
    */

    if (argc != 2)
    {
        printf("Usage: %s <PE file>\n", argv[0]);
        return 1;
    }

    if (fopen_s(&fp, argv[1], "rb") != 0)
    {
        printf("[-] Failed to open file.\n");
        return 1;
    }

    /*
        1. Read DOS Header
    */

    if (fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, fp) != 1)
    {
        printf("[-] Failed to read DOS Header.\n");
        fclose(fp);
        return 1;
    }

    /*
        Check MZ Signature
    */

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[-] This is not a valid PE file.\n");
        fclose(fp);
        return 1;
    }

    printf("=== PE Analyzer ===\n\n");

    printf("[DOS Header]\n");
    printf("MZ Signature : Valid\n");
    printf("PE Offset    : 0x%08X\n", dosHeader.e_lfanew);

    /*
        Move to PE Header using e_lfanew.
    */

    fseek(fp, dosHeader.e_lfanew, SEEK_SET);

    /*
        2. Read PE Signature
    */

    if (fread(&peSignature, sizeof(DWORD), 1, fp) != 1)
    {
        printf("[-] Failed to read PE Signature.\n");
        fclose(fp);
        return 1;
    }

    if (peSignature != IMAGE_NT_SIGNATURE)
    {
        printf("[-] Invalid PE Signature.\n");
        fclose(fp);
        return 1;
    }

    /*
        3. Read COFF / File Header
    */

    if (fread(&fileHeader, sizeof(IMAGE_FILE_HEADER), 1, fp) != 1)
    {
        printf("[-] Failed to read File Header.\n");
        fclose(fp);
        return 1;
    }

    printf("\n[PE Header]\n");

    printf("PE Signature : Valid\n");

    printf("Architecture : %s\n",
        get_machine_name(fileHeader.Machine));

    printf("Sections     : %u\n",
        fileHeader.NumberOfSections);

    /*
        Current file position is the start of the Optional Header.
    */

    long optionalHeaderPosition = ftell(fp);

    /*
        Read Optional Header Magic to distinguish PE32 / PE32+.
    */

    if (fread(&optionalMagic, sizeof(WORD), 1, fp) != 1)
    {
        printf("[-] Failed to read Optional Header Magic.\n");
        fclose(fp);
        return 1;
    }

    /*
        Return to the beginning of Optional Header.
    */

    fseek(fp, optionalHeaderPosition, SEEK_SET);

    /*
        PE32 (32-bit)
    */

    if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER32 optionalHeader32;

        if (fread(
            &optionalHeader32,
            sizeof(IMAGE_OPTIONAL_HEADER32),
            1,
            fp) != 1)
        {
            printf("[-] Failed to read PE32 Optional Header.\n");
            fclose(fp);
            return 1;
        }

        printf("PE Type      : PE32 (32-bit)\n");

        entryPoint = optionalHeader32.AddressOfEntryPoint;
        imageBase = optionalHeader32.ImageBase;

        dllCharacteristics =
            optionalHeader32.DllCharacteristics;
    }

    /*
        PE32+ (64-bit)
    */

    else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER64 optionalHeader64;

        if (fread(
            &optionalHeader64,
            sizeof(IMAGE_OPTIONAL_HEADER64),
            1,
            fp) != 1)
        {
            printf("[-] Failed to read PE32+ Optional Header.\n");
            fclose(fp);
            return 1;
        }

        printf("PE Type      : PE32+ (64-bit)\n");

        entryPoint =
            optionalHeader64.AddressOfEntryPoint;

        imageBase =
            optionalHeader64.ImageBase;

        dllCharacteristics =
            optionalHeader64.DllCharacteristics;
    }

    else
    {
        printf("[-] Unknown Optional Header format.\n");

        fclose(fp);
        return 1;
    }

    printf("Entry Point  : 0x%08X\n", entryPoint);

    printf("Image Base   : 0x%016llX\n",
        (unsigned long long)imageBase);

    /*
        4. Print security options
    */

    print_security_flags(dllCharacteristics);

    /*
        5. Calculate Section Table position

        PE Header offset
        +
        PE Signature
        +
        IMAGE_FILE_HEADER
        +
        Optional Header
    */

    long sectionTableOffset =
        dosHeader.e_lfanew
        + sizeof(DWORD)
        + sizeof(IMAGE_FILE_HEADER)
        + fileHeader.SizeOfOptionalHeader;

    fseek(fp, sectionTableOffset, SEEK_SET);

    printf("\n[Sections]\n\n");

    printf(
        "%-9s %-12s %-12s %-12s %-5s\n",
        "Name",
        "RVA",
        "VirtualSize",
        "RawSize",
        "Perm"
    );

    printf(
        "----------------------------------------------------------\n"
    );

    for (int i = 0; i < fileHeader.NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER section;

        if (fread(
            &section,
            sizeof(IMAGE_SECTION_HEADER),
            1,
            fp) != 1)
        {
            printf("[-] Failed to read Section Header.\n");
            fclose(fp);
            return 1;
        }

        char sectionName[9] = { 0 };

        memcpy(
            sectionName,
            section.Name,
            IMAGE_SIZEOF_SHORT_NAME
        );

        printf(
            "%-9s 0x%08X   0x%08X   0x%08X   ",
            sectionName,
            section.VirtualAddress,
            section.Misc.VirtualSize,
            section.SizeOfRawData
        );

        print_section_permission(
            section.Characteristics
        );

        /*
            A writable + executable section is worth reviewing
            from a security-analysis perspective.
        */

        if (
            (section.Characteristics & IMAGE_SCN_MEM_WRITE)
            &&
            (section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
            )
        {
            printf("  [!] Writable + Executable");
        }

        printf("\n");
    }

    fclose(fp);

    return 0;
}

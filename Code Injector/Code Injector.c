#include <stdio.h>
#include <Windows.h>


int init(int argc, char* argv[]);
void usuage();
void errorHandling();
int readDOSHeader(HANDLE hFile);
int readFileHeader(HANDLE hFile);
int readOptionalHeader(HANDLE hFile);
int createNewSection(HANDLE hFile);

TCHAR filePath[100];

struct _IMAGE_DOS_HEADER imageDOSHeader;
struct _IMAGE_FILE_HEADER imageFileHeader;
struct _IMAGE_OPTIONAL_HEADER imageOptionalHeader32;
struct _IMAGE_OPTIONAL_HEADER64 imageOptionalHeader64;
struct _IMAGE_SECTION_HEADER imageSectionHeader;

DWORD bytesRead = 0;
WORD magic = 0;

int main(int argc, char* argv[])
{
	if (init(argc, argv) != 0) {
		return 0;
	}

	HANDLE hFile = INVALID_HANDLE_VALUE;

	hFile = CreateFile(filePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, NULL, NULL);

	if (hFile != INVALID_HANDLE_VALUE) {

		printf("success opening file\n");

		if (readDOSHeader(hFile) != 0) {
			return 0;
		}
		if (readFileHeader(hFile) != 0) {
			return 0;
		}
		if (readOptionalHeader(hFile) != 0) {
			return 0;
		}
		if (createNewSection(hFile) != 0) {
			return 0;
		}
		CloseHandle(hFile);
	}
	else {
		errorHandling();
	}

	return 0;
}


int init(int argc, char* argv[]) {
	if (argc == 5) {
		if (strcmp(argv[1], "-p") != 0 || strcmp(argv[3], "-pe") != 0) {
			usuage();
		}
		else
		{
			printf("path: %s\n", argv[4]);

			swprintf(filePath, sizeof(filePath) / sizeof(TCHAR), L"%hs", argv[4]);
		}
	}
	else
	{
		usuage();
		return -1;
	}

	return 0;
}

int createNewSection(HANDLE hFile) {

	BYTE name[] = { '.', 'p', 'w', 'n' };
	DWORD virtualSize = 0x3E8;

	if (magic == 0x10b) {

		LONG distanceToMove = imageDOSHeader.e_lfanew + sizeof(DWORD) + sizeof(imageFileHeader) + sizeof(imageOptionalHeader32) + (sizeof(imageSectionHeader) * (imageFileHeader.NumberOfSections - 1));
		SetFilePointer(hFile, distanceToMove, NULL, FILE_BEGIN);

		ZeroMemory(&imageSectionHeader, sizeof(imageSectionHeader));

		if (ReadFile(hFile, &imageSectionHeader, sizeof(imageSectionHeader), &bytesRead, NULL) == 0) {
			errorHandling();
			CloseHandle(hFile);
			return -1;
		}

		DWORD virtualAddress = imageOptionalHeader32.SectionAlignment * ((imageSectionHeader.Misc.VirtualSize + imageOptionalHeader32.SectionAlignment) / imageOptionalHeader32.SectionAlignment);
		virtualAddress += imageSectionHeader.VirtualAddress;

		DWORD rawAddress = imageSectionHeader.SizeOfRawData + imageSectionHeader.PointerToRawData;

		ZeroMemory(&imageSectionHeader, sizeof(imageSectionHeader));
		CopyMemory(imageSectionHeader.Name, name, sizeof(name) / sizeof(BYTE));

		imageSectionHeader.Misc.VirtualSize = virtualSize;
		imageSectionHeader.VirtualAddress = virtualAddress;
		imageSectionHeader.SizeOfRawData = imageOptionalHeader32.FileAlignment * ((virtualSize + imageOptionalHeader32.FileAlignment) / imageOptionalHeader32.FileAlignment);
		imageSectionHeader.PointerToRawData = rawAddress;
		imageSectionHeader.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;

		printf("%s\n", imageSectionHeader.Name);
		printf("%lX\n", imageSectionHeader.Misc.VirtualSize);
		printf("%lX\n", imageSectionHeader.VirtualAddress);
		printf("%lX\n", imageSectionHeader.SizeOfRawData);
		printf("%lX\n", imageSectionHeader.PointerToRawData);
		printf("%lX\n", imageSectionHeader.PointerToRelocations);
		printf("%lX\n", imageSectionHeader.PointerToLinenumbers);
		printf("%hX\n", imageSectionHeader.NumberOfRelocations);
		printf("%hX\n", imageSectionHeader.NumberOfLinenumbers);
		printf("%lX\n", imageSectionHeader.Characteristics);

		if (WriteFile(hFile, &imageSectionHeader, sizeof(imageSectionHeader), &bytesRead, NULL) != 0) {
			printf("Section created successfully\n");
		}
		else {
			errorHandling();
			CloseHandle(hFile);
			return -1;
		}
		SetFilePointer(hFile, imageSectionHeader.PointerToRawData, NULL, FILE_BEGIN);

		HANDLE hHeap = GetProcessHeap();

		byte* sectionEmptyData = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, imageSectionHeader.SizeOfRawData);

		if (WriteFile(hFile, sectionEmptyData, imageSectionHeader.SizeOfRawData, &bytesRead, NULL) != 0) {
			printf("Section filled with zeros\n");
		}
		else {
			errorHandling();
			CloseHandle(hFile);
			HeapFree(hHeap, 0, sectionEmptyData);
			CloseHandle(hHeap);
			return -1;
		}

		HeapFree(hHeap, 0, sectionEmptyData);
		CloseHandle(hHeap);


		imageFileHeader.NumberOfSections += 1;
		imageOptionalHeader32.SizeOfImage = imageOptionalHeader32.SectionAlignment * ((imageSectionHeader.Misc.VirtualSize + imageOptionalHeader32.SectionAlignment) / imageOptionalHeader32.SectionAlignment);
		imageOptionalHeader32.SizeOfImage += imageSectionHeader.VirtualAddress;

		SetFilePointer(hFile, imageDOSHeader.e_lfanew + sizeof(DWORD) + sizeof(WORD), NULL, FILE_BEGIN);

		if (WriteFile(hFile, &imageFileHeader.NumberOfSections, sizeof(imageFileHeader.NumberOfSections), &bytesRead, NULL) != 0) {
			printf("updated number of sections\n");
		}
		else {
			errorHandling();
			CloseHandle(hFile);
			return -1;
		}

		SetFilePointer(hFile, imageDOSHeader.e_lfanew + sizeof(DWORD) + sizeof(imageFileHeader) + (sizeof(WORD) * 7) + (sizeof(DWORD) * 10) + (sizeof(BYTE) * 2), NULL, FILE_BEGIN);

		if (WriteFile(hFile, &imageOptionalHeader32.SizeOfImage, sizeof(imageOptionalHeader32.SizeOfImage), &bytesRead, NULL) != 0) {
			printf("updated size of the image\n");
		}
		else {
			errorHandling();
			CloseHandle(hFile);
			return -1;
		}
	}
	else if (magic == 0x20b) {
		LONG distanceToMove = imageDOSHeader.e_lfanew + sizeof(DWORD) + sizeof(imageFileHeader) + sizeof(imageOptionalHeader64) + (sizeof(imageSectionHeader) * imageFileHeader.NumberOfSections);
		SetFilePointer(hFile, distanceToMove, NULL, FILE_BEGIN);
	}
	else {
		printf("unknown binary\n");
		printf("currently only supports x86 and x64 PE\n");
		return -1;
	}



	return 0;
}

int readOptionalHeader(HANDLE hFile) {
	SetFilePointer(hFile, imageDOSHeader.e_lfanew + sizeof(DWORD) + sizeof(imageFileHeader), NULL, FILE_BEGIN);

	char* Magic = "Magic";
	char* MajorLinkerVersion = "MajorLinkerVersion";
	char* MinorLinkerVersion = "MinorLinkerVersion";
	char* SizeOfCode = "SizeOfCode";
	char* SizeOfInitializedData = "SizeOfInitializedData";
	char* SizeOfUninitializedData = "SizeOfUninitializedData";
	char* AddressOfEntryPoint = "AddressOfEntryPoint";
	char* BaseOfCode = "BaseOfCode";
	char* BaseOfData = "BaseOfData"; // only on 32 bits

	//
	// NT additional fields.
	//

	char* ImageBase = "ImageBase";
	char* SectionAlignment = "SectionAlignment";
	char* FileAlignment = "FileAlignment";
	char* MajorOperatingSystemVersion = "MajorOperatingSystemVersion";
	char* MinorOperatingSystemVersion = "MinorOperatingSystemVersion";
	char* MajorImageVersion = "MajorImageVersion";
	char* MinorImageVersion = "MinorImageVersion";
	char* MajorSubsystemVersion = "MajorSubsystemVersion";
	char* MinorSubsystemVersion = "MinorSubsystemVersion";
	char* Win32VersionValue = "Win32VersionValue";
	char* SizeOfImage = "SizeOfImage";
	char* SizeOfHeaders = "SizeOfHeaders";
	char* CheckSum = "CheckSum";
	char* Subsystem = "Subsystem";
	char* DllCharacteristics = "DllCharacteristics";
	char* SizeOfStackReserve = "SizeOfStackReserve";
	char* SizeOfStackCommit = "SizeOfStackCommit";
	char* SizeOfHeapReserve = "SizeOfHeapReserve";
	char* SizeOfHeapCommit = "SizeOfHeapCommit";
	char* LoaderFlags = "LoaderFlags";
	char* NumberOfRvaAndSizes = "NumberOfRvaAndSizes";

	char* ExportDirectory = "Export Directory";
	char* ImportDirectory = "Import Directory";
	char* ResourceDirectory = "Resource Directory";
	char* ExceptionDirectory = "Exception Directory";
	char* SecurityDirectory = "Security Directory";
	char* RelocationDirectory = "Relocation Directory";
	char* DebugDirectory = "Debug Directory";
	char* ArchitectureDirectory = "Architecture Directory";
	char* GlobalPtr = "Global Pointer Directory";
	char* TLSDirectory = "TLS Directory";
	char* ConfigurationDirectory = "Configuration Directory";
	char* BoundImportDirectory = "Bound Import Directory";
	char* IATDirectory = "IAT Directory";
	char* DelayImportDirectory = "Delay Import Directory";
	char* dotNetMetaDataDirectory = ".Net MetaData Directory";


	if (magic == 0x10b) {
		if (ReadFile(hFile, &imageOptionalHeader32, sizeof(imageOptionalHeader32), &bytesRead, NULL) != 0) {
			printf("%-25s: %-25hX\n", Magic, imageOptionalHeader32.Magic);
			printf("%-25s: %-25lX\n", AddressOfEntryPoint, imageOptionalHeader32.AddressOfEntryPoint);
			printf("%-25s: %-25lX\n", ImageBase, imageOptionalHeader32.ImageBase);
			printf("%-25s: %-25lX\n", SectionAlignment, imageOptionalHeader32.SectionAlignment);
			printf("%-25s: %-25lX\n", FileAlignment, imageOptionalHeader32.FileAlignment);
			printf("%-25s: %-25lX\n", SizeOfImage, imageOptionalHeader32.SizeOfImage);
			printf("%-25s: %-25lX\n", SizeOfHeaders, imageOptionalHeader32.SizeOfHeaders);
		}
		else {
			errorHandling();
			CloseHandle(hFile);
			return -1;
		}
	}
	else if (magic == 0x20b) {
		if (ReadFile(hFile, &imageOptionalHeader64, sizeof(imageOptionalHeader64), &bytesRead, NULL) != 0) {

			printf("%-25s: %-25hX\n", Magic, imageOptionalHeader64.Magic);
			printf("%-25s: %-25lX\n", AddressOfEntryPoint, imageOptionalHeader64.AddressOfEntryPoint);
			printf("%-25s: %-25llX\n", ImageBase, imageOptionalHeader64.ImageBase);
			printf("%-25s: %-25lX\n", SectionAlignment, imageOptionalHeader64.SectionAlignment);
			printf("%-25s: %-25lX\n", FileAlignment, imageOptionalHeader64.FileAlignment);
			printf("%-25s: %-25lX\n", SizeOfImage, imageOptionalHeader64.SizeOfImage);
			printf("%-25s: %-25lX\n", SizeOfHeaders, imageOptionalHeader64.SizeOfHeaders);

		}
		else {
			errorHandling();
			CloseHandle(hFile);
			return -1;
		}
	}
	else {
		printf("unknown binary\n");
		printf("currently only supports x86 and x64 PE\n");
		return -1;
	}

	return 0;
}


int readFileHeader(HANDLE hFile) {

	SetFilePointer(hFile, imageDOSHeader.e_lfanew + sizeof(DWORD), NULL, FILE_BEGIN);

	if (ReadFile(hFile, &imageFileHeader, sizeof(imageFileHeader), &bytesRead, NULL) != 0) {

		char* machine = "Machine";
		char* numOfSections = "Number Of Sections";
		char* timeDateStamp = "Time Date Stamp";
		char* pointerToSymbolTable = "Pointer To Symbol Table";
		char* numberOfSymbols = "Number Of Symbols";
		char* sizeOfOptionalHeader = "Size Of Optional Header";
		char* characteristics = "Characteristics";

		printf("%-25s: %-25hX\n", machine, imageFileHeader.Machine);
		printf("%-25s: %-25hX\n", numOfSections, imageFileHeader.NumberOfSections);
		printf("%-25s: %-25hX\n", sizeOfOptionalHeader, imageFileHeader.SizeOfOptionalHeader);

		if (ReadFile(hFile, &magic, sizeof(WORD), &bytesRead, NULL) != 0) {

			char* mgic = "magic";
			printf("%-25s: %-25hX\n", mgic, magic);
		}
		else
		{
			errorHandling();
			CloseHandle(hFile);
			return -1;
		}

	}
	else
	{
		errorHandling();
		CloseHandle(hFile);
		return -1;
	}

	return 0;
}

int readDOSHeader(HANDLE hFile) {

	char* e_lfanew = "e_lfanew";

	if (ReadFile(hFile, &imageDOSHeader, sizeof(imageDOSHeader), &bytesRead, NULL) != 0) {
		printf("%-25s: %-25lX\n", e_lfanew, imageDOSHeader.e_lfanew);
	}
	else
	{
		errorHandling();
		CloseHandle(hFile);
		return -1;
	}
	return 0;
}

void usuage() {
	printf("Usuage: Code Injector.exe -p <raw payload file> -pe <PE file>\n");
}

void errorHandling() {
	printf("Error Code: %d\n", GetLastError());
}
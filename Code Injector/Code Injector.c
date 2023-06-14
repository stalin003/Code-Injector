#include <stdio.h>
#include <Windows.h>


void init(int, char*);
void usuage();

TCHAR filePath[100];

int main(int argc, char* argv[])
{
	init(argc, argv);
}


void init(int argc, char* argv[]) {
	if (argc == 5) {
		if (strcmp(argv[1], "-p") != 0 || strcmp(argv[3], "-pe") != 0) {
			usuage();
		}
		else
		{
			printf("path: %s\n", argv[4]);

			swprintf(filePath, sizeof(filePath), L"%hs", argv[4]);

			HANDLE hFile = INVALID_HANDLE_VALUE;

			hFile = CreateFile(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, NULL, NULL);

			if (hFile != INVALID_HANDLE_VALUE) {
				printf("success opening file");

				CloseHandle(hFile);
			}
			else {
				if (GetLastError() == ERROR_FILE_NOT_FOUND) {
					printf("File not found");
				}
			}
		}
	}
	else
	{
		usuage();
	}
}

void usuage() {
	printf("Usuage: Code Injector.exe -p <raw payload file> -pe <PE file>\n");
}

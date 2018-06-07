#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <windows.h>

#define N 20
#define NAME_LOG "log.txt"

#define HEADER (48)

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

#define PATH_TO_CONFIG(x) "config_" STRINGIZE(x)
#define PATH_TO_CONFIG_DEF(x) "config_" STRINGIZE(x) "_default"
#define PATH_TO_VULN(x) "vuln" STRINGIZE(x) ".exe"

char * path_config = PATH_TO_CONFIG(N);
char * path_config_default = PATH_TO_CONFIG_DEF(N);
char * path_vuln = PATH_TO_VULN(N);

std::string changes = "";


void Get_Registers_State(CONTEXT *cont, const char *error, HANDLE hProcess)
{
	unsigned char buffer[4048] = { 0 };
	SIZE_T recvSize = 0;

	FILE * file = fopen(NAME_LOG, "a");

	fprintf(file, "Exception: %s\n", error);
	//fprintf(file, "offset: %d  value: 0x%x  count: %d\n", g_offset, g_value, g_count);
	fprintf(file, "%s", changes.c_str());

	fprintf(file, "EAX  :  0x%p   ESP  :  0x%p\n", (void *)cont->Eax, (void *)cont->Esp);
	fprintf(file, "EBX  :  0x%p   EBP  :  0x%p\n", (void *)cont->Ebx, (void *)cont->Ebp);
	fprintf(file, "ECX  :  0x%p   EDI  :  0x%p\n", (void *)cont->Ecx, (void *)cont->Edi);
	fprintf(file, "EDX  :  0x%p   ESI  :  0x%p\n", (void *)cont->Edx, (void *)cont->Esi);
	fprintf(file, "EIP  :  0x%p   FLG  :  0x%p\n", (void *)cont->Eip, (void *)cont->EFlags);

	// читаем из памяти по указателю на вершину стека (ESP) 
	ReadProcessMemory(hProcess, (void *)cont->Esp, buffer, sizeof(buffer), &recvSize);

	if (recvSize != 0)
	{
		std::cout << "Stack: " << recvSize << " bytes read" << std::endl;

		fprintf(file, "\nStack (%d bytes read):\n", recvSize);

		for (int i = 0; i < recvSize; i++)
		{
			if ((i + 1) % 4 == 1)
			{
				fprintf(file, "0x%p : ", (void *)((char *)cont->Esp + i));
			}

			if (buffer[i] < 0x10)
			{
				fprintf(file, "0");
			}

			fprintf(file, "%X ", (int)buffer[i]);
			//cout << hex << uppercase << (int)buffer[i]; 

			if ((i + 1) % 4 == 0)
			{
				fprintf(file, "\n");
			}
		}
	}
	else
	{
		std::cout << "ReadProcessMemory failed: " << GetLastError() << std::endl;
	}

	fprintf(file, "--------------------------------\n\n");
	fclose(file);
}

void Show_Bytes()
{
	unsigned char *byteBuffer;
	int size;
	FILE * pConfFile = fopen(path_config, "rb");
	if (pConfFile == nullptr)
	{
		std::cout << "file did not open" << std::endl;
		return;
	}

	fseek(pConfFile, 0, SEEK_END);
	size = ftell(pConfFile);
	rewind(pConfFile);

	byteBuffer = new unsigned char[size];
	if (byteBuffer == nullptr)
	{
		std::cout << "memory is not allocated" << std::endl;
		return;
	}

	int result = fread(byteBuffer, sizeof(unsigned char), size, pConfFile);
	if (result != size)
	{
		std::cout << "fread returned " << result << std::endl;
		return;
	}

	fclose(pConfFile);

	int i;
	std::cout << "\t";
	for (i = 0; i < 0x10; i++)
	{
		std::cout << std::hex << '0' << i << " ";
	}
	std::cout << std::endl << "00:\t";

	for (i = 0; i < size; i++)
	{
		if (byteBuffer[i] < 0x10)
		{
			std::cout << "0";
		}
		std::cout << std::hex << std::uppercase << (int)byteBuffer[i] << " ";

		if ((i + 1) % 0x10 == 0)
		{
			std::cout << std::endl << (i + 1) / 0x10 << "0" << ":\t";
		}
	}

	std::cout << std::endl;
	delete[] byteBuffer;
}

void Change_Byte(int offset, unsigned char new_value)
{
	FILE * pConfFile = fopen(path_config, "r+b");
	if (pConfFile == nullptr) 
	{
		std::cout << "file did not open" << std::endl;
		return;
	}

	//g_count = 1;
	//g_value = new_value;
	//g_offset = offset;

	char _res[5] = { 0 };

	changes += "offset: " + std::to_string(offset);
	changes += " value: ";
	std::sprintf(_res, "0x%x", new_value);
	changes += _res;
	changes += "\n";

	//changes += "offset: " + std::to_string(offset);
	//changes += " value: " + std::to_string(new_value) + "\n";
	

	fseek(pConfFile, offset, SEEK_SET);
	fputc(new_value, pConfFile);
	fclose(pConfFile);
}
	 
void Change_Few_Bytes(int offset, int count, unsigned char new_value)
{
	FILE * pConfFile = fopen(path_config, "r+b");
	if (pConfFile == nullptr)
	{
		std::cout << "file did not open" << std::endl;
		return;
	}

	//g_count = count;
	//g_value = new_value;
	//g_offset = offset;

	char _res[MAX_PATH] = { 0 };

	changes += "offset: " + std::to_string(offset);
	changes += " value: ";
	std::sprintf(_res, "0x%x", new_value);
	changes += _res;
	changes += " count: ";
	std::sprintf(_res, "0x%x", count);
	changes += "\n";
	
	//changes += "offset: " + std::to_string(offset);
	//changes += " value: " + std::to_string(new_value);
	//changes += " count: " + std::to_string(count) + "\n";


	fseek(pConfFile, offset, SEEK_SET);

	for (int i = 0; i < count; i++)
	{
		fputc(new_value, pConfFile);
	}
	
	fclose(pConfFile);
}

void Write_To_End(int count, unsigned char new_value)
{
	FILE * pConfFile = fopen(path_config, "r+b");
	if (pConfFile == nullptr)
	{
		std::cout << "file did not open" << std::endl;
		return;
	}

	fseek(pConfFile, 0, SEEK_END);

	for (int i = 0; i < count; i++)
	{
		fputc(new_value, pConfFile);
	}

	fclose(pConfFile);
}

void Run_Program()
{
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	DEBUG_EVENT debug_event = { 0 };
	HANDLE thread;
	CONTEXT cont;

	BOOL status;

	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	status = CreateProcessA(path_vuln, NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi);
	if (status == false)
	{
		std::cout << "CreateProcess failed: " << std::dec << GetLastError() << std::endl;
		return;
	}

	while (true)
	{
		// ожидаем событие отладки
		status = WaitForDebugEvent(&debug_event, 500);
		if (status == false)
		{
			if (GetLastError() != ERROR_SEM_TIMEOUT)
				std::cout << "WaitForDebugEvent failed: " << std::dec << GetLastError() << std::endl;
			break;
		}

		// смотрим код события
		if (debug_event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
		{
			// если это не исключение - продолжаем ожидать
			ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
			continue;
		}

		// получаем хэндл потока, в котором произошло событие отладки
		thread = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);
		if (thread == NULL)
		{
			std::cout << "OpenThread failed: " << std::dec << GetLastError() << std::endl;
			break;
		}

		cont.ContextFlags = CONTEXT_FULL;

		// по хэндлу получаем его контекст
		status = GetThreadContext(thread, &cont);
		if (status == false)
		{
			std::cout << "GetThreadContext failed: " << std::dec << GetLastError() << std::endl;
			CloseHandle(thread);
			break;
		}

		switch (debug_event.u.Exception.ExceptionRecord.ExceptionCode)
		{
		case EXCEPTION_ACCESS_VIOLATION:
			// попытка чтения или записи защищенной памяти
			// std::cout << "Access Violation" << std::endl;
			Get_Registers_State(&cont, "Access Violation", pi.hProcess);
			break;
		case EXCEPTION_STACK_OVERFLOW:
			// std::cout << "Stack overflow" << std::endl;
			Get_Registers_State(&cont, "Stack overflow", pi.hProcess);
			break;
		default:
			std::cout << "Unknown exception: " << std::dec << debug_event.u.Exception.ExceptionRecord.ExceptionCode << std::endl;
			ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
		}
	}

	CloseHandle(pi.hProcess);
}

void Return_Default_Version()
{
	BOOL res = CopyFileA(path_config_default, path_config, false);
	if (res == false)
	{
		std::cout << "CopyFileA failed: " << std::dec << GetLastError() << std::endl;
	}

	changes = "";
}

void Find_Boundary_Symbol(char symbol)
{
	int position = -1;
	int counter = 0;
	int size;
	FILE * pConfFile = fopen(path_config, "rb");
	if (pConfFile == nullptr)
	{
		std::cout << "file did not open" << std::endl;
		return;
	}

	fseek(pConfFile, 0, SEEK_END);
	size = ftell(pConfFile);
	rewind(pConfFile);

	for (int i = 0; i < size; i++)
	{
		if (fgetc(pConfFile) == symbol)
		{
			counter++;
			position = i;
		}
	}

	std::cout << "symbol : " << symbol << "  counter : " << counter << "  position : " << position << std::endl;
	fclose(pConfFile);
}

void Auto_Fuzzing(int new_value, int mode)
{
	switch (mode)
	{
	case 1:
		for (int i = 1; i < HEADER; i++)
		{
			Change_Byte(i, new_value);
			Run_Program();
			Return_Default_Version();
		}
		break;
	case 2:
		for (int i = 2; i < HEADER; i += 2)
		{
			Change_Byte(i, new_value >> 8);
			Change_Byte(i + 1, (unsigned char)new_value);
			Run_Program();
			Return_Default_Version();
		}
		break;
	case 3:
		for (int i = 4; i < HEADER; i += 4)
		{
			Change_Byte(i, new_value >> 24);
			Change_Byte(i + 1, new_value >> 16);
			Change_Byte(i + 2, new_value >> 8);
			Change_Byte(i + 3, (unsigned char)new_value);
			Run_Program();
			Return_Default_Version();
		}
		break;
	default:
		std::cout << "Invalid mode" << std::endl;
	}
}

void Compare_Configs()
{
	int compare_arr[HEADER] = { 0 }; // все поля одинаковвые
	int byte[HEADER] = { 0 };

	FILE *pFileConf;
	int i;

	pFileConf = fopen(path_config, "rb");
	if (pFileConf == nullptr)
	{
		std::cout << "fopen failed" << std::endl;
		return;
	}
	for (i = 0; i < HEADER; i++)
	{
		byte[i] = fgetc(pFileConf);
	}
	fclose(pFileConf);

	char *path_to_conf = new char[strlen(path_config) + 1];
	int len = strlen(path_config);
	strncpy(path_to_conf, path_config, len + 1);
	path_to_conf[len - 1] = 0;
	path_to_conf[len - 2] = '1';

	for (i = 2; i < 10; i++) // сравним 10 конфигов
	{
		path_to_conf[len - 2] = i + '0';
		pFileConf = fopen(path_to_conf, "rb");
		//printf("path: %s\n", path_to_conf);
		if (pFileConf == nullptr)
		{
			std::cout << "fopen failed" << std::endl;
			return;
		}

		int j;
		for (j = 0; j < HEADER; j++)
		{
			if (byte[j] != fgetc(pFileConf))
			{
				// разные поля помечаются единицей
				compare_arr[j] = 1;
			}
		}

		fclose(pFileConf);
	}

	std::cout << "Follow bytes matched: " << std::endl << std::endl;

	std::cout << "   ";
	for (int i = 0; i < 0x10; i++)
	{
		std::cout << std::hex << " " << '0' << i;
	}
	std::cout << std::endl << "00: ";

	for (int i = 0; i < HEADER; i++)
	{
		std::cout << "0" << compare_arr[i] << " ";

		if ((i + 1) % 0x10 == 0)
		{
			std::cout << std::endl << (i + 1) / 0x10 << "0" << ": ";
		}
	}
	std::cout << "BUFFER" << std::endl;

	std::cout << std::endl;
}


#define AVAILABLE_COMMANDS \
"1. Show config file bytes\n\
2. Change one byte\n\
3. Change a few bytes\n\
4. Write to the end\n\
5. Run vuln.exe\n\
6. Return default version of config file\n\
7. Find boundary symbols\n\
8. Auto fuzzing\n\
9. Compare config files\n\
0. Exit"

void ProcessRequest(int command)
{
	int offset, value, count, mode;

	unsigned int values[] = {
		0x00,
		0xFF,
		0xFF / 2,
		0xFF / 2 - 1,
		0xFF / 2 + 1,
		0x0000,
		0xFFFF,
		0xFFFF / 2,
		0xFFFF / 2 - 1,
		0xFFFF / 2 + 1,
		0x00000000,
		0xFFFFFFFF,
		0xFFFFFFFF / 2,
		0xFFFFFFFF / 2 - 1,
		0xFFFFFFFF / 2 + 1,
	};

	switch (command)
	{
	case 1:
		Show_Bytes();
		break;
	case 2:
		std::cout << "Offset : ";
		std::cin >> std::dec >> offset;

		std::cout << "Value  : ";
		std::cin >> std::hex >> value;

		Change_Byte(offset, value);
		break;
	case 3:
		std::cout << "Offset (dec) : ";
		std::cin >> std::dec >> offset;

		std::cout << "Count (dec) : ";
		std::cin >> std::dec >> count;

		std::cout << "Value (hex) : ";
		std::cin >> std::hex >> value;

		Change_Few_Bytes(offset, count, value);
		break;
	case 4:
		std::cout << "Count (dec) : ";
		std::cin >> std::dec >> count;
		std::cout << "Value (hex) : ";
		std::cin >> std::hex >> value;

		Write_To_End(count, value);
		break;
	case 5:
		Run_Program();
		break;
	case 6:
		Return_Default_Version();
		break;
	case 7:
		Find_Boundary_Symbol(',');
		Find_Boundary_Symbol(':');
		Find_Boundary_Symbol('=');
		Find_Boundary_Symbol(';');
		break;
	case 8:
		for (int i = 0; i < 3; i++)
		{
			for (int j = 0; j < 5; j++)
			{
				Auto_Fuzzing(values[i * 5 + j], i + 1);
			}
		}
		break;
	case 9:
		Compare_Configs();
		break;
	default:
		std::cout << "Invalid request" << std::endl;
	}
}

int main()
{
	int select;

	std::cout << AVAILABLE_COMMANDS << std::endl << std::endl;

	while (true)
	{
		std::cout << "Enter: ";
		std::cin >> select;

		if (select == 0)
			break;

		ProcessRequest(select);

		std::cout << std::endl << AVAILABLE_COMMANDS << std::endl << std::endl;
	}

	return 0;
}

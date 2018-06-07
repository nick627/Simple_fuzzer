// > C:\Users\Nick\Downloads\pinmsvc11\pin.exe -t C:\Users\Nick\Downloads\Models\6\Project_Fuzzer\coverager.dll -- vuln20.exe

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <windows.h>

#define N 20

#define NAME_LOG "log_reg"
#define NAME_LOG_TXT ".txt"

#define HEADER (48)

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

#define PATH_TO_CONFIG(x) "config_" STRINGIZE(x)
#define PATH_TO_CONFIG_DEF(x) "config_" STRINGIZE(x) "_default"
#define PATH_TO_VULN(x) "vuln" STRINGIZE(x) ".exe"

char * path_config = PATH_TO_CONFIG(N);
char * path_config_default = PATH_TO_CONFIG_DEF(N);
char * path_vuln = PATH_TO_VULN(N);

#define PATH_TO_PIN          "C:\\Users\\Nick\\Downloads\\pinmsvc11\\pin.exe -t "
//#define PATH_TO_DLL_FOR_PIN  "C:\\Users\\Nick\\Downloads\\Models\\6\\Project_Fuzzer\\coverager.dll -- "
#define PATH_TO_DLL_FOR_PIN  "..\\coverager.dll -d logs\\log_"
#define PATH_TO_DLL_FOR_PIN_ADD  " -- "

//char * path_to_pin_dll = PATH_TO_PIN PATH_TO_DLL_FOR_PIN PATH_TO_DLL_FOR_PIN_ADD PATH_TO_VULN(N);

int g_count_for_pin = -1;

FILE * g_statisctic;

int g_count_blocks = 0;
int g_count_total_size = 0;

int past_g_count_blocks = MAXINT;
int past_g_count_total_size = MAXINT;

bool g_flag_for_pin = false;

std::string changes = "";

void Get_Registers_State(CONTEXT *cont, const char *error, HANDLE hProcess)
{
	unsigned char buffer[4048] = { 0 };
	SIZE_T recvSize = 0;

	std::string new_name_log = "logs\\log_" + std::to_string(g_count_for_pin) + "\\";
	new_name_log += NAME_LOG NAME_LOG_TXT;
	//std::string new_name_log = NAME_LOG NAME_LOG_TXT;

	FILE * file = fopen(new_name_log.c_str(), "wb");
	
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


void MySystem(const char *szPath)
{
	STARTUPINFO si;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi;
	memset(&pi, 0, sizeof(pi));

	DEBUG_EVENT debug_event = { 0 };

	bool result = false;
	if (CreateProcess(NULL, (LPSTR)szPath, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		DWORD dwWait = WaitForSingleObject(pi.hProcess, INFINITE);
		if (dwWait == WAIT_OBJECT_0)
		{
			result = true;
		}

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
}


void Parsing_Pin_Log(const char * input_file)
{
	// Parsing_pin_log

	FILE    *infile;
	char    *buffer;
	long    numbytes;

	// open an existing file for reading
	infile = fopen(input_file, "r");

	// quit if the file does not exist
	if (infile == NULL)
	{
		std::cout << "File does not exist: " << std::dec << GetLastError() << std::endl;
		return;
	}

	// Get the number of bytes
	fseek(infile, 0L, SEEK_END);
	numbytes = ftell(infile);

	// reset the file position indicator to	the beginning of the file
	fseek(infile, 0L, SEEK_SET);

	// grab sufficient memory for the buffer to hold the text
	buffer = (char*)calloc(numbytes, sizeof(char));

	// memory error
	if (buffer == NULL)
	{
		std::cout << "Memory error: " << std::dec << GetLastError() << std::endl;
		return;
	}

	// copy all the text into the buffe
	fread(buffer, sizeof(char), numbytes, infile);
	fclose(infile);

	// confirm we have read the file by outputing it to the console
	printf("The file called test.dat contains this text\n\n%s", buffer);

	char *copy_buffer = _strdup(buffer);

	char *istr = strstr(copy_buffer, "blocks = ");

	char *istr1 = strtok(istr, " ");
	istr1 = strtok(NULL, " ");
	istr1 = strtok(NULL, " ");

	//free(copy_buffer);
	copy_buffer = _strdup(buffer);

	char *istr_total = strstr(copy_buffer, "total_size = ");

	char *istr1_total = strtok(istr_total, " ");
	istr1_total = strtok(NULL, " ");
	istr1_total = strtok(NULL, " ");

	// free the memory we used for the buffer
	free(buffer);


	g_count_blocks = atoi(istr1);
	g_count_total_size = atoi(istr1_total);

	
	


	//free(istr1_total);	free(istr_total);
	//free(istr1);	free(istr);
	//free(copy_buffer);
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

	//----------------------------------------------------------
	//----------------------------------------------------------
	
	std::string new_dir_log = "mkdir logs\\log_" + std::to_string(g_count_for_pin);
	system(new_dir_log.c_str());

	std::string path_to_pin_dll = PATH_TO_PIN PATH_TO_DLL_FOR_PIN + std::to_string(g_count_for_pin) + PATH_TO_DLL_FOR_PIN_ADD PATH_TO_VULN(N);
	MySystem(path_to_pin_dll.c_str());

	Parsing_Pin_Log(("logs\\log_" + std::to_string(g_count_for_pin) + "\\coverager.log").c_str());
	
	g_statisctic = fopen("logs\\statistic.txt", "ab");

	if (g_count_blocks >= past_g_count_blocks && g_count_total_size != past_g_count_total_size)
	{
		fclose(g_statisctic);

		g_count_for_pin++;

		return;
	}


	past_g_count_blocks = g_count_blocks;
	past_g_count_total_size = g_count_total_size;

	fprintf(g_statisctic, "#log_%d;\t%d;\t%d;\n", g_count_for_pin, g_count_blocks, g_count_total_size);

	g_flag_for_pin = true;


	//BOOL res = CopyFileA(path_config_default, path_config, false);
	BOOL res = CopyFileA(path_config, path_config_default, false);
	if (res == false)
	{
		std::cout << "CopyFileA failed: " << std::dec << GetLastError() << std::endl;
	}

	changes = "";

	//----------------------------------------------------------
	//----------------------------------------------------------

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
			Get_Registers_State(&cont, "Access Violation", pi.hProcess);

			//MySystem(path_to_pin_dll.c_str());
			//Parsing_Pin_Log(("logs\\log_" + std::to_string(g_count_for_pin) + "\\coverager.log").c_str());
			
			fprintf(g_statisctic, "\t\tAccess Violation;\n");

			break;
		case EXCEPTION_STACK_OVERFLOW:
			Get_Registers_State(&cont, "Stack overflow", pi.hProcess);

			//MySystem(path_to_pin_dll.c_str());
			//Parsing_Pin_Log(("logs\\log_" + std::to_string(g_count_for_pin) + "\\coverager.log").c_str());

			fprintf(g_statisctic, "\t\tStack overflow;\n");

			break;
		default:
			std::cout << "Unknown exception: " << std::dec << debug_event.u.Exception.ExceptionRecord.ExceptionCode << std::endl;

			//fprintf(stat, "\t--Unknown exception\n");
			//fprintf(stat, "\n");

			ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
		}
	}

	fclose(g_statisctic);

	g_count_for_pin++;

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


			if (g_flag_for_pin == true)
			{
				g_flag_for_pin = false;
				g_statisctic = fopen("logs\\statistic.txt", "ab");
				fprintf(g_statisctic, "\t\t(offset %d, value %d)\n", i, new_value);
				fclose(g_statisctic);
			}
		}
		break;
	case 2:
		for (int i = 2; i < HEADER; i += 2)
		{
			Change_Byte(i, new_value >> 8);
			Change_Byte(i + 1, (unsigned char)new_value);
			Run_Program();
			Return_Default_Version();


			if (g_flag_for_pin == true)
			{
				g_flag_for_pin = false;
				g_statisctic = fopen("logs\\statistic.txt", "ab");
				fprintf(g_statisctic, "\t\t(offset %d, value %d)\n", i, new_value);
				fclose(g_statisctic);
			}
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


			if (g_flag_for_pin == true)
			{
				g_flag_for_pin = false;
				g_statisctic = fopen("logs\\statistic.txt", "ab");
				fprintf(g_statisctic, "\t\t(offset %d, value %d)\n", i, new_value);
				fclose(g_statisctic);
			}
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

	std::string path_to_pin_dll = PATH_TO_PIN PATH_TO_DLL_FOR_PIN + std::to_string(g_count_for_pin) + PATH_TO_DLL_FOR_PIN_ADD PATH_TO_VULN(N);
	
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

		// Get start count coverage code
		system(("mkdir logs\\log_" + std::to_string(g_count_for_pin)).c_str());
		//MySystem((PATH_TO_PIN PATH_TO_DLL_FOR_PIN + std::to_string(g_count_for_pin) + PATH_TO_DLL_FOR_PIN_ADD PATH_TO_VULN(N)).c_str);

		//C:\Users\Nick\Downloads\pinmsvc11\pin.exe -t coverager.dll -d logs\log_# -- vuln20.exe
		MySystem(path_to_pin_dll.c_str());
		Parsing_Pin_Log(("logs\\log_" + std::to_string(g_count_for_pin) + "\\coverager.log").c_str());
		
		g_statisctic = fopen("logs\\statistic.txt", "ab");
		fprintf(g_statisctic, "#log_%d;\t%d;\t%d;\n", g_count_for_pin, g_count_blocks, g_count_total_size);
		fclose(g_statisctic);

		g_count_for_pin++;

		past_g_count_blocks = g_count_blocks;
		past_g_count_total_size = g_count_total_size;

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
	system("mkdir logs");
	
	g_statisctic = fopen("logs\\statistic.txt", "wb");
	fprintf(g_statisctic, "For each run, the folder \"log_#\" is created, \
in the folder the files are \"covere*\" - code coverage, \
if there is a file log_reg.txt - was exception\
\n#log_#;\tblocks;\ttotal_size;\n");
	fclose(g_statisctic);

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

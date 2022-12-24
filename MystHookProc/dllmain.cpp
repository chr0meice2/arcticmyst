#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <atomic>
#if __x86_64__
  #include "C:/msys64/mingw64/include/MinHook.h"
#else
  #include "C:/msys64/mingw32/include/MinHook.h"
#endif

//64 bit
/*
g++ -Ofast -s -std=c++17 -static-libgcc  -static-libstdc++ -mwindows -m64   T:/deeptide/mysthookproc/dllmain.cpp  -o T:/deeptide/mysthookproc/mysthookproc64.dll c:/msys64/mingw64/lib/libMinHook.a C:/msys64/mingw64/lib/libwinpthread.a C:/msys64/mingw64/lib/libwinpthread.a c:/msys64/mingw64/lib/libstdc++.a c:/msys64/mingw64/lib/libpthread.a c:/msys64/mingw64/lib/libcrypt32.a c:/msys64/mingw64/lib/gcc/x86_64-w64-mingw32/12.2.0/libgcc.a C:/msys64/mingw64/lib/gcc/x86_64-w64-mingw32/12.2.0/libgcc_eh.a    -w -Wfatal-errors  -fpermissive -shared -Wl,-Bstatic,-lwinpthread -Wl,--no-whole-archive,--stack,1048576,--gc-sections
*/
//32 bit
/*
g++ -Ofast -s -std=c++17 -static-libgcc  -static-libstdc++ -mwindows -m32   T:/deeptide/mysthookproc/dllmain.cpp  -o T:/deeptide/mysthookproc/mysthookproc32.dll c:/msys64/mingw32/lib/libMinHook.a C:/msys64/mingw32/lib/libwinpthread.a C:/msys64/mingw32/lib/libwinpthread.a c:/msys64/mingw32/lib/libstdc++.a c:/msys64/mingw32/lib/libpthread.a c:/msys64/mingw32/lib/libcrypt32.a c:/msys64/mingw32/lib/gcc/i686-w64-mingw32/12.2.0/libgcc.a C:/msys64/mingw32/lib/gcc/i686-w64-mingw32/12.2.0/libgcc_eh.a    -w -Wfatal-errors  -fpermissive -shared -Wl,-Bstatic,-lwinpthread -Wl,--no-whole-archive,--stack,1048576,--gc-sections,--kill-at
*/

	#define PS_ATTRIBUTE_CLIENT_ID 0x10003

	typedef struct _PS_ATTRIBUTE
	{
		ULONG_PTR Attribute;                // PROC_THREAD_ATTRIBUTE_XXX | PROC_THREAD_ATTRIBUTE_XXX modifiers, see ProcThreadAttributeValue macro and Windows Internals 6 (372)
		SIZE_T Size;                        // Size of Value or *ValuePtr
		union
		{
			ULONG_PTR Value;                // Reserve 8 bytes for data (such as a Handle or a data pointer)
			PVOID ValuePtr;                 // data pointer
		};
		PSIZE_T ReturnLength;               // Either 0 or specifies size of data returned to caller via "ValuePtr"
	} PS_ATTRIBUTE, * PPS_ATTRIBUTE;


	typedef struct _PS_ATTRIBUTE_LIST
	{
		SIZE_T TotalLength;                 // sizeof(PS_ATTRIBUTE_LIST)
		PS_ATTRIBUTE Attributes[0];         // Depends on how many attribute entries should be supplied to NtCreateUserProcess
	} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

static std::string ws2s( const std::wstring &wstr );

DWORD __stdcall SendMessageThread(LPVOID l);



typedef NTSTATUS (NTAPI *pNtCreateUserProcess)(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	LPVOID ProcessObjectAttributes,
	LPVOID ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	LPVOID CreateInfo,
	PPS_ATTRIBUTE_LIST AttributeList
);

pNtCreateUserProcess pOriginalNtCreateUserProcess;


NTSTATUS NTAPI NtCreateUserProcess(PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	LPVOID ProcessObjectAttributes,
	LPVOID ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	LPVOID CreateInfo,
	PPS_ATTRIBUTE_LIST AttributeList);




static std::atomic<bool> UnhookNeeded=false;
static std::atomic<bool> CleanupNeeded=false;

#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000200 
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x1


NTSTATUS (NTAPI NtCreateUserProcess)(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	LPVOID ProcessObjectAttributes,
	LPVOID ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	LPVOID CreateInfo,
	PPS_ATTRIBUTE_LIST AttributeList
	)
{
	
	
	DWORD mypid=1 , mytid=0;	
		
	//if theres already a flag to suspend then we dont need to do anything
	//but that means we should NOT resume it either because the caller will do it later	
	if (ThreadFlags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED) {
		//OutputDebugStringA("Process is being created suspended.");
		mytid = 1;
	} else {
		//make the thread start paused;
		ThreadFlags |= THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
		//OutputDebugStringA("Process is being created normally.");
	}	
	
	
	
		NTSTATUS ReturnValue = pOriginalNtCreateUserProcess(ProcessHandle,
			ThreadHandle,
			ProcessDesiredAccess,
			ThreadDesiredAccess,
			ProcessObjectAttributes,
			ThreadObjectAttributes,
			ProcessFlags,
			ThreadFlags,
			ProcessParameters,
			CreateInfo,
			AttributeList
		);
		
		if (ReturnValue != STATUS_SUCCESS) { 
			//char msg[64];
			//sprintf(msg,"CreateUserProcess Failed error: %X",ReturnValue);
			//OutputDebugStringA(msg);
			return ReturnValue; 
		}


		
		std::string ipn_s;
		std::string cmd_s;
		std::wstring ipn;
		std::wstring cmd;
		std::string *SensitivePacket;
		//std::string mypid="9292";
		
		for ( int N=0 ; N < ((AttributeList->TotalLength)/sizeof(PS_ATTRIBUTE)) ; N++ ) {
			if ((AttributeList->Attributes[N].Attribute) == PS_ATTRIBUTE_CLIENT_ID) {
				DWORD* pPID = (DWORD*)(AttributeList->Attributes[N].ValuePtr);
				//if (!IsBadReadPtr( pPID , sizeof(DWORD) )) {
					mypid = *pPID; 
				//} else { 
					//mypid = 1; 
				//}								
				break;
			}
		}

		
		if ( (ThreadHandle) && (mytid==0) ) {
			//myReal_NtSuspendThread( *ThreadHandle , NULL );
			mytid = GetThreadId(*ThreadHandle);
		}
		

		HANDLE ll=0;
		
		//DWORD err=0;
		
		//stack fart
		ipn = ProcessParameters->ImagePathName.Buffer;
		if(ipn.empty() )
		{
				//OutputDebugStringA("Empty Image path.");				
						return ReturnValue;
		}
		ipn_s=ws2s(ipn);
		if(ipn_s.empty() )
		{
				//OutputDebugStringA("wide string conversion failed.");
					return ReturnValue;
		}
		
		
		cmd= ProcessParameters->CommandLine.Buffer;
		if(cmd.empty() )
		{
				//OutputDebugStringA("Empty command line.");				
				return ReturnValue;
		}
		cmd_s=ws2s(cmd);
		if(cmd_s.empty() )
		{
				//OutputDebugStringA("wide string conversion failed.");
				return ReturnValue;
		}


		SensitivePacket=new std::string();
		if(SensitivePacket==nullptr)
		{
				return ReturnValue;
		}
		*SensitivePacket=ipn_s+"\x01"+cmd_s+"\x01"+std::to_string(mypid)+"\x01"+std::to_string(mytid);
		

		
		ll=CreateThread(0,0,SendMessageThread,SensitivePacket,0,0);
		if( ll==0)
		{

			delete SensitivePacket;
			return ReturnValue;
		}

		CloseHandle( ll);	


		



	return ReturnValue;

}

DWORD __stdcall SendMessageThread(LPVOID lp)
{
	
		std::string *SensitivePacket=static_cast<void*>(lp);
		DWORD cbSensitiveText = 0;
		

		COPYDATASTRUCT cds;
		HWND hwnd=0;	
	
		cbSensitiveText = (SensitivePacket->size()*sizeof(CHAR)+1);
		

		cbSensitiveText = (cbSensitiveText | (CRYPTPROTECTMEMORY_BLOCK_SIZE-1))+1;

		SensitivePacket->resize(cbSensitiveText); 		
		

				
		if (!CryptProtectMemory(SensitivePacket->data(), cbSensitiveText,
			CRYPTPROTECTMEMORY_CROSS_PROCESS))
		{
	
			SecureZeroMemory(SensitivePacket->data(), cbSensitiveText);
			delete SensitivePacket;
			return 0;
		}		
		

		if(SensitivePacket->empty() )
		{
		
			delete SensitivePacket;				
			return 0;			
			
		}
						
		cds.dwData = 91; 
		cds.cbData = cbSensitiveText;
		cds.lpData = SensitivePacket->data();
		hwnd=FindWindowA("TideSecOps","TideSecOps");
		if(hwnd==NULL)
		{
			SecureZeroMemory(SensitivePacket->data(), cbSensitiveText);	
			delete SensitivePacket;			
			return 0;	
		}
		SetLastError(0);
		
		SendMessageA(hwnd, WM_COPYDATA, (WPARAM)hwnd, (LPARAM)(LPVOID)&cds);
		
		SecureZeroMemory(SensitivePacket->data(), cbSensitiveText);
		
		delete SensitivePacket;

	return 0;
}


extern "C" __declspec(dllexport) WINAPI void SafeUnhookCRT(void *Dummylol)
{




	FreeLibraryAndExitThread(Dummylol,0);

}




DWORD __stdcall ProcAttachThread(LPVOID l)
{
	

	
	if (MH_Initialize() != MH_OK)
    {
        return 0;
    }
	
	
   MH_STATUS status = MH_CreateHookApi(L"ntdll", "NtCreateUserProcess", NtCreateUserProcess, 
                                           reinterpret_cast<LPVOID*>(&pOriginalNtCreateUserProcess)); 
	
	if(status!=MH_OK)
	{
			CleanupNeeded=true;
			return 0;
	}

	status = MH_EnableHook(MH_ALL_HOOKS);
	
	if(status!=MH_OK)
	{
		CleanupNeeded=true;
		return 0;
	}
	
	CleanupNeeded=true;
	UnhookNeeded=true;
		
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved)
{
	

	switch(fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		{			
			

		DisableThreadLibraryCalls(hinstDLL);

        HANDLE hThread = CreateThread(nullptr, 0, ProcAttachThread, nullptr, 0, nullptr);
        if (hThread != nullptr) {
            CloseHandle(hThread);
		}


			break;
		}
		case DLL_PROCESS_DETACH:
		{


			if(UnhookNeeded)
			{
				MH_DisableHook(MH_ALL_HOOKS);
			}


			if(CleanupNeeded)
			{
				MH_Uninitialize();
			
			}

	

			break;
		}
		case DLL_THREAD_ATTACH:
		{
			break;
		}
		case DLL_THREAD_DETACH:
		{
			break;
		}
	}
	
	/* Return TRUE on success, FALSE on failure */
	return TRUE;
}



static std::string ws2s( const std::wstring &wstr )
{
    // get length
    int length = WideCharToMultiByte( CP_UTF8, 0,wstr.c_str(), wstr.size(),   NULL, 0,  NULL, NULL );
    if( !(length > 0) )
	{
        return std::string();
	}
    else
    {

        std::string result;
        result.resize( length );
		if(result.empty() )
		{
			return std::string();
		}

        if( WideCharToMultiByte( CP_UTF8, 0,wstr.c_str(), wstr.size(), &result[0], result.size(),NULL, NULL ) > 0 )
        {
			return result;
		}
        else
		{
            return std::string();
		}

    }

   return std::string();

}






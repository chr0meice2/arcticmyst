#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <atomic>
#include "c:/mhook-master/mhook-lib/mhook.h"


// 64bit compilation method
// g++ -Ofast -s -std=c++17 -static-libgcc  -static-libstdc++ -mwindows -m64 c:/mhook-master/mhook-lib/mhook.c c:/mhook-master/disasm-lib/disasm.c c:/mhook-master/disasm-lib/disasm_x86.c  c:/mhook-master/disasm-lib/cpu.c T:/deeptide/mysthookproc/dllmain.cpp  -o T:/deeptide/mysthookproc/mysthookproc64.dll C:/msys64/mingw64/lib/libwinpthread.a c:/msys64/mingw64/lib/libstdc++.a c:/msys64/mingw64/lib/libpthread.a c:/msys64/mingw64/lib/libcrypt32.a c:/msys64/mingw64/lib/gcc/x86_64-w64-mingw32/12.2.0/libgcc.a C:/msys64/mingw64/lib/gcc/x86_64-w64-mingw32/12.2.0/libgcc_eh.a    -w -Wfatal-errors  -fpermissive -shared -Wl,-Bstatic,-lwinpthread -Wl,--no-whole-archive,--stack,1048576,--gc-sections


// 32bit compilation method
// g++ -Ofast -s -std=c++17 -static-libgcc  -static-libstdc++ -mwindows -m32 c:/mhook-master/mhook-lib/mhook.c c:/mhook-master/disasm-lib/disasm.c c:/mhook-master/disasm-lib/disasm_x86.c  c:/mhook-master/disasm-lib/cpu.c T:/deeptide/mysthookproc/dllmain.cpp  -o T:/deeptide/mysthookproc/mysthookproc32.dll C:/msys64/mingw32/lib/libwinpthread.a c:/msys64/mingw32/lib/libstdc++.a c:/msys64/mingw32/lib/libpthread.a c:/msys64/mingw32/lib/libcrypt32.a c:/msys64/mingw32/lib/gcc/i686-w64-mingw32/12.2.0/libgcc.a C:/msys64/mingw32/lib/gcc/i686-w64-mingw32/12.2.0/libgcc_eh.a   -w -Wfatal-errors  -fpermissive -shared -Wl,-Bstatic,-lwinpthread -Wl,--no-whole-archive,--stack,1048576,--gc-sections,--kill-at

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

NTSTATUS (NTAPI Real_NtCreateUserProcess)(
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

static decltype(Real_NtCreateUserProcess) *myReal_NtCreateUserProcess=nullptr;

/*
NTSTATUS (NTAPI Real_NtSuspendThread)(	
	PHANDLE ThreadHandle,	
	PULONG SuspendCount
	);

static decltype(Real_NtSuspendThread) *myReal_NtSuspendThread=nullptr;*/


static std::atomic<bool> Free_Real_NtCreateUserProcess=false;

#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000200 
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x1


NTSTATUS (NTAPI Hooked_NtCreateUserProcess)(
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
		OutputDebugStringA("Process is being created suspended.");
		mytid = 1;
	} else {
		//make the thread start paused;
		ThreadFlags |= THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
		OutputDebugStringA("Process is being created normally.");
	}	
	
		NTSTATUS ReturnValue = myReal_NtCreateUserProcess(ProcessHandle,
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
			char msg[64];
			sprintf(msg,"CreateUserProcess Failed error: %X",ReturnValue);
			OutputDebugStringA(msg);
			return ReturnValue; 
		}

		std::string ipn_s;
		std::string cmd_s;
		std::wstring ipn;
		std::wstring cmd;
		std::string SensitivePacket;
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
		
		DWORD cbSensitiveText = 0;
		
		LRESULT hr=0;
		
		COPYDATASTRUCT cds;
		HWND hwnd=0;
		
		//DWORD err=0;
		
		//stack fart
		ipn = ProcessParameters->ImagePathName.Buffer;
		if(ipn.empty() )
		{
				OutputDebugStringA("Empty Image path.");				
				goto failure;
		}
		ipn_s=ws2s(ipn);
		if(ipn_s.empty() )
		{
				OutputDebugStringA("wide string conversion failed.");
				goto failure;
		}
		
		
		cmd= ProcessParameters->CommandLine.Buffer;
		if(cmd.empty() )
		{
				OutputDebugStringA("Empty command line.");				
				goto failure;
		}
		cmd_s=ws2s(cmd);
		if(cmd_s.empty() )
		{
				OutputDebugStringA("wide string conversion failed.");
				goto failure;
		}

		SensitivePacket=ipn_s+"\x01"+cmd_s+"\x01"+std::to_string(mypid)+"\x01"+std::to_string(mytid);
		
		//OutputDebugStringA("size of both");		
		//OutputDebugStringA(std::to_string(SensitivePacket.length()).c_str() );
		//OutputDebugStringA(SensitivePacket.c_str());
		
		// encrypt the shit before sending
		//size with \0 ending
		cbSensitiveText = (SensitivePacket.size()*sizeof(CHAR)+1);
		
		
		// MySoft's magic work=)
		//size aligned to blocksize
		cbSensitiveText = (cbSensitiveText | (CRYPTPROTECTMEMORY_BLOCK_SIZE-1))+1;
		//resize the string so that its contents 
		//are already aligned with BLOCK SIZE and with a \0 at end
		SensitivePacket.resize(cbSensitiveText); 		
		
		//OutputDebugStringA("sensitive packet size");
		//OutputDebugStringA( std::to_string(SensitivePacket.size()).c_str()  );
		
		//we already printed this before as we shouldnt see a difference
		//when this is printed now because only \0's at end
		//and this could be printed with .data() as we have an implicit \0 at end		
		//OutputDebugStringA("cbSensitiveText # ==");
		//OutputDebugStringA(std::to_string(cbSensitiveText).c_str() );
				
		if (!CryptProtectMemory(SensitivePacket.data(), cbSensitiveText,
			CRYPTPROTECTMEMORY_CROSS_PROCESS))
		{
			OutputDebugStringA("CPM" );
			SecureZeroMemory(SensitivePacket.data(), cbSensitiveText);
			goto failure;
		}		
		
		//this will never be empty just like the other one because of the same \1 hehe
		if(SensitivePacket.empty() )
		{
			OutputDebugStringA("SS Empty" );			
			SecureZeroMemory(SensitivePacket.data(), cbSensitiveText);						
			goto failure;			
			
		}
						
		cds.dwData = 91; 
		cds.cbData = cbSensitiveText;
		cds.lpData = SensitivePacket.data();
		hwnd=FindWindowA("TideSecOps","TideSecOps");
		if(hwnd==NULL)
		{
			OutputDebugStringA("Failed to find window." );
			goto failure;
		}
		SetLastError(0);
		OutputDebugStringA("Sending parameters");
		hr=SendMessageA(hwnd, WM_COPYDATA, (WPARAM)hwnd, (LPARAM)(LPVOID)&cds);		
		OutputDebugStringA("Parameters sent!");
		
		/*err = GetLastError(); //need to be called RIGHT after the function
		OutputDebugStringA("After send" );
		OutputDebugStringA(std::to_string(hr).c_str() );	
		OutputDebugStringA( std::to_string(err).c_str() );*/
		
		//clear text that we send just in case :)
		SecureZeroMemory(SensitivePacket.data(), cbSensitiveText);
		return ReturnValue;
				
		failure:
		OutputDebugStringA("FAILED!");

	return ReturnValue;

}

struct DLLPool
{
    public:
	DLLPool(const DLLPool &);
	DLLPool &operator=(const DLLPool &);
    struct DLL 
	{
        HINSTANCE handle;
       
        DLL(const char *libname):handle(LoadLibraryA(libname)){}
        operator HINSTANCE()const{ return handle;}
        DLL(const DLL &) = delete;
        DLL(DLL &&) = delete;
        DLL &operator=(const DLL &) = delete;
        DLL &operator=(DLL &&) = delete;
		void Cleanup()
		{
				FreeLibrary(handle);
		}
        ~DLL()
		{

		}
    };
    DLL ntdll="ntdll"; //leet



    bool success;
    DLLPool() { success =  ntdll     ; }
	void FreeIt() {  ntdll.Cleanup()   ;     } //unleet
};

static DLLPool m;




extern "C" __declspec(dllexport) WINAPI void SafeUnhook(void *Dummylol)
{
	//OutputDebugStringA("unhook 1");
	if(Free_Real_NtCreateUserProcess)
	{
		//OutputDebugStringA("unhook 2");
		Mhook_Unhook((PVOID*)&myReal_NtCreateUserProcess);
	}

	//OutputDebugStringA("unhook 3");
	FreeLibraryAndExitThread(Dummylol,0);
	
}

DWORD __stdcall ProcAttachThread(LPVOID l)
{
	
	char Msg[64];
	sprintf(Msg,"inside thread: PID = %i",GetCurrentProcessId());
	OutputDebugStringA(Msg);
	
	if(m.success==false)
	{
		OutputDebugStringA("Failed to load DLLs (injected DLL)");		
		return 0;
	}
	myReal_NtCreateUserProcess=(decltype(Real_NtCreateUserProcess)*)((void*)GetProcAddress(m.ntdll,"NtCreateUserProcess"));
	if(!myReal_NtCreateUserProcess)
	{
		OutputDebugStringA("Failed to locate NtCreateUserProcess");
		return 0;
	}
	
	/*
	myReal_NtSuspendThread=(decltype(Real_NtSuspendThread)*)((void*)GetProcAddress(m.ntdll,"NtSuspendThread"));
	if(!myReal_NtSuspendThread)
	{
		OutputDebugStringA("Failed to locate NtSuspendThread");
		return 0;
	}	
	*/
		
	
	if (Mhook_SetHook((PVOID*)&myReal_NtCreateUserProcess, Hooked_NtCreateUserProcess))
	{			
		Free_Real_NtCreateUserProcess=true;
	} else {
		char Msg[64];
		sprintf(Msg,"Failed  to hook (%i)",GetCurrentProcessId());
		OutputDebugStringA(Msg);		
		return 0;
	}	
	
	OutputDebugStringA("Hooked sucessfully!");
		
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved)
{
	

	switch(fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		{			
			
			OutputDebugStringA("DLL_PROCESS_ATTACH!");
			char Msg[64];
			sprintf(Msg,"before hook: PID = %i",GetCurrentProcessId());
			OutputDebugStringA(Msg);
			
			/*
			DWORD shadeLog;
			HANDLE ll=CreateThread(0,0,ProcAttachThread,(LPVOID)hinstDLL,0,&shadeLog);
			if( ll==0)
			{
					
				break;
			}
			CloseHandle(ll);
			*/
			
			ProcAttachThread((LPVOID)hinstDLL);			
			
			OutputDebugStringA("After thread");
			
			//puts("test inside dll");

			break;
		}
		case DLL_PROCESS_DETACH:
		{


			m.FreeIt();

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






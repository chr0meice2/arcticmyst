
#define WINVER 0x0601
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <msi.h>
#include <psapi.h>
#include <sddl.h>
#include <wintrust.h>
#include <Softpub.h>
#include <shlobj.h>
#include <wtsapi32.h>
//#include <algorithm>
#include <random>
#include <atomic>
#include <wincrypt.h>
#include <shlwapi.h>
#include <vector>
#include <string>
#include <unistd.h>
#include <winuser.h>

#include "t:/deeptide/hashes.h"
#include "c:/cryptopp870/cryptlib.h"
#include "c:/cryptopp870/filters.h"
#include "c:/cryptopp870/base64.h"
#include "c:/cryptopp870/files.h"
#include "c:/cryptopp870/modes.h"
#include "c:/cryptopp870/hex.h"
#include "c:/cryptopp870/aes.h"
#include "c:/cryptopp870/serpent.h"
#include "c:/cryptopp870/secblock.h"
#include "c:/cryptopp870/whrlpool.h"
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "resource.h"
#define PCRE2_STATIC
#define PCRE2_CODE_UNIT_WIDTH 8
#include "C:/pcre2-10.40/src/pcre2.h"
#include "C:/curl-7.86.0/include/curl/curl.h"

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383


typedef struct ThreadParms {
	long Pid, Tid;
} ThreadParms;

typedef struct AsyncWaitStruct {
	DWORD  dwProcPID;
	HANDLE hWaitHandle;
	HANDLE ThreadHandle;
	HANDLE ProcessHandle;
	LPVOID RemoteData;	
} AsyncWaitStruct;


using namespace CryptoPP;

///

static bool FirstRegHKLM=true;
static bool FirstRegHCKU=true;

static std::string DeviceForC="";

static const char VER_STRING[]="20221105a";

static const char UN_FULL[]="^\\x5cDevice\\x5cHarddiskVolume\\d+\\x5cprogramdata\\x5carcticmyst\\x5cunins000\\x2eexe$";
static const char UN_SHORT[]="unins000.exe";

static const char MIN_FULL[]="^\\x5cDevice\\x5cHarddiskVolume\\d+\\x5cprogramdata\\x5carcticmyst\\x5cmystinstaller\\x2eexe$";
static const char MIN_SHORT[]="mystinstaller.exe";

const char injectLibraryPath64[]="C:\\programdata\\arcticmyst\\MystHookProc64.dll";
const char Path64Hash[]=_hash64; //"ad00800d66e754a48fb17e2b4e5e9906dac1ccc7346dd716b421b4485593ff12";
const char injectLibraryPath32[]="C:\\programdata\\arcticmyst\\MystHookProc32.dll";	
const char Path32Hash[]=_hash32; //"7b418a575f6659a9e4caf009eb6af34a841eefd3d7a9bc757c7f812d49ba65df";

static void EjectProcesses();
static DWORD __stdcall InjectProcessThread(LPVOID lp);

static std::vector<DWORD> p32;
static std::vector<DWORD> p64;

static std::vector<std::string> FileExecutions;

// all vars and functions to be edited

static void CALLBACK myAsyncWaitCallback(LPVOID pParm , BOOLEAN TimerOrWaitFired);

static char* GetProcAddressEx( HANDLE hProcess , HMODULE hModule ,const char* pzName );
static bool ci_endswith(const std::string& value, const std::string& ending);
static void SecEngProcEnumerator_All(std::vector<DWORD> &ProcID32,std::vector<DWORD> &ProcID64);
static DWORD SecEngProcEnumerator(const char *filter);
static void EjectDLL(DWORD nProcessId, const char* wsDLLPath);
static void POSTExeData();
static DWORD __stdcall ExeVectorThread(LPVOID lp);

static void LaunchProcessAsNonSystem(char cmd[]);
static void GetAllStartups(); // HKCU
static void GetAllHKLM();
static std::vector<std::string> GetSidArray();
static std::string QueryKey(HKEY hKey);
static DWORD __stdcall RegistryMonitorThreadHKCU(LPVOID );
static DWORD __stdcall RegistryMonitorThreadHKLM(LPVOID );
static DWORD __stdcall RegistryMonitorThread(LPVOID);
static void RegistryMonitorFunction(void);
static void RegistryMonitorFunctionHKCU(void);
static void RegistryMonitorFunctionHKLM(void);
static std::string WhirlpoolHashString(std::string aString);

static void IceCoolMsg(const char *rawdata);
static DWORD __stdcall CoolMsg(LPVOID x);
static DWORD __stdcall UserCryptoProc(LPVOID);
static INT_PTR CALLBACK CryptoBox(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
static std::string urlencode(const std::string &url);

static bool isHexStringValid(const std::string &myHex);
static bool fastmatch(const std::string pattern, const std::string &subject);
static bool SerpentCryptoInit(const  char *key,const char op,const std::string &CryptoInput,std::string &outBuffer);
static bool GetExeForPid(const DWORD pid,std::string &exepath);

static DWORD __stdcall AttackThread(LPVOID);
static void GenericLogTunnelUpdater(const std::string &TimeStamp,const std::string &MainDataToAdd);
static DWORD __stdcall launchHiddenLog(LPVOID);
static INT_PTR CALLBACK LogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
static void balloon(const char *myGas);
static void Cleanup();
static DWORD __stdcall BalloonCallback(LPVOID deflateGas);
static std::string ProcessFullPath(DWORD pid);
static void POSTMoveData();
static void POSTRegData(unsigned);

static bool comparei(std::string input1,std::string input2);

static DWORD __stdcall UserMarshallCallback(LPVOID);
static DWORD __stdcall SIDMarshallCallback(LPVOID);

static INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
static unsigned __int64  msgloop();
static const std::string logTSEntry();



static BOOL GetLogonFromToken (HANDLE hToken, std::string & strUser, std::string& strdomain, std::string &sid) ;
static HRESULT GetUserFromProcess(const DWORD procId,  std::string & strUser, std::string & strdomain, std::string &sid);
static std::string GetCurrentUserWhileSYSTEMFromExplorer();
static DWORD __stdcall UserMarshallCallback(LPVOID);


static std::string PCRE2_Extract_One_Submatch(const std::string pattern,const std::string &text,const bool);

static LRESULT CALLBACK WndProc(HWND hwnd,UINT message,WPARAM wParam,LPARAM lParam);


static bool ReadAndHash(const char *path,std::string &HashIn); 



static HRSRC hRSrc;

static HGLOBAL hResource ;

static unsigned char* RAWHANDLEEXE;

static const char PA_MD5[]="ab50d8d707b97712178a92bbac74ccc2a5699eb41c17aa77f713ff3e568dcedb";
static const char PA_PATH[]="C:\\programdata\\arcticmyst\\paexec.exe";


static std::string PreviousRegistryHash="";
static std::string PreviousRegistryHashHKCU="";
static std::string PreviousRegistryHashHKLM="";
static std::string AllStartups="";
static std::string AllHKLM="";

static  UINT WM_TASKBARCREATED;
static const unsigned short MAX_LOG_TEXT_SIZE=26624; // 26KN  26624
static std::atomic< bool> CRClean=false;
static std::atomic< bool> VolatileCleanBool=false;
static std::atomic< bool> SerpentCryptoSetup=false;
static const std::string FAIL="[NA]";
static  std::string VolatileCurrentUser=FAIL;
static std::string VolatileCurrentSID=FAIL;

static std::string VolatileCurrentPendMoves=FAIL;

static const std::string RN="\r\n";
static const char cln=':';
static const char one='1';
static const char two='2';
static const char sidID[]="s-1-1-0";
//static CRITICAL_SECTION CriticalLog;
//static  std::atomic< bool> FreeLog=false;


static const char nme[]="TideSecOps"; //windowname



static HANDLE hMutex=NULL;

static const char edit[]="edit";


static bool WSClean=false;
static bool WFClean=false;

static const char MY_TOOLTIP[]="ArcticMyst Security";
static const char ALERTTILE[]="ArcticMyst Security - Alert Log Box";



static CRITICAL_SECTION CleanupCritical;
static  std::atomic< bool>FreeCleanupCS=false;
static CRITICAL_SECTION CurlCritical;
static  std::atomic< bool>FreeCurlCS=false;
static CRITICAL_SECTION LogMessageCS;
static  std::atomic< bool>FreeLog=false;
static  std::atomic< bool>IconCleanupRequired=false;


static CRITICAL_SECTION BalloonCritical;
static  std::atomic< bool>FreeBalloon=false;
static  std::atomic< bool> firstload=true;

static CRITICAL_SECTION InjectCritical;
static std::atomic<bool>FreeInject=false;


static CRITICAL_SECTION ExeVectorCritical;
static  std::atomic< bool>  FreeExeVector=false;



static const std::string HexRgx="^[A-F0-9]+$";
static const char BALLOON0a[]="ArcticMyst Security - Loaded...";
static const char BALLOON0b[]="Monitoring for threats...";
static const char BALLOON1[]="ArcticMyst Security - Check logs for alert details...";
static const char BALLOON2[]="See alert log box for details...";





static HBITMAP hBMP = 0;
static HWND hBitmap = 0;

			



static std::atomic< bool> FreeSID=false;

static const char DOMAINI[]="deeptide.com";
static const unsigned short port = 443;
static NOTIFYICONDATA tnid={};
static HICON hIcon;
static HICON hIcon2;



static HWND hPasswd=0;
static HWND hPlain=0;
static HWND hEnc=0;
static HWND hDec=0;
static HWND hMin=0;
static HWND hDonate=0;
//static HWND hBuy=0;
static HWND hGithub=0;
static  std::atomic< bool>  clickEncryptOK = true;
static  std::atomic< bool>  clickDecryptOK = true;



static CHAR at[128]   {}; // alert box title 
static HINSTANCE hInst=0;

static  std::atomic< bool>FreeGUICrypto=false;
static CRITICAL_SECTION GUICryptoCritical;

static CRITICAL_SECTION AttackCritical;
static CRITICAL_SECTION MarshallVolatilitySection;
static CRITICAL_SECTION SIDMarshallVolatilitySection;

static  std::atomic< bool>  FreeMarshall = false;
static  std::atomic< bool>  FreeAttack = false;

static HWND hButton= 0;
static HWND hwnd2=0;
static HWND hwndAlertLogBox=0;
static std::string globLogString="";
static HWND hwndAlertLogText=0;
static HWND hButtonClose=0;
static HWND hButtonAtk=0;
static HWND hLic=0;
static HWND hUsrTxt=0;


static const char EXPLORER[]="explorer.exe";

static TCHAR COMPUTER_NAME[MAX_COMPUTERNAME_LENGTH + 2] {};
static std::string COMPNAMP_URLENC="";
static const std::string SYSTEM="SYSTEM";


static std::string UA="User-Agent: ";
static std::string tempcn="";
static std::string cnanduser="";
static std::string PEcnanduser="";
static const char NONE[]="NONE";
static  std::atomic< bool> allowedToClick=true;
static  std::atomic< bool> SerpentallowedToClick=true;
static  std::atomic< bool> allowedToClickAttack=true;



static void *myReal_LoadLibraryA32=NULL;

static decltype(LoadLibraryA) *myReal_LoadLibraryA=nullptr;

void WINAPI SafeUnhookParams(void *dummy);

static decltype( SafeUnhookParams) *myReal_SafeUnhook=nullptr;



////
static decltype(ResumeThread) *myResumeThread=nullptr;
static decltype(OpenThread) *myOpenThread=nullptr;
static decltype(RegisterWaitForSingleObject) *myRegisterWaitForSingleObject=nullptr;
static decltype(UnregisterWait) *myUnregisterWait=nullptr;
static decltype(QueryDosDeviceA) *myQueryDosDeviceA=nullptr;
static decltype(GetProcessImageFileNameA) *myGetProcessImageFileNameA=nullptr;
static decltype(ChangeWindowMessageFilterEx) *myChangeWindowMessageFilterEx=nullptr;
static decltype(closesocket) *myclosesocket=nullptr;
static decltype(CryptUnprotectMemory) *myCryptUnprotectMemory=nullptr;
static decltype(GetModuleInformation) *myGetModuleInformation=nullptr;
static decltype(GetExitCodeThread) *myGetExitCodeThread=nullptr;
static decltype(VirtualFreeEx) *myVirtualFreeEx=nullptr;
static decltype(CreateRemoteThread) *myCreateRemoteThread=nullptr;
static decltype(WriteProcessMemory) *myWriteProcessMemory=nullptr;
static decltype(VirtualAllocEx) *myVirtualAllocEx=nullptr;
static decltype(GetModuleFileNameExA) *myGetModuleFileNameExA=nullptr;
static decltype(EnumProcessModulesEx) *myEnumProcessModulesEx=nullptr;

static decltype(ReadProcessMemory) *myReadProcessMemory=nullptr;
static decltype(IsWow64Process) *myIsWow64Process=nullptr;
static decltype(CreateFileA) *myCreateFileA=nullptr;
static decltype(ReadFile) *myReadFile=nullptr;

static decltype(CryptAcquireContextA) *myCryptAcquireContextA=nullptr;
static decltype(CryptCreateHash) *myCryptCreateHash=nullptr;
static decltype(CryptDestroyHash) *myCryptDestroyHash=nullptr;
static decltype(CryptGetHashParam) *myCryptGetHashParam=nullptr;
static decltype(CryptHashData) *myCryptHashData=nullptr;
static decltype(CryptReleaseContext) *myCryptReleaseContext=nullptr;


static decltype(WTSQueryUserToken) *myWTSQueryUserToken=nullptr;
static decltype(ProcessIdToSessionId) *myProcessIdToSessionId=nullptr;
static decltype(CreateProcessAsUserA) *myCreateProcessAsUserA=nullptr;
static decltype(GetShellWindow) *myGetShellWindow=nullptr;
static decltype(GetWindowThreadProcessId) *myGetWindowThreadProcessId=nullptr;
static decltype( InitializeProcThreadAttributeList) *myInitializeProcThreadAttributeList=nullptr;
static decltype(UpdateProcThreadAttribute) *myUpdateProcThreadAttribute=nullptr;

static decltype(CloseHandle) *myCloseHandle=nullptr;

static decltype(ConvertSidToStringSidA) *myConvertSidToStringSidA=nullptr;
static decltype(CreateEvent) *myCreateEventA=nullptr;

static decltype(CreateMutexA) *myCreateMutexA=nullptr;
static decltype(CreatePopupMenu) *myCreatePopupMenu=nullptr;
static decltype(CreateProcessA) *myCreateProcessA=nullptr;
static decltype(CreateThread) *myCreateThread=nullptr;
static decltype(CreateToolhelp32Snapshot) *myCreateToolhelp32Snapshot=nullptr;
static decltype(CreateWindowExA) *myCreateWindowExA=nullptr;

static decltype(DefWindowProcA) *myDefWindowProcA=nullptr;
static decltype(DeleteCriticalSection) *myDeleteCriticalSection=nullptr;

static decltype(DialogBoxParamA) *myDialogBoxParamA=nullptr;
static decltype(DispatchMessageA) *myDispatchMessageA=nullptr;
static decltype(EndDialog) *myEndDialog=nullptr;
static decltype(EnterCriticalSection) *myEnterCriticalSection=nullptr;
static decltype(FindResourceA) *myFindResourceA=nullptr;
static decltype(GetComputerNameA) *myGetComputerNameA=nullptr;
static decltype(GetCursorPos) *myGetCursorPos=nullptr;
static decltype(GetDlgItem) *myGetDlgItem=nullptr;


static decltype(GetLastError) *myGetLastError=nullptr;
static decltype(GetMessageA) *myGetMessageA=nullptr;
static decltype(GetModuleHandleA) *myGetModuleHandleA=nullptr;
static decltype(GetProcessHeap) *myGetProcessHeap=nullptr;

static decltype(GetTokenInformation) *myGetTokenInformation=nullptr;
static decltype(HeapAlloc) *myHeapAlloc=nullptr;
static decltype(HeapFree) *myHeapFree=nullptr;
static decltype(InitializeCriticalSectionAndSpinCount) *myInitializeCriticalSectionAndSpinCount=nullptr;
static decltype(InsertMenuA) *myInsertMenuA=nullptr;
static decltype(LeaveCriticalSection) *myLeaveCriticalSection=nullptr;
static decltype(LoadCursorA) *myLoadCursorA=nullptr;
static decltype(LoadIconA) *myLoadIconA=nullptr;
static decltype(LoadResource) *myLoadResource=nullptr;
static decltype(LocalFree) *myLocalFree=nullptr;
static decltype(LockResource) *myLockResource=nullptr;
static decltype(LookupAccountSidA) *myLookupAccountSidA=nullptr;
static decltype(MessageBoxIndirectA) *myMessageBoxIndirectA=nullptr;

static decltype(OpenProcess) *myOpenProcess=nullptr;
static decltype(OpenProcessToken) *myOpenProcessToken=nullptr;
static decltype(PostQuitMessage) *myPostQuitMessage=nullptr;
static decltype(Process32First) *myProcess32First=nullptr;
static decltype(Process32Next) *myProcess32Next=nullptr;

static decltype(RegCloseKey) *myRegCloseKey=nullptr;
static decltype(RegEnumKeyExA) *myRegEnumKeyExA=nullptr;
static decltype(RegEnumValueA) *myRegEnumValueA=nullptr;
static decltype(RegOpenKeyExA) *myRegOpenKeyExA=nullptr;
static decltype(RegQueryInfoKeyA) *myRegQueryInfoKeyA=nullptr;
static decltype(RegQueryValueExA) *myRegQueryValueExA=nullptr;
static decltype(RegisterClassExA) *myRegisterClassExA=nullptr;
static decltype(RegNotifyChangeKeyValue) *myRegNotifyChangeKeyValue=nullptr;
static decltype(RegisterWindowMessageA) *myRegisterWindowMessageA=nullptr;

static decltype(SendMessageA) *mySendMessageA=nullptr;
static decltype(SetForegroundWindow) *mySetForegroundWindow=nullptr;
static decltype(SetThreadPriority) *mySetThreadPriority=nullptr;
static decltype(SetWindowPos) *mySetWindowPos=nullptr;
//static decltype(ShellExecuteA) *ptrShellExecuteA=nullptr;
static decltype(Shell_NotifyIconA) *ptrShell_NotifyIconA=nullptr;
static decltype(ShowWindow) *myShowWindow=nullptr;
static decltype(ShowWindowAsync) *myShowWindowAsync=nullptr;
static decltype(SizeofResource) *mySizeofResource=nullptr;
static decltype(Sleep) *mySleep=nullptr;

static decltype(TrackPopupMenu) *myTrackPopupMenu=nullptr;
static decltype(TranslateMessage) *myTranslateMessage=nullptr;
static decltype(UpdateWindow) *myUpdateWindow=nullptr;
static decltype(WSACleanup) *myWSACleanup=nullptr;
static decltype(WSAStartup) *myWSAStartup=nullptr;
static decltype(WaitForSingleObject) *myWaitForSingleObject=nullptr;
static decltype(WaitForMultipleObjects) *myWaitForMultipleObjects=nullptr;

static decltype(connect) *myconnect=nullptr;
static decltype(gethostbyname) *mygethostbyname=nullptr;
static decltype(htons) *myhtons=nullptr;
static decltype(socket) *mysocket=nullptr;
static decltype(LoadBitmapA) *myLoadBitmapA=nullptr;
static decltype(DeleteObject) *myDeleteObject=nullptr;


namespace ranges
{
    template<typename Range, typename Generator>
    void generate(Range& range, Generator generator)
    {
        return std::generate(begin(range), end(range), generator);
    }
}

auto randomNumberBetween = [](int low, int high)
{
    auto randomFunc = [distribution_ = std::uniform_int_distribution<int>(low, high), 
                       random_engine_ = std::mt19937{ std::random_device{}() }]() mutable
    {
        return distribution_(random_engine_);
    };
    return randomFunc;
};

class RandomNumberBetween
{
public:
    RandomNumberBetween(int low, int high)
    : random_engine_{std::random_device{}()}
    , distribution_{low, high}
    {
    }
    int operator()()
    {
        return distribution_(random_engine_);
    }
private:
    std::mt19937 random_engine_;
    std::uniform_int_distribution<int> distribution_;
};




template <size_t charCount>
void strcpy_safe(char (&output)[charCount], const char* pSrc)
{
	strncpy(output, pSrc, charCount);
	output[charCount-1] = 0;
}

struct DLLPool
{
    public:
	DLLPool(const DLLPool &);
	DLLPool &operator=(const DLLPool &);
    struct DLL 
	{
        HINSTANCE handle;
       
        DLL(const char *libname):handle(LoadLibrary(libname)){}
        operator HINSTANCE()const{ return handle;}
        DLL(const DLL &) = delete;
        DLL(DLL &&) = delete;
        DLL &operator=(const DLL &) = delete;
        DLL &operator=(DLL &&) = delete;
        ~DLL()
		{
			if(handle != NULL)
			{
        		FreeLibrary(handle);
        	}
		}
    };
    DLL k32="kernel32";
    DLL us32="user32";
    DLL adv32="advapi32";
    DLL sh32="shell32";
    DLL w32="ws2_32";
    DLL gdi32="gdi32";
	DLL wts32="wtsapi32";
	DLL crypt32="crypt32";
	DLL psapi="psapi";


    bool success;
    DLLPool() { success =  k32 && us32 && adv32 && sh32   && w32 && gdi32 && wts32 && crypt32 && psapi     ; }
};


class terminationGas
{

	private:
	HINSTANCE V2us32=NULL;
	
	public:
	bool loaded=false;
	void gasAttack();
	terminationGas();
	~terminationGas();
	

};
terminationGas::terminationGas()
{
	HINSTANCE V2us32=LoadLibrary("user32");
	if(V2us32==NULL)
	{

		return ;
	}
	myPostQuitMessage=(decltype(PostQuitMessage)*)((void*)GetProcAddress(V2us32,"PostQuitMessage"));
	if(myPostQuitMessage)
	{
		loaded=true;
	}
	return ;

}
terminationGas::~terminationGas()
{
	
	if(V2us32!=NULL)
	{
		FreeLibrary(V2us32);
	}

}
void terminationGas::gasAttack()
{

	if(loaded==true)
	{

		(*myPostQuitMessage)(0x0); //leet gas
	}
	return ;

}

static DLLPool m;
static terminationGas postExtract;
static CURL *curl;


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{



	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nCmdShow);
	UNREFERENCED_PARAMETER(hPrevInstance);
	if(postExtract.loaded==false)
	{
		return 0;
	}


	if(m.success==false)
	{

		return 0;
	}

	myOpenThread=(decltype(OpenThread)*)((void*)GetProcAddress(m.k32,"OpenThread"));
	myResumeThread=(decltype(ResumeThread)*)((void*)GetProcAddress(m.k32,"ResumeThread"));
	myUnregisterWait=(decltype(UnregisterWait)*)((void*)GetProcAddress(m.k32,"UnregisterWait"));
	myRegisterWaitForSingleObject=(decltype(RegisterWaitForSingleObject)*)((void*)GetProcAddress(m.k32,"RegisterWaitForSingleObject"));
	myGetProcessImageFileNameA=(decltype(GetProcessImageFileNameA)*)((void*)GetProcAddress(m.psapi,"GetProcessImageFileNameA"));
	myChangeWindowMessageFilterEx=(decltype(ChangeWindowMessageFilterEx)*)((void*)GetProcAddress(m.us32,"ChangeWindowMessageFilterEx"));
	myclosesocket=(decltype(closesocket)*)((void*)GetProcAddress(m.w32,"closesocket"));
	myCryptUnprotectMemory=(decltype(CryptUnprotectMemory)*)((void*)GetProcAddress(m.crypt32,"CryptUnprotectMemory"));
	myGetModuleInformation=(decltype(GetModuleInformation)*)((void*)GetProcAddress(m.psapi,"GetModuleInformation"));
	myQueryDosDeviceA=(decltype(QueryDosDeviceA)*)((void*)GetProcAddress(m.k32,"QueryDosDeviceA"));
	myGetExitCodeThread=(decltype(GetExitCodeThread)*)((void*)GetProcAddress(m.k32,"GetExitCodeThread"));
	myCreateRemoteThread=(decltype(CreateRemoteThread)*)((void*)GetProcAddress(m.k32,"CreateRemoteThread"));
	myWriteProcessMemory=(decltype(WriteProcessMemory)*)((void*)GetProcAddress(m.k32,"WriteProcessMemory"));
	myVirtualFreeEx=(decltype(VirtualFreeEx)*)((void*)GetProcAddress(m.k32,"VirtualFreeEx"));
	myVirtualAllocEx=(decltype(VirtualAllocEx)*)((void*)GetProcAddress(m.k32,"VirtualAllocEx"));
	myEnumProcessModulesEx=(decltype(EnumProcessModulesEx)*)((void*)GetProcAddress(m.psapi,"EnumProcessModulesEx"));
	myGetModuleFileNameExA=(decltype(GetModuleFileNameExA)*)((void*)GetProcAddress(m.psapi,"GetModuleFileNameExA"));
	myReal_LoadLibraryA=(decltype(LoadLibraryA)*)((void*)GetProcAddress(m.k32,"LoadLibraryA"));
	myReadProcessMemory=(decltype(ReadProcessMemory)*)((void*)GetProcAddress(m.k32,"ReadProcessMemory"));

	myIsWow64Process=(decltype(IsWow64Process)*)((void*)GetProcAddress(m.k32,"IsWow64Process"));
	myCreateFileA=(decltype(CreateFileA)*)((void*)GetProcAddress(m.k32,"CreateFileA"));
	myReadFile=(decltype(ReadFile)*)((void*)GetProcAddress(m.k32,"ReadFile"));


	myCryptAcquireContextA=(decltype(CryptAcquireContextA)*)((void*)GetProcAddress(m.adv32,"CryptAcquireContextA"));
	myCryptCreateHash=(decltype(CryptCreateHash)*)((void*)GetProcAddress(m.adv32,"CryptCreateHash"));
	myCryptDestroyHash=(decltype(CryptDestroyHash)*)((void*)GetProcAddress(m.adv32,"CryptDestroyHash"));
	myCryptGetHashParam=(decltype(CryptGetHashParam)*)((void*)GetProcAddress(m.adv32,"CryptGetHashParam"));
	myCryptHashData=(decltype(CryptHashData)*)((void*)GetProcAddress(m.adv32,"CryptHashData"));
	myCryptReleaseContext=(decltype(CryptReleaseContext)*)((void*)GetProcAddress(m.adv32,"CryptReleaseContext"));



	myWTSQueryUserToken=(decltype(WTSQueryUserToken)*)((void*)GetProcAddress(m.wts32,"WTSQueryUserToken"));
	myProcessIdToSessionId=(decltype(ProcessIdToSessionId)*)((void*)GetProcAddress(m.k32,"ProcessIdToSessionId"));
	myCreateProcessAsUserA=(decltype(CreateProcessAsUserA)*)((void*)GetProcAddress(m.adv32,"CreateProcessAsUserA"));


	myGetShellWindow=(decltype(GetShellWindow)*)((void*)GetProcAddress(m.us32,"GetShellWindow"));
	myGetWindowThreadProcessId=(decltype(GetWindowThreadProcessId)*)((void*)GetProcAddress(m.us32,"GetWindowThreadProcessId"));
	myInitializeProcThreadAttributeList=(decltype(InitializeProcThreadAttributeList)*)((void*)GetProcAddress(m.k32,"InitializeProcThreadAttributeList"));
	myUpdateProcThreadAttribute=(decltype(UpdateProcThreadAttribute)*)((void*)GetProcAddress(m.k32,"UpdateProcThreadAttribute"));

	myDeleteObject=(decltype(DeleteObject)*)((void*)GetProcAddress(m.gdi32,"DeleteObject"));
	myLoadBitmapA=(decltype(LoadBitmapA)*)((void*)GetProcAddress(m.us32,"LoadBitmapA"));
	myCloseHandle=(decltype(CloseHandle)*)((void*)GetProcAddress(m.k32,"CloseHandle"));
	myConvertSidToStringSidA=(decltype(ConvertSidToStringSidA)*)((void*)GetProcAddress(m.adv32,"ConvertSidToStringSidA"));

	myCreateEventA=(decltype(CreateEventA)*)((void*)GetProcAddress(m.k32,"CreateEventA"));

	myCreatePopupMenu=(decltype(CreatePopupMenu)*)((void*)GetProcAddress(m.us32,"CreatePopupMenu"));
	myCreateProcessA=(decltype(CreateProcessA)*)((void*)GetProcAddress(m.k32,"CreateProcessA"));
	myCreateThread=(decltype(CreateThread)*)((void*)GetProcAddress(m.k32,"CreateThread"));
	myCreateToolhelp32Snapshot=(decltype(CreateToolhelp32Snapshot)*)((void*)GetProcAddress(m.k32,"CreateToolhelp32Snapshot"));
	myCreateWindowExA=(decltype(CreateWindowExA)*)((void*)GetProcAddress(m.us32,"CreateWindowExA"));

	myDefWindowProcA=(decltype(DefWindowProcA)*)((void*)GetProcAddress(m.us32,"DefWindowProcA"));
	myDeleteCriticalSection=(decltype(DeleteCriticalSection)*)((void*)GetProcAddress(m.k32,"DeleteCriticalSection"));

	myDialogBoxParamA=(decltype(DialogBoxParamA)*)((void*)GetProcAddress(m.us32,"DialogBoxParamA"));
	myDispatchMessageA=(decltype(DispatchMessageA)*)((void*)GetProcAddress(m.us32,"DispatchMessageA"));
	myEndDialog=(decltype(EndDialog)*)((void*)GetProcAddress(m.us32,"EndDialog"));
	myEnterCriticalSection=(decltype(EnterCriticalSection)*)((void*)GetProcAddress(m.k32,"EnterCriticalSection"));
	myFindResourceA=(decltype(FindResourceA)*)((void*)GetProcAddress(m.k32,"FindResourceA"));
	myGetComputerNameA=(decltype(GetComputerNameA)*)((void*)GetProcAddress(m.k32,"GetComputerNameA"));
	myGetCursorPos=(decltype(GetCursorPos)*)((void*)GetProcAddress(m.us32,"GetCursorPos"));

	myGetDlgItem=(decltype(GetDlgItem)*)((void*)GetProcAddress(m.us32,"GetDlgItem"));


	myGetMessageA=(decltype(GetMessageA)*)((void*)GetProcAddress(m.us32,"GetMessageA"));
	myGetModuleHandleA=(decltype (GetModuleHandleA)*)((void*)GetProcAddress(m.k32,"GetModuleHandleA"));
	myGetProcessHeap=(decltype(GetProcessHeap)*)((void*)GetProcAddress(m.k32,"GetProcessHeap"));

	myGetTokenInformation=(decltype(GetTokenInformation)*)((void*)GetProcAddress(m.adv32,"GetTokenInformation"));
	myHeapAlloc=(decltype(HeapAlloc)*)((void*)GetProcAddress(m.k32,"HeapAlloc"));
	myHeapFree=(decltype(HeapFree)*)((void*)GetProcAddress(m.k32,"HeapFree"));
	myInitializeCriticalSectionAndSpinCount=(decltype(InitializeCriticalSectionAndSpinCount)*)((void*)GetProcAddress(m.k32,"InitializeCriticalSectionAndSpinCount"));
	myInsertMenuA=(decltype(InsertMenuA)*)((void*)GetProcAddress(m.us32,"InsertMenuA"));
	myLeaveCriticalSection=(decltype(LeaveCriticalSection)*)((void*)GetProcAddress(m.k32,"LeaveCriticalSection"));

	myLoadCursorA=(decltype(LoadCursorA)*)((void*)GetProcAddress(m.us32,"LoadCursorA"));
	myLoadIconA=(decltype(LoadIconA)*)((void*)GetProcAddress(m.us32,"LoadIconA"));
	myLoadResource=(decltype(LoadResource)*)((void*)GetProcAddress(m.k32,"LoadResource"));
	myLocalFree=(decltype(LocalFree)*)((void*)GetProcAddress(m.k32,"LocalFree"));
	myLockResource=(decltype(LockResource)*)((void*)GetProcAddress(m.k32,"LockResource"));
	myLookupAccountSidA=(decltype(LookupAccountSidA)*)((void*)GetProcAddress(m.adv32,"LookupAccountSidA"));
	myMessageBoxIndirectA=(decltype(MessageBoxIndirectA)*)((void*)GetProcAddress(m.us32,"MessageBoxIndirectA"));

	myOpenProcess=(decltype(OpenProcess)*)((void*)GetProcAddress(m.k32,"OpenProcess"));
	myOpenProcessToken=(decltype(OpenProcessToken)*)((void*)GetProcAddress(m.adv32,"OpenProcessToken"));
	myProcess32First=(decltype(Process32First)*)((void*)GetProcAddress(m.k32,"Process32First"));
	myProcess32Next=(decltype(Process32Next)*)((void*)GetProcAddress(m.k32,"Process32Next"));

	myRegCloseKey=(decltype(RegCloseKey)*)((void*)GetProcAddress(m.adv32,"RegCloseKey"));
	myRegOpenKeyExA=(decltype(RegOpenKeyExA)*)((void*)GetProcAddress(m.adv32,"RegOpenKeyExA"));

	myRegQueryInfoKeyA=(decltype(RegQueryInfoKeyA)*)((void*)GetProcAddress(m.adv32,"RegQueryInfoKeyA"));
	myRegEnumKeyExA=(decltype(RegEnumKeyExA)*)((void*)GetProcAddress(m.adv32,"RegEnumKeyExA"));
	myRegEnumValueA=(decltype(RegEnumValueA)*)((void*)GetProcAddress(m.adv32,"RegEnumValueA"));

	myRegQueryValueExA=(decltype(RegQueryValueExA)*)((void*)GetProcAddress(m.adv32,"RegQueryValueExA"));
	myRegNotifyChangeKeyValue=(decltype(RegNotifyChangeKeyValue)*)((void*)GetProcAddress(m.adv32,"RegNotifyChangeKeyValue"));
	myRegisterClassExA=(decltype(RegisterClassExA)*)((void*)GetProcAddress(m.us32,"RegisterClassExA"));
	myRegisterWindowMessageA=(decltype (RegisterWindowMessageA)*)((void*)GetProcAddress(m.us32,"RegisterWindowMessageA"));
	mySendMessageA=(decltype(SendMessageA)*)((void*)GetProcAddress(m.us32,"SendMessageA"));
	mySetForegroundWindow=(decltype(SetForegroundWindow)*)((void*)GetProcAddress(m.us32,"SetForegroundWindow"));
	mySetThreadPriority=(decltype(SetThreadPriority)*)((void*)GetProcAddress(m.k32,"SetThreadPriority"));
	mySetWindowPos=(decltype (SetWindowPos)*)((void*)GetProcAddress(m.us32,"SetWindowPos"));
	myShowWindow=(decltype(ShowWindow)*)((void*)GetProcAddress(m.us32,"ShowWindow"));
	myShowWindowAsync=(decltype(ShowWindowAsync)*)((void*)GetProcAddress(m.us32,"ShowWindowAsync"));
	mySizeofResource=(decltype(SizeofResource)*)((void*)GetProcAddress(m.k32,"SizeofResource"));
	mySleep=(decltype(Sleep)*)((void*)GetProcAddress(m.k32,"Sleep"));

	myTrackPopupMenu=(decltype(TrackPopupMenu)*)((void*)GetProcAddress(m.us32,"TrackPopupMenu"));
	myTranslateMessage=(decltype(TranslateMessage)*)((void*)GetProcAddress(m.us32,"TranslateMessage"));
	myUpdateWindow=(decltype(UpdateWindow)*)((void*)GetProcAddress(m.us32,"UpdateWindow"));
	myWSACleanup=(decltype(WSACleanup)*)((void*)GetProcAddress(m.w32,"WSACleanup"));
	myWSAStartup=(decltype(WSAStartup)*)((void*)GetProcAddress(m.w32,"WSAStartup"));
	myWaitForSingleObject=(decltype(WaitForSingleObject)*)((void*)GetProcAddress(m.k32,"WaitForSingleObject"));
	myWaitForMultipleObjects=(decltype(WaitForMultipleObjects)*)((void*)GetProcAddress(m.k32,"WaitForMultipleObjects"));

	myconnect=(decltype(connect)*)((void*)GetProcAddress(m.w32,"connect"));
	mygethostbyname=(decltype(gethostbyname)*)((void*)GetProcAddress(m.w32,"gethostbyname"));
	myhtons=(decltype(htons)*)((void*)GetProcAddress(m.w32,"htons"));
	mysocket=(decltype(socket)*)((void*)GetProcAddress(m.w32,"socket"));

	//ptrShellExecuteA=(decltype(ShellExecuteA)*)((void*)GetProcAddress(m.sh32,"ShellExecuteA"));
	ptrShell_NotifyIconA=(decltype(Shell_NotifyIconA)*)((void*)GetProcAddress(m.sh32,"Shell_NotifyIconA"));






	if(!  (myOpenThread&&myResumeThread&&myRegisterWaitForSingleObject&&myUnregisterWait&&myQueryDosDeviceA&&myGetProcessImageFileNameA&&myChangeWindowMessageFilterEx&&myclosesocket && myVirtualFreeEx && myCryptUnprotectMemory&&myGetModuleInformation&&myGetExitCodeThread&&myCreateRemoteThread&&myWriteProcessMemory && myVirtualAllocEx&&myEnumProcessModulesEx&& myGetModuleFileNameExA && myReal_LoadLibraryA && myReadProcessMemory && myIsWow64Process && myCreateFileA && myReadFile && myCryptAcquireContextA && myCryptCreateHash && myCryptDestroyHash && myCryptGetHashParam && myCryptHashData && myCryptReleaseContext && myWTSQueryUserToken && myProcessIdToSessionId && myCreateProcessAsUserA && myGetShellWindow && myGetWindowThreadProcessId && myInitializeProcThreadAttributeList && myUpdateProcThreadAttribute  && myLoadBitmapA && myDeleteObject && myWaitForMultipleObjects && myRegEnumValueA && myRegQueryInfoKeyA && myRegEnumKeyExA && myCreateEventA && myRegNotifyChangeKeyValue && myCloseHandle && myConvertSidToStringSidA   && myCreatePopupMenu && myCreateProcessA && myCreateThread && myCreateToolhelp32Snapshot && myCreateWindowExA  && myDefWindowProcA && myDeleteCriticalSection  && myDialogBoxParamA && myDispatchMessageA && myEndDialog && myEnterCriticalSection && myFindResourceA && myGetComputerNameA && myGetCursorPos  && myGetDlgItem   && myGetMessageA && myGetModuleHandleA && myGetProcessHeap  && myGetTokenInformation && myHeapAlloc && myHeapFree && myInsertMenuA && myLeaveCriticalSection  && myLoadCursorA && myLoadIconA && myLoadResource && myLocalFree && myLockResource && myLookupAccountSidA && myMessageBoxIndirectA && myOpenProcess && myOpenProcessToken && myProcess32First && myProcess32Next   && myRegCloseKey && myRegOpenKeyExA && myRegQueryValueExA && myRegisterClassExA && myRegisterWindowMessageA && mySendMessageA  && mySetForegroundWindow  && mySetThreadPriority && mySetWindowPos && myShowWindow && myShowWindowAsync && mySizeofResource && mySleep  && myTrackPopupMenu && myTranslateMessage && myUpdateWindow  && myWSACleanup && myWSAStartup && myWaitForSingleObject && myconnect && mygethostbyname && myhtons && mysocket   && ptrShell_NotifyIconA )  )
	{

		Cleanup();
		return 0;

	}

	DWORD lastError;
	myCreateMutexA=(decltype(CreateMutexA)*)((void*)GetProcAddress(m.k32,"CreateMutexA"));
	if(myCreateMutexA==0)
	{
		Cleanup();	
		return 0;
	}
	hMutex=myCreateMutexA(0,FALSE,"Global\\ArcticMystOps");
	myGetLastError=(decltype(GetLastError)*)((void*)GetProcAddress(m.k32,"GetLastError"));
	if(myGetLastError==0)
	{
		Cleanup();	
		return 0;
	}
	lastError=(*myGetLastError)();
	if(ERROR_ALREADY_EXISTS==lastError)
	{
		Cleanup();	
		return 0;	
	}


	char DPATH[MAX_PATH]{};
	DWORD PathCopied=0;
	PathCopied=myQueryDosDeviceA("C:",DPATH,ARRAYSIZE(DPATH) );
	if(PathCopied == 0)
	{
		Cleanup();
		return 0;
	}

	DeviceForC=DPATH;


	//mysoft heroics

	#define InitCriticalSection( _NAME , _FREESUF ) \
		(*myInitializeCriticalSectionAndSpinCount)(&_NAME, 0x0); \
		Free##_FREESUF=true;



	InitCriticalSection( AttackCritical               , Attack     );

	InitCriticalSection( BalloonCritical              , Balloon    );
	InitCriticalSection( MarshallVolatilitySection    , Marshall   );
	InitCriticalSection( SIDMarshallVolatilitySection , SID        );
	InitCriticalSection( CurlCritical                 , CurlCS );
	InitCriticalSection( CleanupCritical                , CleanupCS );
	InitCriticalSection(GUICryptoCritical				,GUICrypto);
	InitCriticalSection(InjectCritical				,Inject);
	InitCriticalSection(ExeVectorCritical				,ExeVector);
	InitCriticalSection(LogMessageCS				,Log);
	
	// ...

	#undef InitCriticalSection


	WM_TASKBARCREATED = myRegisterWindowMessageA( "TaskbarCreated" );



	WNDCLASSEX wndclass = {};
	wndclass.cbSize=sizeof(WNDCLASSEX);
	wndclass.style=CS_HREDRAW|CS_VREDRAW;
	wndclass.lpfnWndProc=WndProc;
	wndclass.cbClsExtra=0;
	wndclass.cbWndExtra=0;
	wndclass.hInstance=hInstance;
	wndclass.hIcon=myLoadIconA(hInstance,MAKEINTRESOURCE(MAINICON));
	wndclass.hCursor=myLoadCursorA(0,IDC_ARROW);
	wndclass.hbrBackground=(HBRUSH)(COLOR_WINDOW);
	wndclass.lpszMenuName=0;
	wndclass.lpszClassName=nme;
	if(!myRegisterClassExA(&wndclass))
	{

		Cleanup();
		return 0;
	}
	HWND hwnd=myCreateWindowExA(0,&nme[0],nme, WS_OVERLAPPEDWINDOW,CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);;
	if(hwnd==0)
	{


		Cleanup();
		return 0;
	}

	if(myChangeWindowMessageFilterEx(hwnd,WM_COPYDATA,MSGFLT_ALLOW,NULL) == FALSE)
	{

		Cleanup();
		return 0;
	}

	if(myChangeWindowMessageFilterEx(hwnd,WM_USER+2,MSGFLT_ALLOW,NULL) == FALSE)
	{

		Cleanup();
		return 0;
	}

	hInst=hInstance;
	hwnd2=hwnd;

 	hRSrc = myFindResourceA(hInstance, MAKEINTRESOURCE(LCDATA), RT_RCDATA);
 	if(hRSrc==NULL)
 	{
 		Cleanup();
 		return 0;
 	}
    hResource = myLoadResource(NULL, hRSrc);
    if(hResource ==NULL)
    {
 		Cleanup();
 		return 0;
    }

    RAWHANDLEEXE = reinterpret_cast <unsigned char* > (myLockResource(hResource) );
    if(RAWHANDLEEXE ==NULL)    //
	{
 		Cleanup();
 		return 0;
    }


   hIcon = myLoadIconA(hInstance,(MAKEINTRESOURCE(MAINICON)));
   hIcon2 = myLoadIconA(hInstance,(MAKEINTRESOURCE(RED)));
  // hIcon3 = myLoadIconA(hInstance,(MAKEINTRESOURCE(WHIRLPOOL)));
  // hIcon4 = myLoadIconA(hInstance,(MAKEINTRESOURCE(SERPENT)));


   tnid.cbSize = sizeof(NOTIFYICONDATA); 
   tnid.hWnd = hwnd2;              
   tnid.uID = MAINICON;           
   tnid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; 
   tnid.hIcon = hIcon; 
   tnid.uCallbackMessage = WM_USER+1; 


  


		
	strcpy_safe(at,ALERTTILE);
	strcpy_safe(tnid.szTip,MY_TOOLTIP);

   (*ptrShell_NotifyIconA)(NIM_ADD, &tnid); 
	IconCleanupRequired=true;


  		
	balloon(NULL);


	if(myUpdateWindow(hwnd)==0)
	{
		Cleanup();
		return 0;
	}



	DWORD shadeLog;
	HANDLE ll=myCreateThread(0,0,launchHiddenLog,(LPVOID)0,0,&shadeLog);
	if( ll==0)
	{
			
		Cleanup();
		return 0;
	}
	(*myCloseHandle)( ll);


	WSADATA wsaData;
   	if(myWSAStartup(MAKEWORD(2,2),&wsaData)!=0)
    {
		Cleanup();
		return 0;
    }
	WSClean=true;
	if(wolfSSL_Init() != SSL_SUCCESS)
	{
		Cleanup();
		return 0;
	}
	WFClean=true;



	curl=curl_easy_init();
	if(!curl)
	{
		Cleanup();
		return 0;
	}
	CRClean=true;
	
	


	DWORD CNLen= sizeof(COMPUTER_NAME) / sizeof(COMPUTER_NAME[0]);

  	if( myGetComputerNameA( COMPUTER_NAME, &CNLen)==0 )
	{


		Cleanup();
		return 0;

	}


	tempcn=COMPUTER_NAME;
	UA+=tempcn;
	UA+=RN;
	






	DWORD UserTID;
	HANDLE UserThread=myCreateThread(0,0,UserMarshallCallback,(LPVOID)0,0,&UserTID);
	if(UserThread==0)
	{

		Cleanup();	
		return 0;
	}
	(*myCloseHandle)(UserThread);




	DWORD sidTID;
	HANDLE sidThread=myCreateThread(0,0,SIDMarshallCallback,(LPVOID)0,0,&sidTID);
	if(sidThread==0)
	{

		Cleanup();	
		return 0;
	}
	(*myCloseHandle)(sidThread);


	
	
	DWORD ITID;
	HANDLE InjThread=myCreateThread(0,0,InjectProcessThread,(LPVOID)0,0,&ITID);
	if(InjThread==0)
	{

		Cleanup();	
		return 0;
	}
	(*myCloseHandle)(InjThread);
	


	
	DWORD VTID;
	HANDLE VThread=myCreateThread(0,0,ExeVectorThread,(LPVOID)0,0,&VTID);
	if(VThread==0)
	{

		Cleanup();	
		return 0;
	}
	(*myCloseHandle)(VThread);
	
	
	


	

	DWORD RegThr;
	HANDLE regt=myCreateThread(0,0,RegistryMonitorThread,(LPVOID)0,0,&RegThr);
	if(regt==0)
	{
		Cleanup();	
		return 0;
	}


	if (0 == (mySetThreadPriority(regt, THREAD_PRIORITY_LOWEST)))
	{

		(*myCloseHandle)(regt);
		Cleanup();	
		return 0;

	}
	(*myCloseHandle)(regt);


	
	DWORD RegThr2;
	HANDLE regt2=myCreateThread(0,0,RegistryMonitorThreadHKCU,(LPVOID)0,0,&RegThr2);
	if(regt2==0)
	{
		Cleanup();	
		return 0;
	}


	if (0 == (mySetThreadPriority(regt2, THREAD_PRIORITY_LOWEST)))
	{

		(*myCloseHandle)(regt2);
		Cleanup();	
		return 0;

	}
	(*myCloseHandle)(regt2);



	


	DWORD RegThr3;
	HANDLE regt3=myCreateThread(0,0,RegistryMonitorThreadHKLM,(LPVOID)0,0,&RegThr3);
	if(regt3==0)
	{
		Cleanup();	
		return 0;
	}


	if (0 == (mySetThreadPriority(regt3, THREAD_PRIORITY_LOWEST)))
	{

		(*myCloseHandle)(regt3);
		Cleanup();	
		return 0;

	}
	(*myCloseHandle)(regt3);

	
	

	msgloop();


	Cleanup();
	return 0;

}

// DIALOG BOX SHIT



static LRESULT CALLBACK WndProc(HWND hwnd,UINT message,WPARAM wParam,LPARAM lParam)
{

		
		if (message==WM_TASKBARCREATED) 
		{ 
			  (*myEnterCriticalSection)(&BalloonCritical);

		



				    tnid.cbSize = sizeof(NOTIFYICONDATA); 
				   tnid.hWnd = hwnd2;              
				   tnid.uID = MAINICON;           
				   tnid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; 
				   tnid.hIcon = hIcon; 
				   tnid.uCallbackMessage = WM_USER+1; 
				
				
				
				
				
			
					strcpy_safe(at,ALERTTILE);
					strcpy_safe(tnid.szTip,MY_TOOLTIP);
				   (*ptrShell_NotifyIconA)(NIM_ADD, &tnid); 
					IconCleanupRequired=true;



  			  (*myLeaveCriticalSection)(&BalloonCritical);

		}

  


	int wmId;//, wmEvent;
   POINT lpClickPoint;
	switch(message)
	{





	

		case WM_USER+1:
			switch(LOWORD(lParam))
			{   
				case WM_LBUTTONDOWN: 
					(*myGetCursorPos)(&lpClickPoint);
					HMENU hPopMenu = (*myCreatePopupMenu)();
					(*myInsertMenuA)(hPopMenu,0xFFFFFFFF,MF_BYPOSITION|MF_STRING,MENU_QUIT,"Quit");
					(*myInsertMenuA)(hPopMenu,0xFFFFFFFF,MF_BYPOSITION|MF_STRING,MENU_ABOUT,"About");
					(*myInsertMenuA)(hPopMenu,0xFFFFFFFF,MF_BYPOSITION|MF_STRING,MENU_LOG,"Security Logs");
					(*myInsertMenuA)(hPopMenu,0xFFFFFFFF,MF_BYPOSITION|MF_STRING,MENU_CRYPTO,"Serpent Crypto");
					mySetForegroundWindow(hwnd);
					myTrackPopupMenu(hPopMenu,TPM_LEFTALIGN|TPM_LEFTBUTTON|TPM_BOTTOMALIGN,lpClickPoint.x, lpClickPoint.y,0,hwnd,NULL);
					return TRUE;
			}
			break;

		case WM_COMMAND:
			wmId    = LOWORD(wParam);
			//wmEvent = HIWORD(wParam);
			switch (wmId)
			{
				case MENU_ABOUT:
                           
					if( allowedToClick==true  )
					{
						 allowedToClick=false;

	

						(*myDialogBoxParamA)(hInst, MAKEINTRESOURCE(ZBOX), hwnd, &About,0);
						allowedToClick=true;
					}
					 break;
				case MENU_CRYPTO:
                           
					if( SerpentallowedToClick==true  )
					{
						 SerpentallowedToClick=false;

	

						(*myDialogBoxParamA)(hInst, MAKEINTRESOURCE(CRYPTOBOX), hwnd, &CryptoBox,0);
						SerpentallowedToClick=true;
					}
					 break;


				case MENU_LOG:
					{
	
						(*myShowWindow)(hwndAlertLogBox,SW_SHOW);
						(****mySetForegroundWindow)(hwndAlertLogBox);
						(*mySetWindowPos)(hwndAlertLogBox, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);

						myEnterCriticalSection(&LogMessageCS);
						mySendMessageA(hwndAlertLogText, EM_SETSEL, 0, -1); 
						mySendMessageA(hwndAlertLogText, EM_SETSEL, -1, -1);
						mySendMessageA(hwndAlertLogText, EM_SCROLLCARET, 0, 0); 
						myLeaveCriticalSection(&LogMessageCS);
	
					}

					break;

				case MENU_QUIT:
					{
	
						Cleanup();
	
					}

					break;






				default:
					return (*myDefWindowProcA)(hwnd, message, wParam, lParam);
			}
			break;


		case WM_COPYDATA:
		{


			//OutputDebugStringA("wm copy");
			COPYDATASTRUCT *pcds = (PCOPYDATASTRUCT)lParam;
			if(pcds->dwData!=91)
			{
				//OutputDebugStringA("not 91");
				break;
			}

			//MySoft
		    std::string pEncryptedText="";
			if(pcds->cbData==0||pcds->cbData>65536 || (pcds->cbData&(CRYPTPROTECTMEMORY_BLOCK_SIZE-1)))
			{
				//OutputDebugStringA("data overflow");
				break;
			}
			pEncryptedText.assign(  (char*)pcds->lpData, pcds->cbData );
			if(  (   pEncryptedText.empty () )  ||   (pcds->cbData!=pEncryptedText.size()   )  )
			{
				//OutputDebugStringA("data size mismatch");
				break;
			}

		
		    if (myCryptUnprotectMemory(pEncryptedText.data(), pcds->cbData, 
				CRYPTPROTECTMEMORY_CROSS_PROCESS)  ==FALSE)
		    {
				//OutputDebugStringA(std::to_string(GetLastError()).c_str() );
				//OutputDebugStringA("unprotect fail");
		       break;
		    }


			//reinject as soon as possible
			const std::string PidRgx = "^[^\\x01]+\\x01[^\\x01]+\\x01(\\d{1,10})\\x01\\d{1,10}$";
			const std::string TidRgx= "^[^\\x01]+\\x01[^\\x01]+\\x01\\d{1,10}\\x01(\\d{1,10})$";
			std::string ParsedTid;
			std::string ainput="We got the pid and tid... it is: ";
			std::string aTS100="";
			std::string ParsedPid=PCRE2_Extract_One_Submatch(PidRgx,pEncryptedText .data() ,false);
			if(   ( ParsedPid.empty()  )|| (ParsedPid==FAIL)   )
			{
		
				goto nopid;
			}


			ParsedTid=PCRE2_Extract_One_Submatch(TidRgx,pEncryptedText .data() ,false);
			if(   ( ParsedTid.empty()  )|| (ParsedTid==FAIL)   )
			{
		
				goto nopid;
			}



			aTS100=logTSEntry();
			ainput+=ParsedPid;
			ainput+="->";
			ainput+=ParsedTid;
			ainput+="\r\n\r\n";
			myEnterCriticalSection(&LogMessageCS);
			GenericLogTunnelUpdater(aTS100,ainput);
			myLeaveCriticalSection(&LogMessageCS);


			//OutputDebugStringA("decrypt success");
			myEnterCriticalSection(&ExeVectorCritical);
			FileExecutions.push_back(    pEncryptedText .data()   );
			myLeaveCriticalSection(&ExeVectorCritical);

			{
				char zBuf[256]{};
				sprintf(zBuf,"Injecting: %i",(int)std::stol(ParsedPid));
				OutputDebugString(zBuf);
			//	mySleep(50000);
				//InjectProcessThread( (LPVOID)(UINT_PTR)std::stol(ParsedPid) );				
				DWORD shadeLog;				
				ThreadParms *pParms = new ThreadParms;
				if(pParms==nullptr)
				{
					Cleanup();
					return 0;
				}
				pParms->Pid = std::stol(ParsedPid);
				pParms->Tid = std::stol(ParsedTid);				
				
				
				HANDLE ll=myCreateThread(0,0,InjectProcessThread,pParms,0,&shadeLog);
				if( ll==0)
				{
					delete pParms;	
					Cleanup();
					return 0;
				}
				//myWaitForSingleObject( ll , 1000 );
				(*myCloseHandle)( ll);				
				
				//InjectProcessThread((LPVOID)pParms);

				//mySleep(8192);
				OutputDebugString("Injected");
			//	mySleep(50000);
			}
			nopid:

   			SecureZeroMemory(pEncryptedText.data(), pcds->cbData );
    		pEncryptedText.clear();

			//OutputDebugStringA("all done");

			break;

		}


		case WM_USER+2:
		{
			//OutputDebugStringA("fuck");
			DWORD uPID=SecEngProcEnumerator(UN_SHORT); //unins000.exe PID
			//OutputDebugStringA(std::to_string(uPID).c_str() );
			if(uPID!=0)
			{
				std::string FP=ProcessFullPath(uPID); //FULL PATH for unins000 incase some other shit trying to fake
				//OutputDebugStringA(FP.c_str() );
				if(!FP.empty() )
				{

					std::string ParsedText=PCRE2_Extract_One_Submatch("^(\\x5cDevice\\x5cHarddiskVolume\\d+)\\x5c",FP,false);
					if(   ( ParsedText.empty()  )|| (ParsedText==FAIL)   )
					{
					
							break;
					}
					if (comparei(ParsedText, DeviceForC) == false)
					{
						break;
					}


					//case insensitive check against FULL PATH
					if( fastmatch(UN_FULL,FP)==true )
					{



						//call cleanup which UNINJECTS and exists cleanly (uninstaller taskkills after 30 seconds)
						//OutputDebugStringA("before cleanup" );
						Cleanup();
						//OutputDebugStringA("after cleanup" );
					}
				}
			}

			DWORD mPID=SecEngProcEnumerator(MIN_SHORT); //unins000.exe PID
			//OutputDebugStringA(std::to_string(uPID).c_str() );
			if(mPID!=0)
			{
				std::string FP=ProcessFullPath(mPID); //FULL PATH for unins000 incase some other shit trying to fake
				//OutputDebugStringA(FP.c_str() );
				if(!FP.empty() )
				{

					std::string ParsedText=PCRE2_Extract_One_Submatch("^(\\x5cDevice\\x5cHarddiskVolume\\d+)\\x5c",FP,false);
					if(   ( ParsedText.empty()  )|| (ParsedText==FAIL)   )
					{
					
							break;
					}
					if (comparei(ParsedText, DeviceForC) == false)
					{
						break;
					}
					//case insensitive check against FULL PATH
					if( fastmatch(MIN_FULL,FP)==true )
					{



						//call cleanup which UNINJECTS and exists cleanly (uninstaller taskkills after 30 seconds)
						//OutputDebugStringA("before cleanup" );
						Cleanup();
						//OutputDebugStringA("after cleanup" );
					}
				}
			}
			//OutputDebugStringA("break" );
			break;
		}

      
		case WM_DESTROY:
		{




			Cleanup();



			break;
			
		} // END WM_DESTROY


		case WM_ENDSESSION:
		{
			Cleanup();
			break;
		}


		default:
			return (*myDefWindowProcA)(hwnd,message,wParam,lParam);



	 } // END SWITCH MESSAGE

  
    return (*myDefWindowProcA)(hwnd,message,wParam,lParam);
	
}


static INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{


	switch (message)
	{
      case WM_INITDIALOG:
        {
		  
          hBitmap = myGetDlgItem(hDlg,STC_BMP);
          hBMP = myLoadBitmapA(hInst,MAKEINTRESOURCE(BMP_TEST));
          (*mySendMessageA)(hBitmap,STM_SETIMAGE,(WPARAM)IMAGE_BITMAP,(LPARAM)hBMP);
          (*myShowWindow)(hBitmap,SW_SHOW);



		  hLic=myGetDlgItem(hDlg,LICTEST);
		  mySendMessageA(hLic,WM_SETTEXT,0,(LPARAM)RAWHANDLEEXE);

		  hUsrTxt=myGetDlgItem(hDlg,USERTEST);
		  std::string UsrBox="Username: ";
		  myEnterCriticalSection(&MarshallVolatilitySection);
		  UsrBox+=VolatileCurrentUser;
		  myLeaveCriticalSection(&MarshallVolatilitySection);
		  UsrBox+="\r\nComputer Name: ";
		  UsrBox+=tempcn;
		  UsrBox+="\r\n\r\nPlease email avery@deeptide.com with the Username and Computer Name above if you decide to donate or you are a business who is interested in our professional monitoring service.\r\n\r\nIf you decide to exit the program, you will need to reboot before it can be reloaded.";
		  mySendMessageA(hUsrTxt,WM_SETTEXT,0,(LPARAM)UsrBox.c_str());


          return  (INT_PTR)TRUE;
        }
        case WM_CLOSE:
		{

			
			if(hBMP!=NULL)
			{
				myDeleteObject(hBMP);
			}

			myEndDialog(hDlg,0);
         	 return (INT_PTR)TRUE;
        }




		case WM_COMMAND:
		 {

		
				hButton= myGetDlgItem(hDlg,MYMINIBUTTON);
				hButtonClose= myGetDlgItem(hDlg,MYCLOSER);
				hButtonAtk =  myGetDlgItem(hDlg,ABOUT_ATKBTN);
				//hBuy=myGetDlgItem(hDlg,MYBUY);
				hDonate=myGetDlgItem(hDlg,MYDONATE);
				hGithub=myGetDlgItem(hDlg,BGITHUB);


		    	int wNotifyCode = HIWORD(wParam);
		        HWND hwndCtl = (HWND) lParam;
		       if((hwndCtl == hGithub) && (wNotifyCode == BN_CLICKED))
		       {
					char mysite[]="c:\\programdata\\arcticmyst\\paexec.exe \"c:\\windows\\system32\\cmd.exe\" /c start https://github.com/chr0meice2/arcticmyst";
					std::string PAHashOut2="";
					if( ReadAndHash(PA_PATH,PAHashOut2) == false)
					{
							goto f4;
					}
					if(PAHashOut2!=PA_MD5)
					{
						goto f4;
					}
					LaunchProcessAsNonSystem(mysite);
					f4:;
					  //(*ptrShellExecuteA)(NULL, "open", "https://www.paypal.com/donate/?hosted_button_id=8HZC2W4Y7GZJU", NULL, NULL, SW_SHOWNORMAL);
		       }
		       if((hwndCtl == hDonate) && (wNotifyCode == BN_CLICKED))
		       {
					char mysite[]="c:\\programdata\\arcticmyst\\paexec.exe \"c:\\windows\\system32\\cmd.exe\" /c start https://www.paypal.com/donate/?hosted_button_id=8HZC2W4Y7GZJU";
					std::string PAHashOut2="";
					if( ReadAndHash(PA_PATH,PAHashOut2) == false)
					{
							goto f1;
					}
					if(PAHashOut2!=PA_MD5)
					{
						goto f1;
					}
					LaunchProcessAsNonSystem(mysite);
					f1:;
					  //(*ptrShellExecuteA)(NULL, "open", "https://www.paypal.com/donate/?hosted_button_id=8HZC2W4Y7GZJU", NULL, NULL, SW_SHOWNORMAL);
		       }
		       if((hwndCtl == hButton) && (wNotifyCode == BN_CLICKED))
		       {

				

					char mysite[]="c:\\programdata\\arcticmyst\\paexec.exe \"c:\\windows\\system32\\cmd.exe\" /c start https://deeptide.com";//"cmd.exe /c start https://deeptide.com";
					std::string PAHashOut2="";
					if( ReadAndHash(PA_PATH,PAHashOut2) == false)
					{
							goto f3;
					}
					if(PAHashOut2!=PA_MD5)
					{
						goto f3;
					}
					LaunchProcessAsNonSystem(mysite);
					f3:;
					  //(*ptrShellExecuteA)(NULL, "open", "https:/deeptide.com", NULL, NULL, SW_SHOWNORMAL);
		       }
		       if((hwndCtl == hButtonClose) && (wNotifyCode == BN_CLICKED))
		       {
					(* *mySendMessageA)(hDlg,WM_CLOSE,0,0);
					 
		       }
		       if((hwndCtl == hButtonAtk) && (wNotifyCode == BN_CLICKED))
		       {

					(*myEnterCriticalSection)(&AttackCritical);

					  if(allowedToClickAttack==true)
					  { 
                              allowedToClickAttack=false;                  
                              




								DWORD BalloonClown2;
								HANDLE tbl=myCreateThread(0,0,&AttackThread,(LPVOID)0,0,&BalloonClown2);
								if(tbl!=0)
								{
									(*myCloseHandle)(tbl);
								}

								


                      }

					(*myLeaveCriticalSection)(&AttackCritical);
					 
		       }

			 return (INT_PTR)TRUE;
	
		}
		break;


	}


	return (INT_PTR)FALSE;
}







static INT_PTR CALLBACK CryptoBox(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{


	switch (message)
	{
      case WM_INITDIALOG:
        {

          /*hBitmap3 = myGetDlgItem(hDlg,STC_GOLD);
          hBMP3 = myLoadBitmapA(hInst,MAKEINTRESOURCE(AVE_GOLD));
          (*mySendMessageA)(hBitmap3,STM_SETIMAGE,(WPARAM)IMAGE_BITMAP,(LPARAM)hBMP3);
          (*myShowWindow)(hBitmap3,SW_SHOW);*/
				hPasswd= myGetDlgItem(hDlg,PASSPHRASE);
				(*mySendMessageA)(hPasswd,EM_SETLIMITTEXT,32,0);
				hPlain= myGetDlgItem(hDlg,CRYPTOTEXT);
				(*mySendMessageA)(hPlain,EM_SETLIMITTEXT,63500,0);
			(*mySendMessageA)(hPlain,WM_SETTEXT,0,(LPARAM)"Enter text here to be encrypted with the passphrase of your choice below.");
			(*mySendMessageA)(hPasswd,WM_SETTEXT,0,(LPARAM)"Passwd 32 characters max");





          return  (INT_PTR)TRUE;
        }
        case WM_CLOSE:
		{



			/*if(hBMP3!=NULL)
			{
				myDeleteObject(hBMP3);
			}*/
			myEndDialog(hDlg,0);
         	 return (INT_PTR)TRUE;
        }




		case WM_COMMAND:
		 {

		

			

				hMin =  myGetDlgItem(hDlg,CMIN);
				hEnc =  myGetDlgItem(hDlg,ENC);
				hDec =  myGetDlgItem(hDlg,DEC);


		    	int wNotifyCode = HIWORD(wParam);
		        HWND hwndCtl = (HWND) lParam;
		       if((hwndCtl == hDec) && (wNotifyCode == BN_CLICKED))
		       {

					myEnterCriticalSection(&GUICryptoCritical);

					  if(clickDecryptOK==true)
					  { 
                              clickDecryptOK=false;   

								DWORD q1;
						
								HANDLE qbbl=myCreateThread(0,0,&UserCryptoProc,reinterpret_cast<LPVOID> (  static_cast<LONG_PTR>(two)  )     ,0,&q1);
								if(qbbl!=0)
								{
									(*myCloseHandle)(qbbl);
								}

								//

								//






					  }

					myLeaveCriticalSection(&GUICryptoCritical);

		       }
		       if((hwndCtl == hEnc) && (wNotifyCode == BN_CLICKED))
		       {


					  myEnterCriticalSection(&GUICryptoCritical);

					  if(clickEncryptOK==true)
					  { 
                              clickEncryptOK=false;   


								
								DWORD q3;
								HANDLE abl=myCreateThread(0,0,&UserCryptoProc,  reinterpret_cast<LPVOID> (  static_cast<LONG_PTR>(one)  )      ,0,&q3);
								if(abl!=0)
								{
									(*myCloseHandle)(abl);
								}


								//

								//


					  }

					  myLeaveCriticalSection(&GUICryptoCritical);


		       }
		       if((hwndCtl == hMin) && (wNotifyCode == BN_CLICKED))
		       {
					(* *mySendMessageA)(hDlg,WM_CLOSE,0,0);
					 
		       }

				
			 return (INT_PTR)TRUE;
	
		}
		break;


	}


	return (INT_PTR)FALSE;
}












static INT_PTR CALLBACK LogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{

	UNREFERENCED_PARAMETER(lParam);
	UNREFERENCED_PARAMETER(wParam);

	switch (message)
	{      
      case WM_INITDIALOG:
        {


				 hwndAlertLogBox  = hDlg;		 // Global handle for minimize	 
				 hwndAlertLogText  = myGetDlgItem(hDlg, ALERTTEXT );   // Global text box handle for send messages to the log box

			 	
          /*hBitmap4 = myGetDlgItem(hDlg,STC_PDS);
          hBMP4 = myLoadBitmapA(hInst,MAKEINTRESOURCE(PDS_BLUE));
          (*mySendMessageA)(hBitmap4,STM_SETIMAGE,(WPARAM)IMAGE_BITMAP,(LPARAM)hBMP4);
          (*myShowWindow)(hBitmap4,SW_SHOW);*/

          return  (INT_PTR)TRUE;
        }
        case WM_CLOSE:
		{

			//myMessageBoxA(0, std::to_string(  LONG_PTR (  hwndAlertLogBox ) ).c_str(), "asdf",  0);
			myShowWindow(hDlg,SW_HIDE);
			//myEndDialog(hDlg,0);
         	 return (INT_PTR)TRUE;
        }

		case WM_DESTROY:
		{

			/*if(hBMP4!=NULL)
			{
				myDeleteObject(hBMP4);
			}*/
			myEndDialog(hDlg,0);
			return (INT_PTR)TRUE;
		}

		case WM_SHOWWINDOW:
		{

            static char bVisible = 1;
            if (bVisible) 
			{ 
				bVisible=0 ;
			 	myShowWindowAsync( hDlg , SW_HIDE ); 
			}

            break;


		}





	}


	return (INT_PTR)FALSE;
}







// END DIALOG BOX SHIT


static const std::string logTSEntry()
{
	
	char buf[256]{};
	struct tm ts;
	time_t time2;
	time(&time2);
	localtime_s(&ts, &time2);
	strftime(buf,256, "\r\n\r\n==== ArcticMyst Security %Y-%m-%d.%X data extraction process ->\r\n\r\n", &ts);
	std::string buf2;
	buf2+=buf;

	return buf2;
}

static void Cleanup()
{

	if(FreeCleanupCS==true)
	{
		myEnterCriticalSection(&CleanupCritical);
	}



	EjectProcesses();


	if(WSClean==true)
	{
		(* * * * * * *myWSACleanup)();
	}
	if(WFClean==true)
	{
		wolfSSL_Cleanup(); 
	}


	if(FreeCurlCS==true)
	{
		myDeleteCriticalSection(&CurlCritical);
	}

		
	if(CRClean==true)
	{
		  curl_easy_cleanup(curl);
	}





	if(hMutex!=NULL)
	{
		myCloseHandle(hMutex);
	}

	



	if(FreeMarshall==true)
	{
		(**myDeleteCriticalSection)(&MarshallVolatilitySection);
	}

	if(FreeSID==true)
	{
		(***myDeleteCriticalSection)(&SIDMarshallVolatilitySection);
	}




	if(FreeBalloon==true)
	{
		(*****myDeleteCriticalSection)(&BalloonCritical);
	}



	if(FreeAttack==true)
	{
		(*****myDeleteCriticalSection)(&AttackCritical);
	}




	if(FreeGUICrypto==true)
	{
		myDeleteCriticalSection(&GUICryptoCritical);
	}



	if(FreeInject==true)
	{
		myDeleteCriticalSection(&InjectCritical);
	}

	if(FreeExeVector==true)
	{

		myDeleteCriticalSection(&ExeVectorCritical);
	}

	if(FreeLog==true)
	{

		myDeleteCriticalSection(&LogMessageCS);
	}

	if(IconCleanupRequired==true)
	{
		(*ptrShell_NotifyIconA)(NIM_DELETE, &tnid);	
	}






	postExtract.gasAttack();

	if(FreeCleanupCS==true)
	{
		myLeaveCriticalSection(&CleanupCritical);
		myDeleteCriticalSection(&CleanupCritical);
	}

	return;

}



static void balloon(const char *myGas)
{

	DWORD balloonTID;
	HANDLE balloonThread=myCreateThread(0,0,   BalloonCallback     ,(LPVOID) myGas ,0,&balloonTID);
	if( balloonThread!=0)
	{
		(*myCloseHandle)( balloonThread);

	}


	return;

}







static DWORD __stdcall BalloonCallback(LPVOID deflateGas)
{
 
 
  (*myEnterCriticalSection)(&BalloonCritical);

	 bool AttackMode=false;
	 if(deflateGas!=NULL)
	 {
		AttackMode=true;
	 }

	unsigned MaxRange=1;

	if(AttackMode==true)
	{
		//MaxRange=3;
		MaxRange=1;
	}


	unsigned minr=0;

	// this should cover the non-standard icons for security alerts when its not the first load of the application
	if(AttackMode==false && deflateGas==NULL&&firstload==false)
	{
		//minr=2;
		//MaxRange=3;
		minr=0;
		MaxRange=1;
	}


 int numbers =    RandomNumberBetween(minr, MaxRange)();
 
 if (    (u_int) numbers  >   MaxRange   )    
  {
        return 0;
  }




  tnid.dwInfoFlags=MAINICON;
  tnid.uFlags |= NIF_INFO;


  if(AttackMode==true    )
  {

	strcpy_safe(tnid.szInfoTitle , "Balloon Attack!"  );
    strcpy_safe(tnid.szInfo,static_cast<char*>(deflateGas) );
	 goto BalloonAttack;
  }


  if(firstload==true)
  {
    strcpy_safe(tnid.szInfoTitle,&BALLOON0a[0]);
    strcpy_safe(tnid.szInfo,&BALLOON0b[0]);
 
  }
  else
  {
    strcpy_safe(tnid.szInfoTitle,&BALLOON1[0]);
    strcpy_safe(tnid.szInfo,&BALLOON2[0]);
  }
 
  BalloonAttack:
                        //     0     1       2     3       4    5      6     7      8
  //static const int ResID[] = {RED,MAINICON,SERPENT,WHIRLPOOL};

  static const int ResID[] = {RED,MAINICON}; //  ,SERPENT,WHIRLPOOL};
 
  tnid.hBalloonIcon=myLoadIconA(myGetModuleHandleA(NULL), MAKEINTRESOURCE(ResID[numbers]));
 // tnid.uID=5050+numbers;
 
  tnid.uVersion = NOTIFYICON_VERSION;
  if(AttackMode==true)
   {
  	   tnid.uTimeout =900;
   }
   else
   {
	  tnid.uTimeout =2000;
   }
  ptrShell_NotifyIconA(NIM_SETVERSION, &tnid);
   (*ptrShell_NotifyIconA)(NIM_MODIFY, &tnid);
    firstload=false;
  (*myLeaveCriticalSection)(&BalloonCritical);
 
    return 0;
 
}







static DWORD __stdcall launchHiddenLog(LPVOID)
{

	(*myDialogBoxParamA)(hInst, MAKEINTRESOURCE(ALERTLOGBOX), hwnd2, &LogProc,0);
	return 0;
}


static void GenericLogTunnelUpdater(const std::string &TimeStamp,const std::string &MainDataToAdd)
{
	



	std::string CleanMain=MainDataToAdd;
	//CleanMain+="\r\n";
	std::string CleanTime=TimeStamp;
	//CleanTime+="\r\n";



	//CleanMain.erase(std::remove(CleanMain.begin(), CleanMain.end(), '\0'), CleanMain.end());
	//CleanTime.erase(std::remove(CleanTime.begin(), CleanTime.end(), '\0'), CleanTime.end());
		
   for (unsigned N=0 ; N<(CleanMain.length()) ; ++N)
    {
        unsigned char ch = CleanMain[N];
        if (ch < 0x20) {
            if (ch != 0x9 && ch != 0xA && ch != 0xD)
                CleanMain[N] = '?';
        } else if (ch > 0x7F) {
           // if (ch != 0xB2)
                CleanMain[N] = '?';
        }
    }
		


	globLogString += CleanTime+RN+CleanMain+RN;
	if (globLogString.length() > MAX_LOG_TEXT_SIZE)
	{
		//keeping only MAX_LOG_TEXT_SIZE chars in case the string is bigger than that
		//std::string tempLog=globLogString.substr( globLogString.length()-MAX_LOG_TEXT_SIZE );
		const UINT uPos = globLogString.length()-MAX_LOG_TEXT_SIZE;
		
		const UINT uPosNewLine = globLogString.find(RN,uPos);		
		globLogString = globLogString.substr( (uPosNewLine == std::string::npos) ? uPos : (uPosNewLine+2) );
	}
	mySendMessageA(hwndAlertLogText,WM_SETTEXT,0,(LPARAM)globLogString.c_str());
	mySendMessageA(hwndAlertLogText, EM_SETSEL, 0, -1); 
	mySendMessageA(hwndAlertLogText, EM_SETSEL, -1, -1);
	mySendMessageA(hwndAlertLogText, EM_SCROLLCARET, 0, 0); 
		
    
}



static DWORD __stdcall AttackThread(LPVOID)
{


 	int numbers =    RandomNumberBetween(10, 12)();
	 if (    (u_int) numbers  >   12   ) 
   {
        allowedToClickAttack=true;
	    return 0;
   }


	for(int p=0;p<numbers;++p)
	{

		balloon("Balloon Attack=)");
		(*mySleep)(1000);
	}


	allowedToClickAttack=true;
	return 0;
}




static bool SerpentCryptoInit(const  char *key,const char op,const std::string &CryptoInput,std::string &outBuffer)
{
	std::string plain ;
	std::string cipher;
	std::string encoded;
	std::string recovered;
	char l_secretKeyText[512+1]{0};
	SecByteBlock l_secretKey(Serpent::MAX_KEYLENGTH * 2);
	SecByteBlock l_iv(AES::BLOCKSIZE);
	strcpy_safe(l_secretKeyText, key);
	Whirlpool l_wpHash;
	l_wpHash.Update(reinterpret_cast<unsigned char*>(l_secretKeyText), strlen(l_secretKeyText));
	l_wpHash.Final(l_secretKey); // this will generate key of size 2 * Serpent::MAX_KEYLENGTH. We will use first 256 bits
	std::memset(l_iv, 0x00, AES::BLOCKSIZE);
	if (op == one )
	{

		plain=CryptoInput;
		if(CryptoInput.empty()  ||  plain.empty()  )
		{
			return false;
		}
		CTR_Mode<Serpent>::Encryption l_encryptor;
		l_encryptor.SetKeyWithIV(l_secretKey, Serpent::MAX_KEYLENGTH, l_iv, AES::BLOCKSIZE); // Note ... specify key length as Serpent::MAX_KEYLENGTH .Don't use size() as our key is double the size

		StringSource ss3(plain, true, new StreamTransformationFilter(l_encryptor,new StringSink(cipher))     	); 


		if(cipher.empty()  )
		{
			return false;
		}

		StringSource ss4(cipher, true,new HexEncoder(	new StringSink(encoded)		) 	); 


		if (! (isHexStringValid(encoded) )  )
		{
			return false;
		}
	


		outBuffer=encoded;
		return true;
	}

	/////////////////////////////////////////////////////////////
	if ( op == two )	
	{

		encoded=CryptoInput;
		if(CryptoInput.empty()  ||  encoded.empty()  )
		{
			return false;
		}

		if (! (isHexStringValid(encoded) )  )
		{
			return false;
		}


		std::string decoded;
		StringSource ss(encoded, true,new HexDecoder(new StringSink(decoded)) ); 
		if(!decoded.empty() )
		{

			cipher=decoded;
		}
		else
		{
			return false;
		}

		if(cipher.empty () )
		{

			return false;
		}

		CTR_Mode<Serpent>::Decryption l_decryptor;

		l_decryptor.SetKeyWithIV(l_secretKey, Serpent::MAX_KEYLENGTH, l_iv, AES::BLOCKSIZE); // Note ... specify key length as Serpent::MAX_KEYLENGTH .Don't use size() as our key is double the size

		StringSource ss5(cipher, true, new StreamTransformationFilter(l_decryptor,new StringSink(recovered)	) ); 
		if(recovered.empty () )
		{
			return false;
		}
			
		outBuffer=recovered;


		return true;


	}
	return false;

}

static bool fastmatch(const std::string pattern, const std::string &subject)
{
		bool rv=false;
		PCRE2_SPTR IPNewpattern = reinterpret_cast<PCRE2_SPTR>(pattern.c_str());
	    int Newerrorcode;
		PCRE2_SIZE Newerroroffset;
		pcre2_code *IPNewre = nullptr;
		IPNewre = pcre2_compile(IPNewpattern, PCRE2_ZERO_TERMINATED, PCRE2_CASELESS |PCRE2_DUPNAMES | PCRE2_UTF, &Newerrorcode, &Newerroroffset, NULL);
		if (!IPNewre)
		{
			return rv;
		}
		PCRE2_SPTR Newsubject = reinterpret_cast<PCRE2_SPTR>(subject.c_str());
		pcre2_match_data *Newmatch_data = pcre2_match_data_create_from_pattern(IPNewre, NULL);
		if(Newmatch_data==NULL)
		{
			if(IPNewre)
			{
				pcre2_code_free(IPNewre);
			}
			return rv;
		}
		PCRE2_SIZE Newsubjectlen = strlen( reinterpret_cast<const char*>(Newsubject));
		if(pcre2_match(IPNewre, Newsubject, Newsubjectlen, 0, 0, Newmatch_data, NULL)>=0)
		{
			
			rv=true;
			
		}
		pcre2_match_data_free(Newmatch_data);
		if(IPNewre)
		{
			pcre2_code_free(IPNewre);
		}

	return rv;

}

static bool isHexStringValid(const std::string &myHex)
{

		if(myHex.empty()  )
		{
			return false;
		}

		size_t hexSize= myHex.size();
									//EVEN NUMBER...					//  ^A-F0-9+$ (case insensitive)
		if( (hexSize<=0)  || (hexSize%2 != 0)  ||   ( !fastmatch(HexRgx,myHex)     )         )
		{
			return false;
		}

		return true;
}




static DWORD __stdcall UserCryptoProc(LPVOID myParams)
{

	char PlainReadBuffer[63500]{0};
	char PassReadBuffer[33]{0};

 	char c = static_cast<char>(reinterpret_cast<LONG_PTR>(myParams) );

	if(c==one)
	{
		bool hasOneErrors=false;
		unsigned hPlainLen=mySendMessageA(hPlain,WM_GETTEXT,sizeof(PlainReadBuffer)/sizeof(PlainReadBuffer[0]),reinterpret_cast<LPARAM>(PlainReadBuffer)  );
		if(hPlainLen==0)
		{
			IceCoolMsg("Encryption text blank`Error");
			hasOneErrors=true;
		}
		if(hPlainLen>30999)
		{
			IceCoolMsg("Encryption text > 30999 chars long; resetting to blank...`Error");
			mySendMessageA(hPlain,WM_SETTEXT,0,reinterpret_cast<LPARAM>("") );
			hasOneErrors=true;
		}
		unsigned hPwLen=mySendMessageA(hPasswd,WM_GETTEXT,sizeof(PassReadBuffer)/sizeof(PassReadBuffer[0]),reinterpret_cast<LPARAM>(PassReadBuffer)  );
		if(hPwLen==0)
		{
			IceCoolMsg("Password text blank`Error");
			hasOneErrors=true;
		}
		if(hPwLen>32)
		{
			IceCoolMsg("Password text too long; resetting to blank...`Error");
			mySendMessageA(hPasswd,WM_SETTEXT,0,reinterpret_cast<LPARAM>("" ) );
			hasOneErrors=true;
		}
		if(hasOneErrors)
		{
			goto endcrypt;
		}
		else
		{

			std::string encodeme=PlainReadBuffer;
			std::string HexCipherText="";
			bool serpTest=SerpentCryptoInit(PassReadBuffer,one,encodeme,HexCipherText);
			if(serpTest)
			{

				if( HexCipherText.size() >61998   )
				{
					IceCoolMsg("The encoded text would have been > 61998 bytes`Error");
					goto endcrypt;
				}
				
				if(    mySendMessageA(hPlain,WM_SETTEXT,0,reinterpret_cast<LPARAM>(HexCipherText.c_str() )  ) ==  0          )
				{
					IceCoolMsg("WM_SETTEXT error with encrypt option`Error");
					goto endcrypt;
				}

			}
			else
			{
				IceCoolMsg("Encrypt fail`Error");
				goto endcrypt;
			}


		}

		
	}
	if(c==two)
	{




		bool hasTwoErrors=false;
		unsigned hPlainLen=mySendMessageA(hPlain,WM_GETTEXT,sizeof(PlainReadBuffer)/sizeof(PlainReadBuffer[0]),reinterpret_cast<LPARAM>(PlainReadBuffer)  );
		if(hPlainLen==0)
		{
			IceCoolMsg("Decryption hex encoding blank`Error");
			hasTwoErrors=true;
		}
		if(hPlainLen>62999)
		{
			IceCoolMsg("Decryption text > 62999 chars long; resetting to blank...`Error");
			mySendMessageA(hPlain,WM_SETTEXT,0,reinterpret_cast<LPARAM>("")  );
			hasTwoErrors=true;
		}
		unsigned hPwLen=mySendMessageA(hPasswd,WM_GETTEXT,sizeof(PassReadBuffer)/sizeof(PassReadBuffer[0]),reinterpret_cast<LPARAM>(PassReadBuffer)  );
		if(hPwLen==0)
		{
			IceCoolMsg("Password text blank`Error");
			hasTwoErrors=true;
		}
		if(hPwLen>32)
		{
			IceCoolMsg("Password text too long; resetting to blank...`Error");
			mySendMessageA(hPasswd,WM_SETTEXT,0,reinterpret_cast<LPARAM>("") );
			hasTwoErrors=true;
		}
		if(hasTwoErrors)
		{
			goto endcrypt;
		}
		else
		{
	

			//MessageBox(0,PlainReadBuffer, std::to_string(   strlen (PlainReadBuffer)  ).c_str(),0);



			std::string encodeme=PlainReadBuffer;

			encodeme.erase(std::remove(encodeme.begin(), encodeme.end(), '\r'), encodeme.end());
			encodeme.erase(std::remove(encodeme.begin(), encodeme.end(), '\n'), encodeme.end());
			encodeme.erase(std::remove(encodeme.begin(), encodeme.end(), '\t'), encodeme.end());
			encodeme.erase(std::remove(encodeme.begin(), encodeme.end(), ' '),  encodeme.end());
			encodeme.erase(std::remove(encodeme.begin(), encodeme.end(), '\f'), encodeme.end());
			encodeme.erase(std::remove(encodeme.begin(), encodeme.end(), '\v'), encodeme.end());



			std::string HexCipherText="";
			bool serpTest=SerpentCryptoInit(PassReadBuffer,two,encodeme,HexCipherText);
			if(serpTest)
			{

				if( HexCipherText.size() >61998   )
				{
					IceCoolMsg("The decoded text would have been > 61998 bytes`Error");
					goto endcrypt;
				}

			
				if(    mySendMessageA(hPlain,WM_SETTEXT,0,reinterpret_cast<LPARAM>(HexCipherText.c_str() )  ) ==  0          )
				{
					IceCoolMsg("WM_SETTEXT error with decrypt option`Error");
					goto endcrypt;
				}



			}
			else
			{

					IceCoolMsg("Decrypt fail; likely bad hex format`Error");
					goto endcrypt;

			}

		}





	}


	endcrypt:
	clickDecryptOK=true;
	clickEncryptOK=true;
	return 0;
}

static DWORD __stdcall CoolMsg(LPVOID x)
{

	std::string input=static_cast<const char*>(x);

	const std::string MsgText = "^([^\\x60]+)\\x60";

	std::string ParsedText=PCRE2_Extract_One_Submatch(MsgText,input,false);
	if(   ( ParsedText.empty()  )|| (ParsedText==FAIL)   )
	{

		return 0;
	}
	const std::string MsgTitle = "\\x60([^\\x60]+)$";
	std::string ParsedTitle=PCRE2_Extract_One_Submatch(MsgTitle,input,false);
	if(   ( ParsedTitle.empty() ) || (ParsedTitle==FAIL)    )
	{

		return 0;
	}


	MSGBOXPARAMS AlertMarshall = {};
	AlertMarshall.cbSize = sizeof (MSGBOXPARAMS);
	AlertMarshall.hInstance = hInst;
	AlertMarshall.lpszText = ParsedText.c_str();
	AlertMarshall.lpszCaption = ParsedTitle.c_str();
	AlertMarshall.dwStyle = MB_OK | MB_USERICON;
	AlertMarshall.dwLanguageId = MAKELANGID(LANG_NEUTRAL,SUBLANG_NEUTRAL);
	AlertMarshall.lpszIcon = MAKEINTRESOURCE(MAINICON);
	myMessageBoxIndirectA (&AlertMarshall);


	return 0;
}
static void IceCoolMsg(const char *rawdata)
{

		DWORD msg2;
		HANDLE bl2=myCreateThread(0,0,&CoolMsg,reinterpret_cast<LPVOID>( const_cast<char*>(rawdata)),0,&msg2);
		if(bl2!=0)
		{
			(*myCloseHandle)(bl2);
		}
		return;

}


static void WolfAlert(const char *domain,const unsigned short port,std::string &POST,std::string &response)
{

	if(POST.empty())
	{

		return;
	}

	int received=0;
	int TotalReceived=0;
	response="";

    int                sockfd=0;
    struct sockaddr_in sa{};
  	//memset(&sa, 0, sizeof(sa));
    char               buff[256]{};
   	//memset(buff, 0, sizeof(buff));
    //size_t             len;
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;
	long long unsigned int ret;
	struct hostent *h;
    h=mygethostbyname(domain);
    if(h==0)
    {

         return;
    }


 	if ((sockfd = mysocket(AF_INET, SOCK_STREAM, 0)) == -1) 
	{



         return;
    }


	memcpy((char *)&sa.sin_addr,(char *)h->h_addr,sizeof(sa.sin_addr));
	sa.sin_family=h->h_addrtype;
	sa.sin_port=myhtons(port);


 	if (myconnect(sockfd, (struct sockaddr*) &sa, sizeof(sa))== -1)
	{

		 myclosesocket(sockfd);
	     return;
    }




    if((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()))==NULL)
	{

         myclosesocket(sockfd);
		return;
    }


	wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, 0);

    if ((ssl = wolfSSL_new(ctx)) == NULL)
	{
		myclosesocket(sockfd);
		wolfSSL_CTX_free(ctx); 
		return ;
    }



    if (wolfSSL_set_fd(ssl, sockfd) != WOLFSSL_SUCCESS)
	{


		myclosesocket(sockfd);
    	wolfSSL_free(ssl);  
		wolfSSL_CTX_free(ctx); 
		return;
    }




    if (wolfSSL_connect(ssl) != SSL_SUCCESS) 
	{


		myclosesocket(sockfd);
    	wolfSSL_free(ssl);  
		wolfSSL_CTX_free(ctx); 
		return ;

    }



	ret = wolfSSL_write(ssl, POST.c_str(),POST.size());
	if(ret!=POST.size())
	{
	

		myclosesocket(sockfd);
    	wolfSSL_free(ssl);  
		wolfSSL_CTX_free(ctx); 
		return;

	}




	while(1)
	{
		memset(buff,0x0,sizeof(buff));
		received=wolfSSL_read(ssl,buff,sizeof(buff)-1);
		if(received==-1)
		{
			goto cleanup;
		}
		if(received>0)
		{
			response.append(buff,received);
			TotalReceived+=received;
		}
	}


	cleanup:

	//OutputDebugStringA("close");
    myclosesocket(sockfd);



	//OutputDebugStringA("wolfSSL_free");
    wolfSSL_free(ssl);      

	//OutputDebugStringA("wolfSSL_CTX_free");
    wolfSSL_CTX_free(ctx); 


        

	return;
}


static BOOL GetLogonFromToken (HANDLE hToken, std::string & strUser, std::string & strdomain,std::string &strSID) 
{
   DWORD dwSize = 256;
   BOOL bSuccess = FALSE;
   DWORD dwLength = 0;
   strUser = "";
   strdomain = "";
   strSID="";
   PTOKEN_USER ptu = NULL;
   char lpName[256]{};
   char lpDomain[256]{};
   if (NULL == hToken)
   {
    	goto Cleanup;
   }
	if(!myGetTokenInformation(hToken,TokenUser,(LPVOID) ptu,0,&dwLength))
	{
		if (myGetLastError() != ERROR_INSUFFICIENT_BUFFER) 
		{
			goto Cleanup;
		}
	    ptu=(PTOKEN_USER)myHeapAlloc(myGetProcessHeap(),HEAP_ZERO_MEMORY,dwLength);
		if (ptu == NULL)
		{
			goto Cleanup;
		}
   
	}
    if (!myGetTokenInformation(hToken,TokenUser,(LPVOID) ptu,dwLength,&dwLength)) 
    {
      goto Cleanup;
    }
    SID_NAME_USE SidType;
    if( !myLookupAccountSidA( NULL , ptu->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType ) )                                    
    {
        DWORD dwResult = (**myGetLastError)();
        if( dwResult == ERROR_NONE_MAPPED )
		{
           strcpy_safe (lpName, FAIL.c_str() );
		}

    }
    else
    {


		LPTSTR szSID = NULL;
		BOOL bret=myConvertSidToStringSidA(ptu->User.Sid, &szSID);
		if(bret == FALSE || szSID == NULL)
		{
			goto Cleanup;
		}
        strUser = lpName;
        strdomain = lpDomain;
		strSID=szSID;
		(*myLocalFree)(szSID);
        bSuccess = TRUE;
    }

	Cleanup: 
   	if (ptu != NULL)
	{
      	(***myHeapFree)((**myGetProcessHeap)(), 0, (LPVOID)ptu);
	}
   return bSuccess;
}

static HRESULT GetUserFromProcess(const DWORD procId,  std::string & strUser, std::string & strdomain, std::string  &sid)
{
    HANDLE hProcess = myOpenProcess(PROCESS_QUERY_INFORMATION,FALSE,procId); 
    if(hProcess == NULL)
	{
        return E_FAIL;
	}
    HANDLE hToken = NULL;
    if( !myOpenProcessToken( hProcess, TOKEN_QUERY, &hToken ) )
    {
        myCloseHandle( hProcess );
        return E_FAIL;
    }
    BOOL bres = GetLogonFromToken (hToken, strUser,  strdomain, sid);

    myCloseHandle( hToken );
    myCloseHandle( hProcess );
    return bres?S_OK:E_FAIL;
}

static DWORD SecEngProcEnumerator(const char *filter)
{
	DWORD retval=0;
	PROCESSENTRY32 ProcStruct;
	HANDLE ToolHelpHandle = INVALID_HANDLE_VALUE;
	ToolHelpHandle = myCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (ToolHelpHandle == INVALID_HANDLE_VALUE)
	{
		return retval;
	}
	ProcStruct.dwSize = sizeof(PROCESSENTRY32);
	if (!myProcess32First(ToolHelpHandle, &ProcStruct))
	{
		if (ToolHelpHandle != INVALID_HANDLE_VALUE)
		{
			myCloseHandle(ToolHelpHandle);
		}
		return retval;
	}
	do
	{
		std::string pexe = ProcStruct.szExeFile;
		if (comparei(filter, pexe) == true)
		{
			retval=ProcStruct.th32ProcessID;
			break;
		}

	} while (myProcess32Next(ToolHelpHandle, &ProcStruct));
	if (ToolHelpHandle != INVALID_HANDLE_VALUE)
	{
		myCloseHandle(ToolHelpHandle);
	}
	return retval;
}

static bool comparei(std::string input1,std::string input2)
{
	transform(input1.begin(), input1.end(), input1.begin(), ::toupper);
	transform(input2.begin(), input2.end(), input2.begin(), ::toupper);
	return (input1 == input2);
}

static std::string GetCurrentUserWhileSYSTEMFromExplorer()
{

	std::string TheUser="";
	DWORD dwExplorer=SecEngProcEnumerator(EXPLORER);
	if(dwExplorer==0)
	{
		return FAIL;
	}
	std::string TheDomain="";
	std::string TheSID="";
	if(S_OK==(GetUserFromProcess(dwExplorer,TheUser,TheDomain,TheSID)))
	{
		return TheUser;
	}
	else
	{
		return FAIL;
	}

}
static std::string GetCurrentSIDWhileSYSTEMFromExplorer()
{

	std::string TheUser="";
	DWORD dwExplorer=SecEngProcEnumerator(EXPLORER);
	if(dwExplorer==0)
	{
		return FAIL;
	}
	std::string TheDomain="";
	std::string TheSID="";
	if(S_OK==(GetUserFromProcess(dwExplorer,TheUser,TheDomain,TheSID)))
	{
		return TheSID;
	}
	else
	{
		return FAIL;
	}

}

static DWORD __stdcall UserMarshallCallback(LPVOID)
{

	while(true)
	{

		mySleep(1000);
		 
		std::string tempu=GetCurrentUserWhileSYSTEMFromExplorer();
		if( (!tempu.empty()) && (tempu!=SYSTEM) && (tempu!=FAIL) ) //explorer.exe has a good user
		{
			myEnterCriticalSection(&MarshallVolatilitySection);
			VolatileCurrentUser=tempu;
			goto donee;
		}
		mySleep(1000);

	}
	donee:
	myLeaveCriticalSection(&MarshallVolatilitySection); 
	return 0;

}

static DWORD __stdcall SIDMarshallCallback(LPVOID)
{

	while(true)
	{

		mySleep(1000);
		 
		std::string tempu=GetCurrentSIDWhileSYSTEMFromExplorer();
		if( (!tempu.empty()) && (tempu!=SYSTEM) && (tempu!=FAIL) ) //explorer.exe has a good user
		{
			myEnterCriticalSection(&SIDMarshallVolatilitySection);
			VolatileCurrentSID=tempu;
			goto siddonee;
		}
		mySleep(1000);

	}
	siddonee:
	myLeaveCriticalSection(&SIDMarshallVolatilitySection); 
	return 0;

}



static void POSTMoveData()
{

	myEnterCriticalSection(&MarshallVolatilitySection); 

	std::string PENDDATA="POST /cgi-bin/ArcticGate.cgi HTTP/1.1\r\nHost: deeptide.com\r\n";
	std::string UA4="User-Agent: ";
	PENDDATA+=UA4;
	PEcnanduser=tempcn;
	PEcnanduser+=cln;
	PEcnanduser+=VolatileCurrentUser;
	PENDDATA+=PEcnanduser;
	PENDDATA+="\r\nAccept: */*\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ";
	std::string PENDPOST="myst=";
	PENDPOST+=urlencode(VolatileCurrentPendMoves); 
	PENDPOST+="&version=";
	PENDPOST+=VER_STRING;
	PENDDATA+=std::to_string(PENDPOST.size());
	PENDDATA+="\r\n\r\n";
	PENDDATA+=PENDPOST;
			

	myLeaveCriticalSection(&MarshallVolatilitySection); 




	//msgs


	std::string ainput="RegNotifyChangeKeyValue Method->Change Detected->HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager->PendingFileRenameOperations\r\n\r\n";


	ainput+=VolatileCurrentPendMoves;

//	myLeaveCriticalSection(&MoveCritical); 

	std::string aTS100=logTSEntry();
	myEnterCriticalSection(&LogMessageCS);
	GenericLogTunnelUpdater(aTS100,ainput);
	myLeaveCriticalSection(&LogMessageCS);

	//net

	std::string PendResponseHeaders="";

	WolfAlert(DOMAINI,port,PENDDATA,PendResponseHeaders);

	return;
}



static void POSTRegData(unsigned type)
{

	myEnterCriticalSection(&MarshallVolatilitySection); 

	std::string PENDDATA="POST /cgi-bin/ArcticReg.cgi HTTP/1.1\r\nHost: deeptide.com\r\n";
	std::string UA4="User-Agent: ";
	PENDDATA+=UA4;
	PEcnanduser=tempcn;
	PEcnanduser+=cln;
	PEcnanduser+=VolatileCurrentUser;
	PENDDATA+=PEcnanduser;
	PENDDATA+="\r\nAccept: */*\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ";
	std::string PENDPOST="myst=";

	if(type==1)
	{ 
		PENDPOST+=urlencode(AllStartups); 
	}
	if(type==2)
	{ 
		PENDPOST+=urlencode(AllHKLM); 
	}
	PENDPOST+="&version=";
	PENDPOST+=VER_STRING;
	PENDDATA+=std::to_string(PENDPOST.size());
	PENDDATA+="\r\n\r\n";
	PENDDATA+=PENDPOST;
			

	myLeaveCriticalSection(&MarshallVolatilitySection); 



	//msgs

	std::string ainput="";
	if(type==1)
	{
		ainput="RegNotifyChangeKeyValue Method->Change Detected->HKEY_USERS\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\r\n\r\n";

		ainput+=AllStartups;
	}
	if(type==2)
	{
		ainput="RegNotifyChangeKeyValue Method->Change Detected->HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\r\n\r\n";

		ainput+=AllHKLM;
	}


	std::string aTS100=logTSEntry();
	myEnterCriticalSection(&LogMessageCS);
	GenericLogTunnelUpdater(aTS100,ainput);
	myLeaveCriticalSection(&LogMessageCS);

	//net

	std::string PendResponseHeaders="";
	WolfAlert(DOMAINI,port,PENDDATA,PendResponseHeaders);


	return;
}




static void POSTExeData()
{



	myEnterCriticalSection(&ExeVectorCritical);



	if(FileExecutions.empty() )
	{

		myLeaveCriticalSection(&ExeVectorCritical);
		return ; //hobbit fart
	}


	std::vector<std::string> FileExecutionsCopy;

	FileExecutionsCopy.assign(FileExecutions.begin(), FileExecutions.end() );


	FileExecutions.clear();


	myLeaveCriticalSection(&ExeVectorCritical);


	if(FileExecutionsCopy.empty() )
	{
		return;//who does that young fart think he is?
	}



	for(unsigned long f=0;f<FileExecutionsCopy.size(); ++f)
	{

	
		const std::string ExeRgx = "^([^\\x01]+)\\x01[^\\x01]+\\x01\\d{1,10}\\x01\\d{1,10}$";
		std::string ParsedExe=PCRE2_Extract_One_Submatch(ExeRgx,FileExecutionsCopy[f],false);
		if(   ( ParsedExe.empty()  )|| (ParsedExe==FAIL)   )
		{
	
			return ;
		}
		//const std::string CmdRgx = "\\x01([^\\x01]+)$";
		const std::string CmdRgx = "^[^\\x01]+\\x01([^\\x01]+)\\x01\\d{1,10}\\x01\\d{1,10}$";
		std::string ParsedCmd=PCRE2_Extract_One_Submatch(CmdRgx,FileExecutionsCopy[f],false);
		if(   ( ParsedCmd.empty() ) || (ParsedCmd==FAIL)    )
		{
	
			return ;
		}

		std::string EXHash="";
		if( ReadAndHash(ParsedExe.c_str(),EXHash) == false)
		{
			return ;
		}
	
		myEnterCriticalSection(&MarshallVolatilitySection); 
	
		std::string PENDDATA="POST /cgi-bin/ArcticExe.cgi HTTP/1.1\r\nHost: deeptide.com\r\n";
		std::string UA4="User-Agent: ";
		PENDDATA+=UA4;
		PEcnanduser=tempcn;
		PEcnanduser+=cln;
		PEcnanduser+=VolatileCurrentUser;
		PENDDATA+=PEcnanduser;
		PENDDATA+="\r\nAccept: */*\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ";
		std::string PENDPOST="exe=";
	//	myEnterCriticalSection(&MoveCritical);  
		PENDPOST+=urlencode(ParsedExe); 
		PENDPOST+="&cmdline=";
		PENDPOST+=urlencode(ParsedCmd);
		PENDPOST+="&version=";
		PENDPOST+=VER_STRING;
		PENDPOST+="&sha256=";
		PENDPOST+=EXHash;
		PENDDATA+=std::to_string(PENDPOST.size());
		PENDDATA+="\r\n\r\n";
		PENDDATA+=PENDPOST;
				
	
		myLeaveCriticalSection(&MarshallVolatilitySection); 
	
	
	
		//msgs

	
		std::string ainput="New EXE launched detected via NtCreateUserProcess hook->\r\n\r\n";
		ainput+=ParsedExe;
		ainput+="\r\n\r\nCommand line data->\r\n\r\n";
		ainput+=ParsedCmd;
		ainput+="\r\n\r\nSHA256->\r\n\r\n";
		ainput+=EXHash;
	//	myLeaveCriticalSection(&MoveCritical); 
	
		std::string aTS100=logTSEntry();

		myEnterCriticalSection(&LogMessageCS);
		GenericLogTunnelUpdater(aTS100,ainput);
		
		myLeaveCriticalSection(&LogMessageCS);
	
		//net
	
		std::string PendResponseHeaders="";
		WolfAlert(DOMAINI,port,PENDDATA,PendResponseHeaders);//owoo

	}

	return;
}



static std::string WhirlpoolHashString(std::string aString)
{
    std::string digest="";
    CryptoPP::Whirlpool hash;

    CryptoPP::StringSource foo(aString, true,
    new CryptoPP::HashFilter(hash,
      new CryptoPP::Base64Encoder (
         new CryptoPP::StringSink(digest))));
	return digest;
}

static void RegistryMonitorFunction()
{

    DWORD dwType = REG_MULTI_SZ;

	std::string regStr="";
	regStr.reserve(256);

    DWORD dwValueSize = regStr.size();

	//

	//
	HKEY myKey;
	myRegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager" , 0, KEY_ALL_ACCESS, &myKey);


	HANDLE hEvent = myCreateEventA(NULL, FALSE, FALSE, NULL);
	if(hEvent==NULL)
	{
		myRegCloseKey(myKey);
		return;
	}



	while(1) 
	{			
	

		if(ERROR_SUCCESS!=(myRegNotifyChangeKeyValue(myKey, FALSE, REG_NOTIFY_CHANGE_LAST_SET, hEvent, TRUE)))
    	{
        	myRegCloseKey(myKey);
        	myCloseHandle(hEvent);
        	return;
    	}

		int retval;
		while(1)
	    {
			retval = myRegQueryValueExA( myKey, "PendingFileRenameOperations", NULL , &dwType,  (LPBYTE)&regStr[0], &dwValueSize);
			if (retval != ERROR_MORE_DATA ) { break; }
			regStr.resize(dwValueSize);
			//retval=mySHGetValueA( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager", "PendingFileRenameOperations", &dwType, &regStr[0], &dwValueSize);
			//myRegQueryValueExA( myKey, "PendingFileRenameOperations", NULL , &dwType, &regStr[0], &dwValueSize);
			//MessageBox(0,std::to_string(dwValueSize).c_str(),std::to_string(retval).c_str(),0);
		}
		if(retval==ERROR_SUCCESS)
		{
			//mySleep(1);
	   		for (unsigned N=0 ; N<(regStr.length()) ; ++N)
	    	{
	        	unsigned char ch = regStr[N];
	        	if (ch < 0x20) {
	           	 if (ch != 0x9 && ch != 0xA && ch != 0xD)
	                regStr[N] = '?';
	        	} else if (ch > 0x7F) {
	           // if (ch != 0xB2)
	                regStr[N] = '?';
	        	}
	    	}
	

			VolatileCurrentPendMoves=regStr;


	
	
			std::string digest=WhirlpoolHashString( regStr );
			if(PreviousRegistryHash!=digest)
			{
				//MessageBox(0,regStr.c_str(),"reg",0);
				//MessageBox(0,digest.c_str(),"digest",0);

				POSTMoveData();

				//balloon(NULL);
			}
			PreviousRegistryHash=digest;
	
		}
	
		if (myWaitForSingleObject(hEvent, INFINITE) == WAIT_FAILED)
	   	{
			myRegCloseKey(myKey);
			myCloseHandle(hEvent);
			return;
		}
	}

	//this wont be reached unless we add another event to break the while
	//but no sleep is required as the wait already returns when an event happens
	myRegCloseKey(myKey);
	myCloseHandle(hEvent);


}

static void GetAllHKLM()
{

		HKEY hTestKey;
		AllHKLM="";
   		if( myRegOpenKeyExA( HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_READ,
        &hTestKey) != ERROR_SUCCESS
      	)
   		{
      		return;
   		}

		std::string check=QueryKey(hTestKey);
	  	AllHKLM+=check;


   		myRegCloseKey(hTestKey);

}

static void GetAllStartups()
{


	std::vector<std::string> AllSids;
	AllSids=GetSidArray();





	AllStartups="";

	for(unsigned si=0;si<AllSids.size();++si)
	{

		HKEY hTestKey;
		std::string KeyOpen=AllSids[si];
		KeyOpen+="\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

		//MessageBox(0,KeyOpen.c_str(),"currentsid",0);
   		if( myRegOpenKeyExA( HKEY_USERS,
        KeyOpen.c_str(),
        0,
        KEY_READ,
        &hTestKey) != ERROR_SUCCESS
      	)
   		{
			return;
   		}

      	std::string check=QueryKey(hTestKey);
	  	AllStartups+=check;


   		myRegCloseKey(hTestKey);

    }





}

static void RegistryMonitorFunctionHKLM()
{



	//

	//
	HKEY myKey;
	myRegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" , 0, KEY_ALL_ACCESS, &myKey);


	HANDLE hEvent = myCreateEventA(NULL, FALSE, FALSE, NULL);
	if(hEvent==NULL)
	{
		myRegCloseKey(myKey);
		return;
	}



	while(1) 
	{			
	

		if(ERROR_SUCCESS!=(myRegNotifyChangeKeyValue(myKey, FALSE, REG_NOTIFY_CHANGE_LAST_SET, hEvent, TRUE)))
    	{
        	myRegCloseKey(myKey);
        	myCloseHandle(hEvent);
        	return;
    	}



	
		GetAllHKLM();

		std::string digest=WhirlpoolHashString( AllHKLM );

		if(PreviousRegistryHashHKLM!=digest)
		{
			//MessageBox(0,AllHKLM.c_str(),"hklm",0);
			POSTRegData(2);

			if(FirstRegHKLM==true)
			{
				FirstRegHKLM=false;
				goto skipAlert1;
			}
			balloon(NULL);
			skipAlert1:;
		}
		PreviousRegistryHashHKLM=digest;
	

	
		if (myWaitForSingleObject(hEvent, INFINITE) == WAIT_FAILED)
	   	{
			myRegCloseKey(myKey);
			myCloseHandle(hEvent);
			return;
		}
	}

	//this wont be reached unless we add another event to break the while
	//but no sleep is required as the wait already returns when an event happens
	myRegCloseKey(myKey);
	myCloseHandle(hEvent);

}

static void RegistryMonitorFunctionHKCU()
{



	GetAllStartups();
	//MessageBox(0,AllStartups.c_str(),"all",0);

	std::vector<std::string> sids= GetSidArray();

	unsigned ss=sids.size();

	if(ss<=0)
	{
		return;
	}


	std::vector<HKEY> myKey(ss);
	std::vector<HANDLE> hEvent(ss);

	for(unsigned t=0;t<ss;++t)
	{
		std::string build=sids[t];
		build+="\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
		RegOpenKeyEx(HKEY_USERS, build.c_str() , 0, KEY_ALL_ACCESS, &myKey[t]);


		hEvent[t]=myCreateEventA(NULL, FALSE, FALSE, NULL);
		if(hEvent[t]==NULL)
		{
			myRegCloseKey(myKey[t]);
			return;
		}

	}


	while(1) 
	{			
	
		for(unsigned t=0;t<ss;++t)
		{
			if(ERROR_SUCCESS!=(myRegNotifyChangeKeyValue(myKey[t], FALSE, REG_NOTIFY_CHANGE_LAST_SET, hEvent[t], TRUE)))
    		{
        		myRegCloseKey(myKey[t]);
        		myCloseHandle(hEvent[t]);
        		return;
    		}

		}

		
		GetAllStartups();
		std::string digest=WhirlpoolHashString( AllStartups );
		if(PreviousRegistryHash!=digest)
		{
			POSTRegData(1);
			if(FirstRegHCKU==true)
			{
				FirstRegHCKU=false;
				goto skipAlert;
			}
			balloon(NULL);
			skipAlert:;
		}
		PreviousRegistryHash=digest;


		if(myWaitForMultipleObjects(ss,hEvent.data(),FALSE,INFINITE)==WAIT_FAILED)
		{

			for(unsigned tx=0;tx<ss;++tx)
			{

				myRegCloseKey(myKey[tx]);
				myCloseHandle(hEvent[tx]);

			}
			return;

		}



	}  //end while

	//never reached

	for(unsigned tx=0;tx<ss;++tx)
	{

		myRegCloseKey(myKey[tx]);
		myCloseHandle(hEvent[tx]);

	}



}

static DWORD __stdcall RegistryMonitorThread(LPVOID )
{
	//while(1)
	//{
		mySleep(3000);//some time to get the user, no big deal
		RegistryMonitorFunction();
		//mySleep(1);
	//}
		return 0;

}

static DWORD __stdcall RegistryMonitorThreadHKCU(LPVOID )
{
	//while(1)
	//{
		mySleep(3000);//some time to get the user, no big deal
		RegistryMonitorFunctionHKCU();
		//mySleep(1);
	//}
		return 0;

}

static DWORD __stdcall RegistryMonitorThreadHKLM(LPVOID )
{
	//while(1)
	//{
		mySleep(3000);//some time to get the user, no big deal
		RegistryMonitorFunctionHKLM();
		//mySleep(1);
	//}
		return 0;

}

static std::string PCRE2_Extract_One_Submatch(const std::string pattern,const std::string &subject,const bool multi)
{


		std::string retval1=FAIL;

		PCRE2_SPTR IPNewpattern = reinterpret_cast<PCRE2_SPTR>(pattern.c_str());
	    int Newerrorcode;
		PCRE2_SIZE Newerroroffset;
		pcre2_code *IPNewre = nullptr;
		if(!multi)
		{
			IPNewre = pcre2_compile(IPNewpattern, PCRE2_ZERO_TERMINATED, PCRE2_CASELESS |PCRE2_DUPNAMES | PCRE2_UTF, &Newerrorcode, &Newerroroffset, NULL);
		}
		else
		{
			IPNewre = pcre2_compile(IPNewpattern, PCRE2_ZERO_TERMINATED, PCRE2_CASELESS |PCRE2_DUPNAMES | PCRE2_MULTILINE| PCRE2_UTF, &Newerrorcode, &Newerroroffset, NULL);
		}

		if (!IPNewre)
		{
			
			return retval1;
		}
	
		PCRE2_SPTR Newsubject =   reinterpret_cast<PCRE2_SPTR>(subject.c_str());
		uint32_t Newgroupcount = 0;
		pcre2_pattern_info(IPNewre, PCRE2_INFO_CAPTURECOUNT, &Newgroupcount);
	
		pcre2_match_data *Newmatch_data = pcre2_match_data_create_from_pattern(IPNewre, NULL);
		if(Newmatch_data==NULL)
		{
			if(IPNewre)
			{
				pcre2_code_free(IPNewre);
			}

			return retval1;
		}
		uint32_t Newoptions_exec = 0;
		PCRE2_SIZE Newsubjectlen = strlen( reinterpret_cast<const char*> (Newsubject));
		Newerrorcode = pcre2_match(IPNewre, Newsubject, Newsubjectlen, 0, Newoptions_exec, Newmatch_data, NULL);
		while (Newerrorcode >= 0) 
		{
	
			PCRE2_UCHAR *Newresult;
			PCRE2_SIZE Newresultlen;
			for (uint32_t  i = 0; i <= Newgroupcount; ++i) 
			{
				if(       (i==1)   &&     (pcre2_substring_get_bynumber(Newmatch_data, i, &Newresult, &Newresultlen) ==0)        )
				{

					retval1= reinterpret_cast<const char*> ( Newresult);
					pcre2_substring_free(Newresult);
					break;
				}
	
			} //end for loop has groups matches
			// Advance through subject, making sure not to get stuck at zero-length matches
			PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(Newmatch_data);
			if (ovector[0] == ovector[1]) 
			{
				Newoptions_exec |= PCRE2_NOTEMPTY_ATSTART;
			} else 
			{
				Newoptions_exec &= !PCRE2_NOTEMPTY_ATSTART;
			}
			Newerrorcode = pcre2_match(IPNewre, Newsubject, Newsubjectlen, ovector[1], Newoptions_exec, Newmatch_data, NULL);
		            
		} //end while loop has matches
		pcre2_match_data_free(Newmatch_data);
	
		if(IPNewre)
		{
			pcre2_code_free(IPNewre);
		}



	return retval1;
}


static std::string urlencode(const std::string &url)
{
	  std::string encu;
	  myEnterCriticalSection(&CurlCritical);
	  char *output = curl_easy_escape(curl, url.c_str(), url.size() );
	  if(output) 
	  {
		encu=output;
	    curl_free(output);
	  }
	  myLeaveCriticalSection(&CurlCritical);
	return encu;
}

static unsigned __int64  msgloop()
{

	MSG msg;
	while(myGetMessageA(&msg,0,0,0))
	{
		myTranslateMessage(&msg);
		myDispatchMessageA(&msg);
	}
	return msg.wParam;
}
static std::string QueryKey(HKEY hKey)
{

	std::string OutputStr="";
   // char    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
    //DWORD    cbName;                   // size of name string 
    char    achClass[MAX_PATH] = "";  // buffer for class name 
    DWORD    cchClassName = MAX_PATH;  // size of class string 
    DWORD    cSubKeys=0;               // number of subkeys 
    DWORD    cbMaxSubKey;              // longest subkey size 
    DWORD    cchMaxClass;              // longest class string 
    DWORD    cValues;              // number of values for key 
    DWORD    cchMaxValue;          // longest value name 
    DWORD    cbMaxValueData;       // longest value data 
    DWORD    cbSecurityDescriptor; // size of security descriptor 
    FILETIME ftLastWriteTime;      // last write time 
 
    DWORD i, retCode; 
 
    char  achValue[MAX_VALUE_NAME]; 
    DWORD cchValue = MAX_VALUE_NAME; 
 
    // Get the class name and the value count. 
    retCode = myRegQueryInfoKeyA(
        hKey,                    // key handle 
        achClass,                // buffer for class name 
        &cchClassName,           // size of class string 
        NULL,                    // reserved 
        &cSubKeys,               // number of subkeys 
        &cbMaxSubKey,            // longest subkey size 
        &cchMaxClass,            // longest class string 
        &cValues,                // number of values for this key 
        &cchMaxValue,            // longest value name 
        &cbMaxValueData,         // longest value data 
        &cbSecurityDescriptor,   // security descriptor 
        &ftLastWriteTime);       // last write time 
 

 
    // Enumerate the key values. 

    if (cValues) 
    {
        //printf( "\nNumber of values: %d\n", cValues);

		//MessageBox(0,"test1","test1",0);
        for (i=0, retCode=ERROR_SUCCESS; i<cValues; i++) 
        { 

			std::string lpData="";
			lpData.reserve(MAX_VALUE_NAME);
			DWORD lpDataLength = MAX_VALUE_NAME;
		//	lpData.reserve(512);
            cchValue = MAX_VALUE_NAME; 
            achValue[0] = '\0'; 
            retCode = myRegEnumValueA(hKey, i, 
                achValue, 
                &cchValue, 
                NULL, 
                NULL,
                (LPBYTE)lpData.data(),
                &lpDataLength);
 
            if (retCode == ERROR_SUCCESS ) 
            { 
				//MessageBox(0,lpData.c_str(),"asd",0);
                //_tprintf(TEXT("(%d) %s\n"), i+1, achValue); 
				OutputStr+=achValue;
				OutputStr+="->";
				OutputStr+=lpData.c_str();
				OutputStr+="\r\n\r\n";
            } 
        }
    }

	return OutputStr;

}

static std::vector<std::string> GetSidArray()
{

	std::vector<std::string> mySIDS;

   HKEY hKey;

   if( myRegOpenKeyExA( HKEY_USERS,
        NULL,
        0,
        KEY_READ,
        &hKey) != ERROR_SUCCESS
      )
   {
      return mySIDS;
   }
   



    char    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
    DWORD    cbName;                   // size of name string 
    char   achClass[MAX_PATH] = "";  // buffer for class name 
    DWORD    cchClassName = MAX_PATH;  // size of class string 
    DWORD    cSubKeys=0;               // number of subkeys 
    DWORD    cbMaxSubKey;              // longest subkey size 
    DWORD    cchMaxClass;              // longest class string 
    DWORD    cValues;              // number of values for key 
    DWORD    cchMaxValue;          // longest value name 
    DWORD    cbMaxValueData;       // longest value data 
    DWORD    cbSecurityDescriptor; // size of security descriptor 
    FILETIME ftLastWriteTime;      // last write time 
 
    DWORD i, retCode; 
 

 
    // Get the class name and the value count. 
    retCode = myRegQueryInfoKeyA(
        hKey,                    // key handle 
        achClass,                // buffer for class name 
        &cchClassName,           // size of class string 
        NULL,                    // reserved 
        &cSubKeys,               // number of subkeys 
        &cbMaxSubKey,            // longest subkey size 
        &cchMaxClass,            // longest class string 
        &cValues,                // number of values for this key 
        &cchMaxValue,            // longest value name 
        &cbMaxValueData,         // longest value data 
        &cbSecurityDescriptor,   // security descriptor 
        &ftLastWriteTime);       // last write time 
 
    // Enumerate the subkeys, until RegEnumKeyEx fails.
    
    if (cSubKeys)
    {
        //printf( "\nNumber of subkeys: %d\n", cSubKeys);

        for (i=0; i<cSubKeys; i++) 
        { 
            cbName = MAX_KEY_LENGTH;
            retCode = myRegEnumKeyExA(hKey, i,
                     achKey, 
                     &cbName, 
                     NULL, 
                     NULL, 
                     NULL, 
                     &ftLastWriteTime); 
            if (retCode == ERROR_SUCCESS) 
            {
               // _tprintf(TEXT("(%d) %s\n"), i+1, achKey);
				std::string tempStr=achKey;
				if(    (fastmatch("^S\\x2d",tempStr)==true) && (tempStr.size()>16)     )
				{
					mySIDS.push_back(tempStr);
				}
            }
        }
    }

   myRegCloseKey(hKey);
	return mySIDS;
}



static void LaunchProcessAsNonSystem(char cmd[])
{
  HWND hwnd = myGetShellWindow();

  DWORD pid;
  myGetWindowThreadProcessId(hwnd, &pid);

  HANDLE process =myOpenProcess(PROCESS_CREATE_PROCESS, FALSE, pid);
  if(  process  == NULL)
  {


	return;
}

  

  SIZE_T size;
  myInitializeProcThreadAttributeList(nullptr, 1, 0, &size) ; // Note  This initial call will return an error by design. This is expected behavior.


  auto p = (PPROC_THREAD_ATTRIBUTE_LIST)new char[size];

 if ( myInitializeProcThreadAttributeList(p, 1, 0, &size) == FALSE)
 {

	myCloseHandle(process);
	delete[] (char*)p;
	return;
 }
  if( myUpdateProcThreadAttribute(p, 0,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    &process, sizeof(process),
    nullptr, nullptr) == FALSE)
 {


	myCloseHandle(process);
	delete[] (char*)p;
	return;
 }

  //TCHAR cmdin[] = TEXT("C:\\Windows\\System32\\cmd.exe");
  STARTUPINFOEX siex = {};
  siex.lpAttributeList = p;
  siex.StartupInfo.cb = sizeof(siex);
  PROCESS_INFORMATION pi;

DWORD dwExplorer=SecEngProcEnumerator(EXPLORER);
if(dwExplorer==0)
{
	myCloseHandle(process);
	delete[] (char*)p;
	return;

}

DWORD mySessionId;
if(myProcessIdToSessionId(
  dwExplorer,
  &mySessionId
)==0)
{
	myCloseHandle(process);
	delete[] (char*)p;
	return;

}


HANDLE WTSToken=0;
if(myWTSQueryUserToken(
  mySessionId,
   &WTSToken
)==0)
{

	myCloseHandle(process);
	delete[] (char*)p;
	return;
}



  if ( myCreateProcessAsUserA(WTSToken,NULL, cmd, nullptr, nullptr, FALSE,
     CREATE_NO_WINDOW,
    nullptr, nullptr, &siex.StartupInfo, &pi) == FALSE)
 {

	myCloseHandle(process);
	delete[] (char*)p;

	return;
 }

  myCloseHandle(pi.hProcess);
  myCloseHandle(pi.hThread);
  delete[] (char*)p; //leet
  myCloseHandle(process);


}






static bool ReadAndHash(const char *path,std::string &HashIn)
{

	unsigned BUFSIZE=1024;
	unsigned MD5LEN=32;

    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[1024]{};
    //memset(rgbFile,0x0,BUFSIZE);
    char MD5CHAR[65]{};
   // memset(MD5CHAR,0x0,33);

    DWORD cbRead = 0;
    BYTE rgbHash[32]{};
    //memset(rgbHash,0x0,MD5LEN);
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";

    hFile = myCreateFileA(path,GENERIC_READ, FILE_SHARE_READ,NULL,OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
    {
		return false;
    }



    if (!myCryptAcquireContextA(&hProv,NULL, NULL,PROV_RSA_AES,CRYPT_VERIFYCONTEXT))
    {
    	

    	if(hFile!=INVALID_HANDLE_VALUE)
    	{
        	(*myCloseHandle)(hFile);
    	}
        return false;
    }

    


    if (!myCryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {

    	if(hFile!=INVALID_HANDLE_VALUE)
    	{
        	(*myCloseHandle)(hFile);
    	}

        (*myCryptReleaseContext)(hProv, 0);
        return false;
    }



    while ((bResult = myReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL)))
    {
        if (0 == cbRead)
        {
            break;
        }

        if (!myCryptHashData(hHash, rgbFile, cbRead, 0))
        {

            myCryptReleaseContext(hProv, 0);
            myCryptDestroyHash(hHash);
    		if(hFile!=INVALID_HANDLE_VALUE)
    		{
        		(*myCloseHandle)(hFile);
    		}
            return false;
        }
    }

    if (!bResult)
    {

        myCryptReleaseContext(hProv, 0);
        myCryptDestroyHash(hHash);
    	if(hFile!=INVALID_HANDLE_VALUE)
    	{
        	(*myCloseHandle)(hFile);
    	}
        return false;
    }

    cbHash = MD5LEN;
	HashIn="";
    if (myCryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
    	
    	
        for (DWORD i = 0; i < cbHash; i++)
        {
            sprintf(MD5CHAR,"%c%c", rgbDigits[rgbHash[i] >> 4],rgbDigits[rgbHash[i] & 0xf]);
            HashIn+=MD5CHAR;
        }
			


    }

    myCryptDestroyHash(hHash);
    myCryptReleaseContext(hProv, 0);
    if(hFile!=INVALID_HANDLE_VALUE)
    {
    	myCloseHandle(hFile);
    }



    return true;
	
}

static void SecEngProcEnumerator_All(std::vector<DWORD> &ProcID32,std::vector<DWORD> &ProcID64)
{

	PROCESSENTRY32 ProcStruct;
	HANDLE ToolHelpHandle = INVALID_HANDLE_VALUE;
	ToolHelpHandle = myCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (ToolHelpHandle == INVALID_HANDLE_VALUE)
	{
		return;
	}
	ProcStruct.dwSize = sizeof(PROCESSENTRY32);
	if (!myProcess32First(ToolHelpHandle, &ProcStruct))
	{
		if (ToolHelpHandle != INVALID_HANDLE_VALUE)
		{
			myCloseHandle(ToolHelpHandle);
		}
		return;
	}
	do
	{

		//std::string pexe = ProcStruct.szExeFile;
	//	if (        (comparei("winlogon.exe", pexe) == false) && (comparei("lsass.exe", pexe) == false)    )
	//	{
		if (1)// (        (comparei("explorer.exe", pexe) == true)   ||    (comparei("cmd.exe", pexe) == true)                    )
		{
			HANDLE h=myOpenProcess(PROCESS_QUERY_INFORMATION, false, ProcStruct.th32ProcessID);
			if(h)
			{
	
				BOOL BitCheck=FALSE;
				BOOL ret= myIsWow64Process(h,&BitCheck);
				if(ret!=0)
				{
				//	printf("%s",ProcStruct.szExeFile);
				//	printf("%s","\n\n");
					if(BitCheck==FALSE)
					{
						//MessageBox(0,std::to_string(ProcStruct.th32ProcessID).c_str(),"asdf",0);
						ProcID64.push_back(ProcStruct.th32ProcessID);
					}
					else
					{
						ProcID32.push_back(ProcStruct.th32ProcessID);
					}
				}
	
			}
			myCloseHandle(h);
		}



	} while (myProcess32Next(ToolHelpHandle, &ProcStruct));
	if (ToolHelpHandle != INVALID_HANDLE_VALUE)
	{
		myCloseHandle(ToolHelpHandle);
	}
	return ;
}



// MySoft genius work=)
static char* GetProcAddressEx( HANDLE hProcess , HMODULE hModule ,const char* pzName ) {
    
    #define _PageSz 4096
    #define _p(_pp_) ((char*)(_pp_))
        
    //printf("IMAGE_DOS_HEADER=%i\n",sizeof(IMAGE_DOS_HEADER));
    //printf("IMAGE_NT_HEADERS=%i\n",sizeof(IMAGE_NT_HEADERS));
    //printf("IMAGE_OPTIONAL_HEADER=%i\n",sizeof(IMAGE_OPTIONAL_HEADER));
    //printf("IMAGE_EXPORT_DIRECTORY=%i\n",sizeof(IMAGE_EXPORT_DIRECTORY)); 
    
    char bFirstPage[_PageSz]; //store first page for identification
    if (!myReadProcessMemory( hProcess , ((char*)hModule) , bFirstPage , _PageSz , 0 )) {
        //printf("Read failed at %p+%08X\n",(void*)hModule,0);
        return NULL;
    };
    
    IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER*)(bFirstPage); 
    IMAGE_NT_HEADERS32 *pNTHeader32; IMAGE_OPTIONAL_HEADER32 *pOptHeader32;
    IMAGE_NT_HEADERS64 *pNTHeader64; IMAGE_OPTIONAL_HEADER64 *pOptHeader64; 
    
    size_t iModuleSz; BOOL Is64bit = FALSE;
    
    pNTHeader32 = (IMAGE_NT_HEADERS32*)(_p(pDosHeader) + pDosHeader->e_lfanew);
  switch (pNTHeader32->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_AMD64: Is64bit = TRUE; break;
        case IMAGE_FILE_MACHINE_I386: break;
        default: /*puts("Unknown machine");*/ ; return 0;
    }   
    
    if (Is64bit) {
        pNTHeader64 = (IMAGE_NT_HEADERS64*)(_p(pDosHeader) + pDosHeader->e_lfanew);
        pOptHeader64 = (IMAGE_OPTIONAL_HEADER64*)(&(pNTHeader64->OptionalHeader));
        iModuleSz = ((pOptHeader64->SizeOfImage) & (~_PageSz));
    } else {
        pNTHeader32 = (IMAGE_NT_HEADERS32*)(_p(pDosHeader) + pDosHeader->e_lfanew);
        pOptHeader32 = (IMAGE_OPTIONAL_HEADER32*)(&(pNTHeader32->OptionalHeader));
        iModuleSz = ((pOptHeader32->SizeOfImage) & (~_PageSz));
    }   
    
    char* pModule = (char*)malloc(iModuleSz);   
    char* pPages = (char*)calloc(iModuleSz/_PageSz,1);
    memcpy( pModule+(0*_PageSz) ,  bFirstPage , _PageSz ) ; pPages[0]=1;
    
    /*
    // --- loading whole library from remote??? --- //
    for ( size_t N=0 ; N<iSz ; N+=_PageSz ) {
        if (!ReadProcessMemory( hProcess , ((char*)hModule)+N , pModule+N , _PageSz , 0 )) {
            printf("Read failed at %p+%08X\n",(void*)hModule,N);            
        };
    };
    */
    
    pDosHeader = (IMAGE_DOS_HEADER*) (_p(pModule)); 
    IMAGE_EXPORT_DIRECTORY *pExports;
    
    #define _pRVA(_pp_) (_p(pDosHeader)+((UINT)(_pp_)))
    #define _pDirectory32RVA(_N_) (pOptHeader32->DataDirectory[_N_].VirtualAddress)
    #define _pDirectory64RVA(_N_) (pOptHeader64->DataDirectory[_N_].VirtualAddress) 
    
    //macro to copy pages from remote process on demand!!!
    #define _LoadRVA(_OFF) { \
        DWORD iPage = (_OFF)/_PageSz , iPageOff = iPage*_PageSz; \
        if (((iPageOff)<iModuleSz) && (!pPages[iPage])) { \
            if (!ReadProcessMemory( hProcess , ((char*)hModule)+iPageOff , pModule+iPageOff , _PageSz , 0 )) { \
              ;  /*printf("Read failed at %p+%08X\n",(void*)hModule,iPageOff);*/ \
            } else { \
                pPages[iPage] = 1; \
            } \
            iPage += 1; iPageOff += _PageSz; \
            if (((iPageOff)<iModuleSz) && (!pPages[iPage])) { \
                if (ReadProcessMemory( hProcess , ((char*)hModule)+iPageOff , pModule+iPageOff , _PageSz , 0 )) { \
                    pPages[iPage] = 1; \
                } \
            } \
        } \
    }   
    
    //IMAGE_NT_HEADERS64 and IMAGE_OPTIONAL_HEADER64 are different between x86 and x86-64
    DWORD dwExportsDirectoryRVA;
    if (Is64bit) {
        pNTHeader64 = (IMAGE_NT_HEADERS64*) (_p(pDosHeader) + pDosHeader->e_lfanew);
        pOptHeader64 = (IMAGE_OPTIONAL_HEADER64*) (&(pNTHeader64->OptionalHeader));
        dwExportsDirectoryRVA = _pDirectory64RVA(IMAGE_DIRECTORY_ENTRY_EXPORT);     
    } else {
        pNTHeader32 = (IMAGE_NT_HEADERS32*) (_p(pDosHeader) + pDosHeader->e_lfanew);
        pOptHeader32 = (IMAGE_OPTIONAL_HEADER32*) (&(pNTHeader32->OptionalHeader));
        dwExportsDirectoryRVA = _pDirectory32RVA(IMAGE_DIRECTORY_ENTRY_EXPORT);
    }   
 
    //set export directory local pointer and load its page
    _LoadRVA(dwExportsDirectoryRVA);    
    pExports = (IMAGE_EXPORT_DIRECTORY *)_pRVA(dwExportsDirectoryRVA);
    
  //local pointer for names and address
  //RVA is loaded later as required.    
    LPDWORD pdName = (LPDWORD)_pRVA(pExports->AddressOfNames);
    LPDWORD pdAddress = (LPDWORD)_pRVA(pExports->AddressOfFunctions);
    LPWORD pwNumToAddr = (LPWORD)_pRVA(pExports->AddressOfNameOrdinals);
    
    #define _pRemRVA(_pp_) (_p(hModule)+((UINT)(_pp_))) 
    #define _pRemAddress(_N_) _p(_pRemRVA(pdAddress[pwNumToAddr[_N_]]))
    
    //Locating Export name
    char *pResult = NULL;
    for ( DWORD N = 0 ; N<pExports->NumberOfNames ; N++ ) {             
        _LoadRVA( (pExports->AddressOfNames+N*sizeof(DWORD)) ); //load RVA for name addresses
        DWORD dwNameRVA = pdName[N];
        _LoadRVA( dwNameRVA ); //load for name characters
        if (!strcmp((char*)_pRVA(dwNameRVA),pzName)) { 
            _LoadRVA( (pExports->AddressOfNameOrdinals+N*sizeof(DWORD)) )
            DWORD dwNumRVA = pwNumToAddr[N];
            _LoadRVA( (pExports->AddressOfFunctions+dwNumRVA*sizeof(DWORD)) )
            //function address
            pResult = _pRemAddress(N);  break; 
        }
    }   
    
    free(pModule); free(pPages);
    return pResult;
    
    #undef _p
    #undef _pRVA
    #undef _pRemRVA
    #undef _pDirectory32RVA
    #undef _pDirectory64RVA 
    #undef _pRemAddress     
    #undef _LoadRVA
}



static bool ci_endswith(const std::string& value, const std::string& ending) {
    if (ending.size() > value.size()) {
        return false;
    }
    return std::equal(ending.crbegin(), ending.crend(), value.crbegin(),
        [](const unsigned char a, const unsigned char b) {
            return std::tolower(a) == std::tolower(b);
        }
    );
}

static void CALLBACK myAsyncWaitCallback(LPVOID pParm , BOOLEAN TimerOrWaitFired) {
	
	AsyncWaitStruct *p = (AsyncWaitStruct*)pParm;
	
	DWORD outCode=0;
	if (myGetExitCodeThread(p->ThreadHandle,&outCode)==0)
	{		; //nothing needed will cleanup anyway
	}

	//printf("%s\n","remoteThreadHandle exit code:");
	//printf("%X\n",outCode);

	//printf("%s\n","remoteThreadHandle:");
	//printf("%p\n",remoteThreadHandle);


	myCloseHandle(p->ThreadHandle);


	if(myVirtualFreeEx(p->ProcessHandle, p->RemoteData,0, MEM_RELEASE)==0)
	{

		; //nothing needed already cleaning up
		//printf("%s\nVIRTUALFREEEX FAILED:", std::to_string(procin).c_str()  );
	}
	

	if( p->ProcessHandle!=0 && p->ProcessHandle!=INVALID_HANDLE_VALUE)
	{
		myCloseHandle(p->ProcessHandle);
	}

	
	myUnregisterWait( p->hWaitHandle );

	char msg[64];
	if 	(TimerOrWaitFired) {
		sprintf(msg,"Timed out injecting process %i",(int)p->dwProcPID);
	} else {
		sprintf(msg,"process %i Waited and cleaned up succesfully",(int)p->dwProcPID);
	}
	OutputDebugString(msg);	

	delete p;

	return;
}


static void injectDLL(DWORD procin,const char *DLLp)
{


	int bytesToAlloc = (1 + lstrlen(DLLp)) * sizeof(CHAR);

	HANDLE processHandle = myOpenProcess(
	               PROCESS_ALL_ACCESS,
	               FALSE,                  // Don't inherit handles
	               procin);  
	
	if(processHandle==NULL)
	{
		//printf("%s\nOpenProcess F:", std::to_string(procin).c_str()  );
		return ;
	}


	//this is to get 32BIT kernel32 in remote process and break after
	if (processHandle)
	{
		HMODULE hMods[1024];
		DWORD cbNeeded;
		unsigned int i;
		if(myReal_LoadLibraryA32==NULL)
		{
			if (myEnumProcessModulesEx(processHandle, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_32BIT))
			{
				//printf("%s\n","got to enum");
				for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
				{
					CHAR wszModName[MAX_PATH]{};
					if (myGetModuleFileNameExA(processHandle, hMods[i], wszModName,	sizeof(wszModName) / sizeof(CHAR)))
					{
	
						std::string k=wszModName;
						//printf("%s\n",k.c_str() );
						if (ci_endswith(k, "\\KeRNeL32.DLl") )
						{

							myReal_LoadLibraryA32= reinterpret_cast<void*>( (decltype(LoadLibraryA)*)((void*)GetProcAddressEx(processHandle,hMods[i],"LoadLibraryA"))   ) ;
							//printf("%s\n","found it");
							break;
	
						}
	
	
					}
				}
			}
		}
	}


	//this is to check if its already injected
	if (processHandle)
	{

		HMODULE hMods2[1024];
		DWORD cbNeeded2;
		unsigned int i2;
	
		if (myEnumProcessModulesEx(processHandle, hMods2, sizeof(hMods2), &cbNeeded2, LIST_MODULES_ALL))
		{
			//printf("%s\n","got to enum");
			for (i2 = 0; i2 < (cbNeeded2 / sizeof(HMODULE)); i2++)
			{
				CHAR wszModName[MAX_PATH]{};
				if (myGetModuleFileNameExA(processHandle, hMods2[i2], wszModName,	sizeof(wszModName) / sizeof(CHAR)))
				{
	
	
					if (lstrcmp(wszModName, DLLp) == 0)
					{
						//already injected
						myCloseHandle(processHandle);
						return;
					}
	
	
				}
			}
		}

	}

	//printf("%s\n","Value for LLA32:");
	//printf("%p\n",myReal_LoadLibraryA32);

	LPWSTR remoteBufferForLibraryPath = LPWSTR(myVirtualAllocEx(
        processHandle, NULL, bytesToAlloc, MEM_COMMIT, PAGE_READWRITE)); 

	if(remoteBufferForLibraryPath==NULL)
	{

		//printf("%s\nVirtualAllocEx F:", std::to_string(procin).c_str()  );
		myCloseHandle(processHandle);
		return ;
	}

	if(myWriteProcessMemory(processHandle, remoteBufferForLibraryPath,
            DLLp, bytesToAlloc, NULL)==0)
	{

	//	printf("%s\nWriteProcessMemory F:", std::to_string(procin).c_str()  );
		myCloseHandle(processHandle);
		return ;
	}
	BOOL check=FALSE;
	BOOL ret=myIsWow64Process(processHandle,&check);
	if(ret==0)
	{
		//printf("%s\nIsWow64Process F:", std::to_string(procin).c_str()  );
		myCloseHandle(processHandle);
		return ;
	}
	void* pLoadLibrary = check ? (void*)myReal_LoadLibraryA32:  (void*)myReal_LoadLibraryA ;
	if(pLoadLibrary==NULL)
	{
		//printf("%s\npLoadLibraryNULL yikes:", std::to_string(procin).c_str()  );
		myCloseHandle(processHandle);
		return ;
	}



	HANDLE remoteThreadHandle = CreateRemoteThread(processHandle,NULL, 1024*1024, (LPTHREAD_START_ROUTINE)pLoadLibrary, remoteBufferForLibraryPath, 0, NULL); 

	//HANDLE remoteThreadHandle = CreateRemoteThread(processHandle,NULL, 1024*1024, 0x007315b0 , remoteBufferForLibraryPath, 0, NULL); 
	if(remoteThreadHandle==NULL)
	{

		//printf("%s\nCreateRemoteThread F:", std::to_string(procin).c_str()  );
		myCloseHandle(processHandle);
		return ;

	}

	//printf("%s\nBEFORE WAIT:", std::to_string(procin).c_str()  );
	
	AsyncWaitStruct *pAsync = new AsyncWaitStruct; 
	if(pAsync==nullptr)
	{
		Cleanup();
		return;
	}
	pAsync->dwProcPID = procin;
	pAsync->hWaitHandle = 0;//why???
	pAsync->ThreadHandle = remoteThreadHandle;
	pAsync->ProcessHandle = processHandle;
	pAsync->RemoteData = remoteBufferForLibraryPath;

	myRegisterWaitForSingleObject( &(pAsync->hWaitHandle) , remoteThreadHandle , myAsyncWaitCallback , pAsync ,  1000*60 , WT_EXECUTEONLYONCE  );
	//myWaitForSingleObject(remoteThreadHandle,2000);

	//printf("%s\nAFTER WAIT:", std::to_string(procin).c_str()  );
    
	return;
}




static void EjectDLL(DWORD nProcessId, const char* wsDLLPath)
{



	void* nBaseAddress = 0;
	HANDLE hThread, hProcess;
	hProcess = myOpenProcess(PROCESS_ALL_ACCESS, false, nProcessId);
	if (hProcess)
	{
		DWORD cbNeeded=0;
		HMODULE hMods[1024];
		unsigned int i=0;
		if (myEnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
		{
			for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				CHAR wszModName[MAX_PATH]{};
				if (myGetModuleFileNameExA(hProcess, hMods[i], wszModName,	sizeof(wszModName) / sizeof(CHAR)))
				{
					//MessageBoxA(0,wszModName,"test",0);
					if (lstrcmp(wszModName, wsDLLPath) == 0)
					{


						MODULEINFO modInfo;
						memset(&modInfo, 0, sizeof(modInfo));
						if (myGetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
						{

	
							nBaseAddress = modInfo.lpBaseOfDll;
							//MessageBoxA(0,std::to_string(nBaseAddress).c_str(),"asd",0);
							//DWORD SafeUnhook_Offset=0;

							//SafeUnhook_Offset=((LONG_PTR)myReal_SafeUnhook)-((LONG_PTR)m2.myhook.handle);

							myReal_SafeUnhook=(decltype(SafeUnhookParams)*)((void*)GetProcAddressEx(hProcess,hMods[i],"SafeUnhook"));
							//hThread = CreateRemoteThread(hProcess, NULL, 1024*1024, (LPTHREAD_START_ROUTINE)nBaseAddress+SafeUnhook_Offset, nBaseAddress, 0, NULL);
							hThread = myCreateRemoteThread(hProcess, NULL, 1024*1024, (LPTHREAD_START_ROUTINE)(INT_PTR)myReal_SafeUnhook, nBaseAddress, 0, NULL);	
							if (hThread)
							{
								myWaitForSingleObject(hThread, 2000);
								myCloseHandle(hThread);
							}
							//MessageBox(0,"unhook","test",0);
							break;
						

							
						}
					}
				}
			}
		}


		myCloseHandle(hProcess);
		hProcess=INVALID_HANDLE_VALUE;
		//MessageBoxA(0,"gothere","shouldwork",0);
	}
}

static DWORD __stdcall InjectProcessThread(LPVOID lp)
{	
	//UNREFERENCED_PARAMETER(lp);



	myEnterCriticalSection(&InjectCritical);
	

	unsigned Start32 = 0 , Start64 = 0;	
		
	ThreadParms *pParms = (ThreadParms*)lp;
	if (lp) { //new process to inject
		Start32 = p32.size(); Start64 = p64.size();
		HANDLE h=myOpenProcess(PROCESS_QUERY_INFORMATION, false, pParms->Pid );
			if(h)
			{	
				BOOL BitCheck=FALSE;
				BOOL ret= myIsWow64Process(h,&BitCheck);
				if(ret!=0)
				{				
					if(BitCheck==FALSE)
					{
						p64.push_back(pParms->Pid);
					}
					else
					{
						p32.push_back(pParms->Pid);
					}
				}
	
			}
			myCloseHandle(h);
	} else { //list processes to inject
		SecEngProcEnumerator_All(p32,p64);
	}


	if(! p64.empty()  )
  	{


		for(unsigned p=Start64;p<p64.size();++p)
		{
			std::string PAHashOut2="";
			if( ReadAndHash(injectLibraryPath64,PAHashOut2) == false)
			{
			
				continue;
			}
			if(PAHashOut2!=Path64Hash)
			{

				continue;
			}
			injectDLL(p64[p],injectLibraryPath64);
			//MessageBox(0,std::to_string(p64[p]).c_str(),"asdf",0);
		}

	}
	if(! p32.empty()  )
	{

		for(unsigned p=Start32;p<p32.size();++p)
		{
			std::string PAHashOut2="";
			if( ReadAndHash(injectLibraryPath32,PAHashOut2) == false)
			{
				continue;
			}
			if(PAHashOut2!=Path32Hash)
			{
				continue;
			}
			injectDLL(p32[p],injectLibraryPath32);
			//MessageBox(0,std::to_string(p32[p]).c_str(),"asdf",0);
		}

	}

	if (lp) {
		if ( pParms->Tid > 1 ) {
			HANDLE h=myOpenThread(THREAD_SUSPEND_RESUME , false , pParms->Tid );
			if (h) { 
				myResumeThread(h); 
				myCloseHandle(h);
			}
		}
		delete pParms;
	}

	myLeaveCriticalSection(&InjectCritical);

	


//	} //infiite inject loop

//	mySleep(60000); // for testing, uninject after 2 mins

//	EjectProcesses(); // testing only remove this shit in prod



	return 0;
}


static void EjectProcesses()
{


	myEnterCriticalSection(&InjectCritical);


	if(!p64.empty() )
	{
		for(unsigned p=0;p<p64.size();++p)
		{
			std::string PAHashOut2="";
			if( ReadAndHash(injectLibraryPath64,PAHashOut2) == false)
			{
				continue;
			}
			if(PAHashOut2!=Path64Hash)
			{
				continue;
			}
			EjectDLL(p64[p],injectLibraryPath64);
		//	MessageBox(0,std::to_string(p64[p]).c_str(),"asd",0);
		}
	}

	if(! p32.empty() )
	{
		for(unsigned p=0;p<p32.size();++p)
		{
			std::string PAHashOut2="";
			if( ReadAndHash(injectLibraryPath32,PAHashOut2) == false)
			{
				continue;
			}
			if(PAHashOut2!=Path32Hash)
			{
				continue;
			}
			EjectDLL(p32[p],injectLibraryPath32);
		//	MessageBox(0,std::to_string(p32[p]).c_str(),"asd",0);
		}
	}

	myLeaveCriticalSection(&InjectCritical);

	//MessageBox(0,"done EjectProcesses()","Done",0);

	return;
}


static DWORD __stdcall ExeVectorThread(LPVOID lp)
{

	UNREFERENCED_PARAMETER(lp);
	while(1)
	{
		POSTExeData();
		Sleep(5000);
	}
	return 0;
}

static std::string ProcessFullPath(DWORD pid)
{
	std::string retval="";
    HANDLE hProcess = myOpenProcess(PROCESS_ALL_ACCESS,FALSE,pid); 
    if(hProcess == NULL)
	{
        return retval;
	}

	char buf[MAX_PATH+1]{};
	if(myGetProcessImageFileNameA(hProcess,buf,MAX_PATH+1)==0)
	{
		myCloseHandle(hProcess);
		return retval;
	}
	retval=buf;
	myCloseHandle(hProcess);
	return retval;
}



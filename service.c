/*
** This file is part of "zebedee"
**
** Copyright 1999 by Neil Winton. All rights reserved.
** 
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
**
** $Id: service.c,v 1.1.1.1 2001-04-12 18:07:12 ndwinton Exp $
**
** $Log: not supported by cvs2svn $
** Revision 1.2  2000/01/08 21:35:22  nwinton
** Version 1.3.0
**
** Revision 1.1  1999/09/24 20:20:58  nwinton
** Cleanup of compiler warnings
**
** Revision 1.0  1999/09/18 21:35:06  nwinton
** Initial revision
**
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>

char *service_c_rcsid = "$Id: service.c,v 1.1.1.1 2001-04-12 18:07:12 ndwinton Exp $";

extern void message(unsigned short, int, char *, ...);

#define	MAX_BUF_SIZE	2048

HANDLE			SvcFinishEvent = NULL;
SERVICE_STATUS		SvcStatus;	/* Current status of service */
SERVICE_STATUS_HANDLE   SvcStatusHandle;
DWORD			SvcError;
HANDLE			SvcThreadHandle = NULL;
char			*SvcName = NULL;
VOID			(*SvcFunction)(VOID *) = NULL;
VOID			*SvcArg = NULL;

DWORD	svcPlatform(void);
VOID	svcRun(char *name, VOID (*function)(VOID *), VOID *arg);
VOID	svcRun9X(char *name);
VOID	svcRunNT(char *name);
VOID	svcMain(DWORD argc, LPTSTR *argv);
VOID	svcControl(DWORD ctrlCode);
BOOL	svcReport(DWORD currentState, DWORD exitCode, DWORD checkPoint,
		  DWORD waitHint);
VOID    svcStop(LPTSTR msg);
int	svcInstall(char *name, char *configFile);
int	svcInstall9X(char *name, char *configFile);
int	svcInstallNT(char *name, char *configFile);
int	svcRemove(char *name);
int	svcRemove9X(char *name);
int	svcRemoveNT(char *name);


DWORD
svcPlatform(void)
{
    OSVERSIONINFO info;

    info.dwOSVersionInfoSize = sizeof(info);
    if (!GetVersionEx(&info))
    {
	message(0, 0, "can't get OS version info");
	return 0;
    }
    return info.dwPlatformId;
}

VOID
svcRun(char *name, VOID (*function)(VOID *), VOID *arg)
{
    DWORD platform = svcPlatform();

    SvcName = name;
    SvcFunction = function;
    SvcArg = arg;

    switch (platform)
    {
    case VER_PLATFORM_WIN32_WINDOWS:
	svcRun9X(name);
	break;

    case VER_PLATFORM_WIN32_NT:
	svcRunNT(name);
	break;

    default:
	message(0, 0, "unsupported OS platform (type %d)", platform);
	break;
    }
}

VOID
svcRunNT(char *name)
{
    SERVICE_TABLE_ENTRY dispatchTable[] = {
        { TEXT(name), (LPSERVICE_MAIN_FUNCTION)svcMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(dispatchTable))
    {
        svcStop("StartServiceCtrlDispatcher failed");
    }
}

VOID
svcRun9X(char *name)
{
    HINSTANCE kernelDll;
    DWORD (*regFn)(void *, DWORD);


    /* Obtain a handle to the kernel library */

    if ((kernelDll = LoadLibrary("KERNEL32.DLL")) == NULL)
    {
	message(0, 0, "can't get handle to kernel library");
	return;
    }

    /* Find the address of the RegisterServiceProcess function */

    regFn = (DWORD (*)(void *, DWORD))GetProcAddress(kernelDll, "RegisterServiceProcess");
    if (regFn == NULL)
    {
	message(0, 0, "can't get the address of RegisterServiceProcess()");
	return;
    }
			
    /* Register this process with the OS as a service */

    if ((*regFn)(NULL, 1 /* RSP_SIMPLE_SERVICE */) == 0)
    {
	message(0, 0, "failed to register service process");
	exit(EXIT_FAILURE);
    }

    /* Run the main routine */

    (*SvcFunction)(SvcArg);

    /* Unregister the process */

    if ((*regFn)(NULL, 0 /* RSP_UNREGISTER_SERVICE */) == 0)
    {
	message(0, 0, "failed to unregister service process");
	exit(EXIT_FAILURE);
    }

    /* Free the kernel library */

    FreeLibrary(kernelDll);

    exit(EXIT_SUCCESS);
}

/*
**  svcMain
**
** This function starts the service worker thread proper. It then waits
** for the worker to terminate.
**
*/

VOID
svcMain(DWORD argc, LPTSTR *argv)
{
    DWORD   wait;


    /* Register the control handler */

    SvcStatusHandle = RegisterServiceCtrlHandler(TEXT(SvcName),
						 (LPHANDLER_FUNCTION)svcControl);
    if (!SvcStatusHandle)
    {
	message(0, 0, "failed to register service control handler");
	goto finish;
    }

    /* Initialise static service status values */

    SvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    SvcStatus.dwServiceSpecificExitCode = 0;

    /* Report to SCM */

    if (!svcReport(SERVICE_START_PENDING,   /* Service state */
		   NO_ERROR,		    /* Exit code */
		   1,			    /* Checkpoint number */
		   5000))		    /* Wait hint -- 5 secs */
    {
	message(0, 0, "failed to report status to SCM");
	goto finish;
    }

    /*
    ** Create the "stop event" object. The arguments indicate a manually
    ** reset event whose initial state is unset.
    */

    if ((SvcFinishEvent = CreateEvent(NULL, 1, 0, NULL)) == NULL)
    {
	goto finish;
    }

    /* Report next checkpoint to SCM */

    if (!svcReport(SERVICE_START_PENDING, NO_ERROR, 2, 5000))
    {
	message(0, 0, "failed to report status to SCM");
	goto finish;
    }

    /* Start the worker thread */

    SvcThreadHandle = (HANDLE)_beginthread(SvcFunction, 65536, SvcArg);
    if (!SvcThreadHandle)
    {
	message(0, 0, "failed to create worker thread");
	goto finish;
    }

    /* Report all systems GO! */

    if (!svcReport(SERVICE_RUNNING, NO_ERROR, 0, 0))
    {
	message(0, 0, "failed to report status to SCM");
        goto finish;
    }

    /* Wait until SvcFinishEvent is set */

    wait = WaitForSingleObject(SvcFinishEvent, INFINITE);

finish:
    if (SvcFinishEvent != NULL)
    {
	CloseHandle(SvcFinishEvent);
    }

    /* Report to SCM if possible */

    if (SvcStatusHandle != 0)
    {
	svcReport(SERVICE_STOPPED, SvcError, 0, 0);
    }

    return;
}

/*
** svcControl
**
** Handle SCM service control requests
*/

VOID
svcControl(DWORD code)
{
    DWORD  state = SERVICE_RUNNING;
 

    switch(code)
    {
    case SERVICE_CONTROL_PAUSE:
	if (SvcStatus.dwCurrentState == SERVICE_RUNNING)
	{
	    SuspendThread(SvcThreadHandle);
	    state = SERVICE_PAUSED;
	}
        break;

    case SERVICE_CONTROL_CONTINUE:
	if (SvcStatus.dwCurrentState == SERVICE_PAUSED)
	{
	    ResumeThread(SvcThreadHandle);
	    state = SERVICE_RUNNING;
	}
	break;

    case SERVICE_CONTROL_STOP:
	state = SERVICE_STOP_PENDING;
	svcReport(SERVICE_STOP_PENDING, NO_ERROR, 1, 5000);
	SetEvent(SvcFinishEvent);
	return;

    case SERVICE_CONTROL_INTERROGATE:
	break;

    default:
	break;
    }

    svcReport(state, NO_ERROR, 0, 0);
}

/*
** svcReport
**
** Update the SCM with the current state of the service.
*/

BOOL
svcReport(DWORD currentState, DWORD exitCode, DWORD checkPoint, DWORD waitHint)
{
    BOOL result;

    /* Disable control requests while starting */

    if (currentState == SERVICE_START_PENDING)
    {
	SvcStatus.dwControlsAccepted = 0;
    }
    else
    {
	SvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP |
				       SERVICE_ACCEPT_PAUSE_CONTINUE;
    }

    SvcStatus.dwCurrentState = currentState;
    SvcStatus.dwWin32ExitCode = exitCode;
    SvcStatus.dwCheckPoint = checkPoint;
    SvcStatus.dwWaitHint = waitHint;

    /* Make the report */

    if (!(result = SetServiceStatus(SvcStatusHandle, &SvcStatus)))
    {
	/* If there is an error then bail out */
	svcStop("SetServiceStatus failed!");
    }

    return result;
}

/*
** svcStop
**
** Report an error and stop the service
*/

VOID
svcStop(LPTSTR msg)
{
    SvcError = GetLastError();

    message(0, 0, "failed in Win32 service routines: code %#0x", SvcError);

    /* Signal the main routine to finish */

    SetEvent(SvcFinishEvent);
}

int
svcInstall(char *name, char *configFile)
{
    const char *runArg = "-Srun";
    char path[MAX_BUF_SIZE];
    char cmd[MAX_BUF_SIZE];
    const char *flag = "-f";
    const char *quote = "\"";
    DWORD platform = svcPlatform();


    if (configFile == NULL)
    {
	flag = "";
	quote = "";
	configFile = "";
    }

    /*
    ** Get the filename of the running executable. We need to leave
    ** space in the buffer for additional arguments, whitespace and
    ** quotes ...
    */

    if (GetModuleFileName(NULL, path,
			  MAX_BUF_SIZE - (strlen(configFile) + 20)) == 0)
    {
	message(0, 0, "can't get executable path");
	return EXIT_FAILURE;
    }

    /*
    ** Build the command string. If a config file was specified
    ** this will be of the form:
    **
    **	"program path" -f "config file" -Srun
    */

    sprintf(cmd, "\"%s\" %s %s%s%s %s", path,
	    flag, quote, configFile, quote, runArg);

    switch (platform)
    {
    case VER_PLATFORM_WIN32_WINDOWS:
	return svcInstall9X(name, cmd);
	break;

    case VER_PLATFORM_WIN32_NT:
	return svcInstallNT(name, cmd);
	break;

    default:
	message(0, 0, "unsupported OS platform (type %d)", platform);
	break;
    }
    return EXIT_FAILURE;
}

int
svcInstallNT(char *name, char *cmd)
{
    SC_HANDLE svcHandle;
    SC_HANDLE scmHandle;


    /* Open the local SCM database */

    if ((scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL)
    {
	message(0, 0, "can't open SCM database");
	return EXIT_FAILURE;
    }

    /* Now create the service entry */

    svcHandle = CreateService(scmHandle,    /* SCM database handle */
			      name,	    /* Name of service */
			      name,	    /* Display name */
			      SERVICE_ALL_ACCESS,	/* Desired access */
			      SERVICE_WIN32_OWN_PROCESS,/* Run in own process */
			      SERVICE_AUTO_START,	/* Start during boot */
			      SERVICE_ERROR_NORMAL,	/* Show message but continue boot */
			      cmd,	    /* Program plus arguments */
			      NULL,	    /* No load ordering group */
			      NULL,	    /* No tag identifier */
			      NULL,	    /* No dependencies */
			      NULL,	    /* Use LocalSystem account */
			      NULL);	    /* No password */
    CloseServiceHandle(scmHandle);

    if (svcHandle == NULL)
    {
	message(0, 0, "can't create service");
	return EXIT_FAILURE;
    }

    CloseServiceHandle(svcHandle);

    message(1, 0, "%s service installed to run '%s'", name, cmd);

    return EXIT_SUCCESS;
}

int
svcInstall9X(char *name, char *cmd)
{
    HKEY    runKey;


    /* Open RunServices registry key */

    if (RegCreateKey(HKEY_LOCAL_MACHINE,
		     "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
		     &runKey) != ERROR_SUCCESS)
    {
	message(0, 0, "can't locate registry key");
	return EXIT_FAILURE;
    }

    /* Add value for this service */

    if (RegSetValueEx(runKey, name, 0, REG_SZ, cmd, strlen(cmd) + 1) != ERROR_SUCCESS)
    {
	RegCloseKey(runKey);
	message(0, 0, "failed to add value to registry");
	return EXIT_FAILURE;
    }

    RegCloseKey(runKey);

    message(1, 0, "%s service installed to run '%s'", name, cmd);

    return EXIT_SUCCESS;
}

int
svcRemove(char *name)
{
    DWORD platform = svcPlatform();


    switch (platform)
    {
    case VER_PLATFORM_WIN32_WINDOWS:
	return svcRemove9X(name);
	break;

    case VER_PLATFORM_WIN32_NT:
	return svcRemoveNT(name);
	break;

    default:
	message(0, 0, "unsupported OS platform (type %d)", platform);
	break;
    }

    return EXIT_FAILURE;
}

int
svcRemoveNT(char *name)
{
    SC_HANDLE   svcHandle;
    SC_HANDLE   scmHandle;
    SERVICE_STATUS status;
    int		retStatus = EXIT_SUCCESS;


    /* Open the SCM */

    if ((scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) != NULL)
    {
	svcHandle = OpenService(scmHandle, name, SERVICE_ALL_ACCESS);

	if (svcHandle != NULL)
	{
	    /* Try to stop the service */

	    if (ControlService(svcHandle, SERVICE_CONTROL_STOP, &status))
	    {
		while (QueryServiceStatus(svcHandle, &status))
		{
		    if (status.dwCurrentState == SERVICE_STOP_PENDING)
		    {
			Sleep(1000);
		    }
		    else
		    {
			break;
		    }
		}

		if (status.dwCurrentState != SERVICE_STOPPED)
		{
		    message(0, 0, "failed to stop the '%s' service", name);
		    retStatus = EXIT_FAILURE;
		}
	    }

	    /* Now remove the service from the SCM */

	    if (DeleteService(svcHandle))
	    {
		message(1, 0, "successfully removed the '%s' service", name);
	    }
	    else
	    {
		message(0, 0, "failed to remove the '%s' service", name);
		retStatus = EXIT_FAILURE;
	    }

	    CloseServiceHandle(svcHandle);
	}
	else
	{
	    message(0, 0, "can't find the '%s' service", name);
	    retStatus = EXIT_FAILURE;
	}

	CloseServiceHandle(scmHandle);
    }
    else
    {
	message(0, 0, "can't contact Service Control Manager");
	retStatus = EXIT_FAILURE;
    }

    return retStatus;
}


int
svcRemove9X(char *name)
{
    HKEY runKey;
    int status = EXIT_SUCCESS;


    /* Locate the RunServices registry entry */

    if (RegOpenKey(HKEY_LOCAL_MACHINE, 
		   "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
		   &runKey) != ERROR_SUCCESS)
    {
	message(0, 0, "can't find the RunServices registry key");
	status = EXIT_FAILURE;
    }
    else
    {
	/* Delete the key value for our service */

	if (RegDeleteValue(runKey, name) != ERROR_SUCCESS)
	{
	    message(0, 0, "failed to delete registry RunServices entry for '%s'", name);
	    status = EXIT_FAILURE;
	}
	else
	{
	    message(1, 0, "successfully removed the '%s' service", name);
	}

	RegCloseKey(runKey);
    }

    return status;
}

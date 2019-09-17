<#
.SYNOPSIS
NtSuspend Process syscall test 
Author:  Souhardya Sardar
#>

function Get-DelegateType
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

function Get-ProcAddress
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
$proc = $openProc.Invoke(0x00000800, $false, 13828)  #change pid here 


$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)


#Winver : Windows Version 1803
[Byte[]] $ntsuspendstub = @(0x49, 0x89, 0xCA, 0xB8, 0xB3, 0x01, 0x00, 0x00, 0x0F, 0x05, 0xC3)
   #0:   49 89 ca                mov    %rcx,%r10
   #3:   b8 b3 01 00 00          mov    $0x1b3,%eax
   #8:   0f 05                   syscall
   #a:   c3                      retq

$suspendDelegate = Get-DelegateType @([IntPtr]) ([UInt32])
$shellcodeBuf = $VirtualAlloc.Invoke([System.IntPtr]::Zero, $ntsuspendstub.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($ntsuspendstub, 0, $shellcodeBuf, $ntsuspendstub.Length)
$sysdelgate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($shellcodeBuf, $suspendDelegate)
$sysdelgate.DynamicInvoke($proc)








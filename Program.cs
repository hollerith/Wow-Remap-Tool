using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;

namespace Remap_Memory_Region
{
    class Program : NativeMethods
    {
        static void Main(string[] args)
        {
            Process process = Process.GetProcessesByName("Wow").FirstOrDefault();
            IntPtr hProcess = OpenProcess(ProcessAccessFlags.PROCESS_ALL_ACCESS, false, process.Id);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("Failed on OpenProcess. Handle is invalid.");
                return;
            }

            if (VirtualQueryEx(hProcess, process.MainModule.BaseAddress, out MEMORY_BASIC_INFORMATION basicInformation, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0)
            {
                Console.WriteLine("Failed on VirtualQueryEx. Return is 0 bytes.");
                return;
            }
            IntPtr regionBase = basicInformation.baseAddress;
            IntPtr regionSize = basicInformation.regionSize;
            NtSuspendProcess(hProcess);
            RemapMemoryRegion2(hProcess, regionBase, regionSize.ToInt32(), MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);            //MISSING VIRTUALALLOC
            NtResumeProcess(hProcess);
            CloseHandle(hProcess);

        }
        public static bool RemapMemoryRegion2(IntPtr processHandle, IntPtr baseAddress, int regionSize, MemoryProtectionConstraints mapProtection)
        {
            IntPtr addr = VirtualAllocEx(processHandle, IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            if (addr == IntPtr.Zero)
                return false;

            IntPtr copyBuf = VirtualAlloc(IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            IntPtr copyBufEx = VirtualAllocEx(processHandle, IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            byte[] copyBuf2 = new byte[regionSize];

            if (!ReadProcessMemory(processHandle, baseAddress, copyBuf, regionSize, out IntPtr bytes))
                return false;

            if (!ReadProcessMemory(processHandle, baseAddress, copyBuf2, regionSize, out bytes))
                return false;

            IntPtr sectionHandle = default;
            long sectionMaxSize = regionSize;


            Ntstatus status = NtCreateSection(ref sectionHandle, AccessMask.SECTION_ALL_ACCESS, IntPtr.Zero, ref sectionMaxSize, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE, SectionProtectionConstraints.SEC_COMMIT, IntPtr.Zero);

            if (status != Ntstatus.STATUS_SUCCESS)
                return false;

            status = NtUnmapViewOfSection(processHandle, baseAddress);

            if (status != Ntstatus.STATUS_SUCCESS)
                return false;



            IntPtr viewBase = baseAddress;
            long sectionOffset = default;
            uint viewSize = 0;
            status = NtMapViewOfSection(sectionHandle,
                                               processHandle,
                                               ref viewBase,
                                               UIntPtr.Zero,
                                               regionSize,
                                               ref sectionOffset,
                                               ref viewSize,
                                               2,
                                               0,
                                               MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);


            if (status != Ntstatus.STATUS_SUCCESS)
                return false;

            if (!WriteProcessMemory(processHandle, viewBase, copyBuf, (int)viewSize, out bytes))
                return false;

            if (!WriteProcessMemory(processHandle, copyBufEx, copyBuf, (int)viewSize, out bytes))
                return false;

            MemoryProtectionConstraints old = MemoryProtectionConstraints.PAGE_NOACCESS;

            if (!VirtualProtectEx(processHandle, copyBufEx, (int)viewSize, MemoryProtectionConstraints.PAGE_EXECUTE_READ, out old))
                return false;

            if (!VirtualFree(copyBuf, 0, MemFree.MEM_RELEASE))
                return false;

            //crc32 bypass

            //search for F2 ?? 0F 38 F1 - F2 REX.W 0F 38 F1 /r CRC32 r64, r/m64	RM	Valid	N.E.	Accumulate CRC32 on r/m64.
            byte[] AoBpattern = { 0xF2, 0x42, 0x0F, 0x38, 0xF1 };
            for (long i = 0; i < regionSize; i++)
            {
                bool isMatch = true;
                for (long j = 0; j < AoBpattern.Length; j++)
                {
                    if (!(copyBuf2[i+j] == AoBpattern[j] || j == 1))
                    {
                        isMatch = false;
                        break;
                    }
                }
                if (isMatch)
                {
                    Console.WriteLine($"CRC found at 0x{((long)baseAddress + i).ToString("X")}");
                    // [wow.exe+0x270]
                    detourCRC(processHandle, (long)baseAddress+i, (long)baseAddress, 0x20a85ff, (long)copyBufEx);
                }
            }

            return true;

        }

        public static bool detourCRC(IntPtr processHandle, long crcLocation, long wowBase, long wowSize, long wowCopyBase)
        {
            #region asmCave
            byte[] crcDetour =
            {
                0x51,                                                               //push rcx
                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov rcx, CaveAddr (0x03)
                0xFF, 0xF1,                                                         //call rcx
                0x59,                                                               //pop rcx
                0x90                                                                //nop
            };
            byte[] crcCave =
            {
                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov rcx, wowBase (0x02)
                0x48, 0x39, 0xCF,                                                   //cmp rdi,rcx
                0x7C, 0x29,                                                         //jl crc
                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov rcx, wowBaseEnd (0x11)
                0x48, 0x39, 0xCF,                                                   //cmp rdi, rcx
                0x7F, 0x1A,                                                         //jg crc
                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov rcx, Wowbase (0x20)
                0x48, 0x29, 0xCF,                                                   //sub rdi, rcx
                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov rcx, wowCopyBase (0x2D)
                0x48, 0x01, 0xCF,                                                   //add rdi,rcx
                0xF2, 0x48, 0x0F, 0x38, 0xF1, 0x1C, 0xC7,                           //crc32 rbc,[rdi+rax*8]
                0x48, 0xFF, 0xC0,                                                   //inc rax
                0x48, 0x3B, 0xC2,                                                   //cmp rax,rdx
                0x72, 0xF1,                                                         //jb crc
                0xC3                                                                //ret
            };
            #endregion asmCave

            IntPtr CaveAddr = VirtualAllocEx(processHandle, IntPtr.Zero, crcCave.Length, MemoryAllocationType.MEM_COMMIT, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            if(CaveAddr == IntPtr.Zero)
            {
                Console.WriteLine("VirtualAlloxEx error");
                return false;
            }

            
            byte[] splitCaveAddr = BitConverter.GetBytes(CaveAddr.ToInt64());       //write CaveAddr to crcDetour buffer
            byte[] splitWowBase = BitConverter.GetBytes(wowBase);                   //write wowBase to crcCave buffer
            byte[] splitWowBaseEnd = BitConverter.GetBytes((wowBase + wowSize));    //write wowBaseEnd to crcCave buffer
            byte[] splitWowCopyBase = BitConverter.GetBytes(wowCopyBase);           //write wowCopyBase to crcCave buffer

            for (int i = 0; i < 8; i++)
            {
                crcDetour[0x03 + i] = splitCaveAddr[i];     //CaveAdr
                crcCave[0x02 + i] = splitWowBase[i];        //WowBase
                crcCave[0x20 + i] = splitWowBase[i];        //WowBase
                crcCave[0x11 + i] = splitWowBaseEnd[i];     //WowBaseEnd
                crcCave[0x2D + i] = splitWowCopyBase[i];    //WowCopyBase
            }

            IntPtr bWrite = IntPtr.Zero;
            if(!WriteProcessMemory(processHandle, (IntPtr)(crcLocation), crcDetour, crcDetour.Length, out bWrite))
            {
                Console.WriteLine("Writing CRC detour failed");
                return false;
            }
            if(!WriteProcessMemory(processHandle, CaveAddr, crcCave, crcCave.Length, out bWrite))
            {
                Console.WriteLine("Writing CRC CodeCave failed");
                return false;
            }

            Console.WriteLine($"Detoured CRC at {crcLocation.ToString("X")} to {CaveAddr.ToString("X")}");
            return true;
        }
        public static bool RemapMemoryRegion(IntPtr processHandle, IntPtr baseAddress, int regionSize, MemoryProtectionConstraints mapProtection)
        {
            IntPtr addr = VirtualAlloc(IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            if (addr == IntPtr.Zero)
                return false;

            IntPtr copyBuf = VirtualAlloc(IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);

            if (!ReadProcessMemory(processHandle, baseAddress, copyBuf, regionSize, out IntPtr bytes))
                return false;
            
            IntPtr sectionHandle = default;
            long sectionMaxSize = regionSize;

            
            Ntstatus status = NtCreateSection(ref sectionHandle, AccessMask.SECTION_ALL_ACCESS, IntPtr.Zero, ref sectionMaxSize, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE, SectionProtectionConstraints.SEC_COMMIT, IntPtr.Zero);
            
            if (status != Ntstatus.STATUS_SUCCESS)
                return false;

            status = NtUnmapViewOfSection(processHandle, baseAddress);

            if (status != Ntstatus.STATUS_SUCCESS)
                return false;



            IntPtr viewBase = baseAddress;
            long sectionOffset = default;
            uint viewSize = 0;
            status = NtMapViewOfSection(sectionHandle,
                                               processHandle,
                                               ref viewBase,
                                               UIntPtr.Zero,
                                               regionSize,
                                               ref sectionOffset,
                                               ref viewSize,
                                               2,
                                               0,
                                               MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);

            if (status != Ntstatus.STATUS_SUCCESS)
                return false;

            if (!WriteProcessMemory(processHandle, viewBase, copyBuf, (int)viewSize, out bytes))
                return false;

            if(!VirtualFree(copyBuf, 0, MemFree.MEM_RELEASE))
                return false;

            return true;

        }

        //CRC find
        //instruction: https://www.felixcloutier.com/x86/crc32

        /*
         * 
                Opcode/Instruction	Op/En	64-Bit Mode	Compat/Leg Mode	Description
                F2 0F 38 F0 /r CRC32 r32, r/m8	RM	Valid	Valid	Accumulate CRC32 on r/m8.
                F2 REX 0F 38 F0 /r CRC32 r32, r/m8*	RM	Valid	N.E.	Accumulate CRC32 on r/m8.
                F2 0F 38 F1 /r CRC32 r32, r/m16	RM	Valid	Valid	Accumulate CRC32 on r/m16.
                F2 0F 38 F1 /r CRC32 r32, r/m32	RM	Valid	Valid	Accumulate CRC32 on r/m32.
                F2 REX.W 0F 38 F0 /r CRC32 r64, r/m8	RM	Valid	N.E.	Accumulate CRC32 on r/m8.
                F2 REX.W 0F 38 F1 /r CRC32 r64, r/m64	RM	Valid	N.E.	Accumulate CRC32 on r/m64.

         */
            // F2 ?? 0F 38 F1

        }
    }

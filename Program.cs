using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;
using System.Collections.Generic;

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
                    //[wow.exe+0x270] == sizeof(.text)
                    //detourCRC(processHandle, (long)baseAddress+i, (long)baseAddress, 0, (long)copyBufEx);
                    detourCRC(processHandle, (long)baseAddress+i, (long)baseAddress, 0x20A7600 + 0x1000-1, (long)copyBufEx);
                }
            }

            return true;

        }

        public static bool detourCRC(IntPtr processHandle, long crcLocation, long wowBase, long wowSize, long wowCopyBase)
        {
            #region asmCave
            byte[] crcDetour =
            {
                0x50,                                                               //push rax
                0x48, 0xB8, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov rax, CaveAddr (0x03)
                0xFF, 0xD0,                                                         //call rax
                0x58,                                                               //pop rax
                0x90                                                                //nop
            };
            byte[] crcDetourRegOffsets = { 0x00, 0x02, 0x0C, 0x0D }; //regiser offsets (may need to change when register is used in code)

            byte[] crcCave =
            {
                0x51,                                                               //push rcx (r1)

                //0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov r1, wowBase (0x02)
                //0x90, 0x90, 0x90,
                0x48, 0x39, 0xCF,                                                   //cmp r2, r1 (r2-0x0A)
                0x7C, 0x29,                                                         //jl crc
                //0x90, 0x90,
                //0x72, 0x29,                                                         //jb crc
                //0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,       //mov r1, wowBaseEnd (0x11)
                
                //0x50,                                                              //push rax
                //0x48, 0x8B, 0xC1,                                                  //mov rax, rcx
                //0x48, 0x8B, 0x89, 0x78, 0x02, 0x00, 0x00, 0x90, 0x90, 0x90,         //mov r1, [r1+0x278]   & NOP NOP NOP
                //0x48, 0x01, 0xC1,                                                 //add rcx,rax
                //0x48, 0x8B, 0x80, 0x74, 0x02, 0x00, 0x00, 0x90, 0x90, 0x90          //mov rax,[rax+0x274]
                //0x48, 0x01, 0xC1,                                                 //add rcx,rax
                //0x58,                                                             //pop rax

                //0x90, 0x90, 0x90,
                0x48, 0x39, 0xCF,                                                   //cmp r2, r1 (r2-0x19)
                
                0x7F, 0x1A,                                                         //jg crc
                //0x7D, 0x1A,                                                         //jge crc
                //0x73, 0x1A,                                                         //jae crc
                
                //0x90, 0x90,
                //0x77, 0x1A,                                                         //ja crc
                //0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov r1, Wowbase (0x20)
                //0x90, 0x90, 0x90,
                0x48, 0x29, 0xCF,                                                   //sub r2, r1 (r2-0x28)
                //0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov r1, wowCopyBase (0x2D)
                //0x90, 0x90, 0x90,
                0x48, 0x01, 0xCF,                                                   //add r2, r1 (r2-0x35)

                0x59,                                                               //pop rcx (r1)

                //crc start
                0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,                           //+ 0x38
                0x90, 0x90, 0x90,
                0x90, 0x90, 0x90, 0x90, 0x90,                                       // 15 - 19 bytes

                0x90, 0x90, 0x90,                                                   // 0x72 0x?? - jb instructions 
                //0xF2, 0x48, 0x0F, 0x38, 0xF1, 0x1C, 0xC7,                         //crc32 rbx,[r2+rax*8] - orig?
                //0x48, 0xFF, 0xC0,                                                 //inc rax
                //0x48, 0x3B, 0xC2,                                                 //cmp rax, rcx
                //0x72, 0xF1,                                                       //jb crc
                //crc end

                0xC3                                                                //ret
            };
            byte[] crcCaveRegInstructOffsets = { 0x0A, 0x19, 0x28, 0x35 }; //register offsets (may need to change when register is used in code)
            byte[] crcCaveRegOffsets = { 0x01, 0x0C, 0x10, 0x1B, 0x1F, 0x2A, 0x2C, }; //register offsets (may need to change when register is used in code)
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

            //remove the beef (placeholders)
            for (int i = 0; i < 8; i++)
            {
                crcDetour[0x03 + i] = splitCaveAddr[i];         //CaveAdr
                crcCave[0x02 + 1 + i] = splitWowBase[i];        //WowBase
                crcCave[0x11 + 1 + i] = splitWowBaseEnd[i];     //WowBaseEnd
                crcCave[0x20 + 1 + i] = splitWowBase[i];        //WowBase
                crcCave[0x2D + 1 + i] = splitWowCopyBase[i];    //WowCopyBase
            }

            //obtain crc instructions
            byte[] crcBuffer = new byte[42];
            if (!ReadProcessMemory(processHandle, (IntPtr)crcLocation, crcBuffer, crcBuffer.Length, out IntPtr bRead))
            {
                Console.WriteLine("Reading CRC location failed");
                return false;
            }

            int origCrcInstructionLength = -1;
            for (int i = 0; i < 88; i++)
            {
                //jb is the last instruction and starts with 0x72 (2 bytes long)
                crcCave[0x38 + 2 + i] = crcBuffer[i];               //write byte to codecave
                if(crcBuffer[i] == 0x72)
                {
                    crcCave[0x38 + 2 + i + 1] = crcBuffer[i + 1];   //include last byte of JB instruction before breaking
                    origCrcInstructionLength = i + 2;               //Keep track of bytes used to NOP later
                    break;
                }
            }

            //list all registers and set unused
            //bool[] usedCodebaseRegs = { true, true, true, true, true, true, true, true }; //rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi
            //usedCodebaseRegs[(crcBuffer[0x06] - 0xC0) / 8] = false; //chec reg used

            ////find unused register
            //byte selectCcReg = 0;
            //for (byte r = 0; r < usedCodebaseRegs.Length; r++)
            //{
            //    if (usedCodebaseRegs[r] == false)
            //    {
            //        selectCcReg = r;
            //        break;
            //    }
            //}

            //for(int i = 0; i < 123; i++)
            //{
            //    crcDetour[i] += selectCcReg; //set selected register
            //}

            //{
            //    //decrease each register byte to replace rcx with rax
            //    crcDetour[0x00] -= 1;
            //    crcDetour[0x02] -= 1;
            //    crcDetour[0x0C] -= 1;
            //    crcDetour[0x0D] -= 1;

            //}

            //list used registers
            bool[] usedRegs = { false, false, false, false, false, false, false, false }; //rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi

            //check byte code to find used stuff
            usedRegs[(crcBuffer[0x05]-0x04)/8] = true;           //x,[reg+reg*8]
            usedRegs[(crcBuffer[0x09]-0xC0)] = true;             //inc x

            if(crcBuffer[0x0C] >= 0xC0 && crcBuffer[0x0C] < 0xC8)
                usedRegs[(crcBuffer[0x0C]-0xC0)] = true;         // cmp ?, x


            byte selectReg = 0;
            for(byte r = 0; r < usedRegs.Length; r++)
            {
                if (usedRegs[r] == false)
                {
                    selectReg = r;
                    break;
                }
            }

            //change Detour to non-used register
            for(int i = 0; i < crcDetourRegOffsets.Length; i++)
            {
                crcDetour[crcDetourRegOffsets[i]] += selectReg;      //increase byte to set selected register
            }

            //Change the register (r2) used to calc crc32

            //TODO: place in array and loop
            //for(int i = 0; i < crcCaveRegOffsets.Length; i++)
            //{
            //    crcCave[crcCaveRegOffsets[i] + 1 + 0] = crcBuffer[0x01];
            //    crcCave[crcCaveRegOffsets[i] + 1 + 2] = (byte)(crcBuffer[0x06] + 0x08);
            //}

            //cmp r2, r1 - 0x0A             - 48 39 CF
            crcCave[0x0A + 1 + 0] = crcBuffer[0x01];
            crcCave[0x0A + 1 + 2] = crcBuffer[0x06];
            if (crcCave[0x0A + 1 + 0] != 0x48)
                crcCave[0x0A + 1 + 0] = 0x49;
            else
                crcCave[0x0A + 1 + 2] += 8;

            //cmp r2, r1 - 0x19             - 48 39 CF
            crcCave[0x19 + 1 + 0] = crcBuffer[0x01];
            crcCave[0x19 + 1 + 2] = crcBuffer[0x06];
            if (crcCave[0x19 + 1 + 0] != 0x48)
                crcCave[0x19 + 1 + 0] = 0x49;
            else
                crcCave[0x19 + 1 + 2] += 8;

            //sub r2, r1 (r2-0x28)          - 48 29 CF
            crcCave[0x28 + 1 + 0] = crcBuffer[0x01];
            crcCave[0x28 + 1 + 2] = crcBuffer[0x06];
            if (crcCave[0x28 + 1 + 0] != 0x48)
                crcCave[0x28 + 1 + 0] = 0x49;
            else
                crcCave[0x28 + 1 + 2] += 8;
            
            

            //add r2, r1 (r2-0x35)          - 48 01 CF
            crcCave[0x35 + 1 + 0] = crcBuffer[0x01];
            crcCave[0x35 + 1 + 2] = crcBuffer[0x06];
            if (crcCave[0x35 + 1 + 0] != 0x48)
                crcCave[0x35 + 1 + 0] = 0x49;
            else
                crcCave[0x35 + 1 + 2] += 8;


            /*
             - Comparing
                cmp rax,rcx 
                48 39 X
                C8 -> rax
                C9 -> rcx
                CA -> rdx
                CB -> rbx
                CC -> rsp
                CD -> rbp
                CE -> rsi
                CF -> rdi

                cmp rX, rcx

                49 39 CX
                x = reg nr
             - Subtract - 3 byte, 48/49 - 29 - regNr
                sub rax,rcx
                48 29 X
                C8 -> rax
                C9 -> rcx
                CA -> rdx
                CB -> rbx
                CC -> rsp
                CD -> rbp
                CE -> rsi
                CF -> rdi

                49 29 CX
                x = reg nr

             - Add - 3 byte, 48/49 - 01 - regNr
                add rax,rcx
                48 01 X
                C8 -> rax
                C9 -> rcx
                CA -> rdx
                CB -> rbx
                CC -> rsp
                CD -> rbp
                CE -> rsi
                CF -> rdi

                49 01 CX
                x = reg nr

            - CRC32
                crc32 rsi,[rax+rax*8]
                F2 48 0F 38 F0 34 C0 rax
                F2 48 0F 38 F0 34 C1 rcx
                F2 48 0F 38 F0 34 C2 rdx
                F2 48 0F 38 F0 34 C3 rbx
                F2 49 0F 38 F0 34 C0 r8
                F2 49 0F 38 F0 34 C7 r15
                    48/49         CX
            */

            //add nops to end of the detour buffer
            byte[] crcDetourFixed = new byte[origCrcInstructionLength];
            for(int i = 0; i < origCrcInstructionLength; i++)
            {
                if(i < crcDetour.Length)
                {
                    //Copy byte from crcDetour to fixed crcDetour
                    crcDetourFixed[i] = crcDetour[i];
                }
                else
                {
                    //add NOPs
                    crcDetourFixed[i] = 0x90;
                }
            }

            if (!WriteProcessMemory(processHandle, (IntPtr)(crcLocation), crcDetourFixed, crcDetourFixed.Length, out IntPtr bWrite))
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

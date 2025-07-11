//Finds and labels the syscall table and all the syscalls contained in it.
//
//Once started, the script will prompt for the two syscall shim DLLs (sdklib.dll and krnllib.dll) that contain all the syscall symbols. You must extract them from the DAT files that come with the ROM file you are reversing.
//@author Project Muteki
//@category Besta RTOS
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.AccessMode;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.bin.format.pe.DataDirectory;
import ghidra.app.util.bin.format.pe.ExportDataDirectory;
import ghidra.app.util.bin.format.pe.ExportInfo;
import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.LocalFileSystem;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

public class SyscallLabeler extends GhidraScript {
	private static final String SYSCALL_HANDLER_PATTERN = (
		// syscall_handler:
		// stmdb sp!, {r0, r1}
		"\\x03\\x00\\x2d\\xe9" +
		// ldr r0, [lr, -4]
		"\\x04\\x00\\x1e\\xe5" +
		// bic r0, r0, 0xff000000
		"\\xff\\x04\\xc0\\xe3" +
		// tst r0, 0x10000
		"\\x01\\x08\\x10\\xe3" +
		// bne handle_sdklib_syscall
		"\\x02\\x00\\x00\\x1a" +
		// tst r0, 0x20000
		"\\x02\\x08\\x10\\xe3" +
		// bne handle_krnllib_syscall
		"\\x03\\x00\\x00\\x1a" +
		// bl extern panic_nosys (bl ?)
		"...\\xeb" +
		// handle_sdklib_syscall:
		// bic r0, r0, 0xff0000
		"\\xff\\x08\\xc0\\xe3" +
		// ldr r1, extern =syscall_table_sdk (ldr r1, [pc, ?])
		".[\\x10-\\x1f]\\x9f\\xe5" +
		// b call_syscall_function
		"\\x01\\x00\\x00\\xea" +
		// bic r0, r0, 0xff0000
		"\\xff\\x08\\xc0\\xe3" +
		// ldr r1, extern =syscall_table_krnl (ldr r1, [pc, ?])
		".[\\x10-\\x1f]\\x9f\\xe5" +
		// call_syscall_function:
		// add r1, r1, r0 lsl 2
		"\\x00\\x11\\x81\\xe0" +
		// ldr r0, [r1]
		"\\x00\\x00\\x91\\xe5" +
		// str r0, [sp, 0xc]
		"\\x0c\\x00\\x8d\\xe5" +
		// ldmia sp!, {r0, r1, lr, pc}^
		"\\x03\\xc0\\xfd\\xe8"
	);
	private static final LocalFileSystem fs = LocalFileSystem.makeGlobalRootFS();

	@Override
	protected void run() throws Exception {
		//TODO: Add script code here
		final File sdklib = askFile("Select sdklib.dll", "Select");
		final File krnllib = askFile("Select krnllib.dll", "Select");

		final Address handlerOffset = this.findBytes(null, SYSCALL_HANDLER_PATTERN);
		if (handlerOffset == null) {
			println("Error: Cannot locate syscall handler.");
			return;
		}
		printf("Found syscall handler at %s.\n", handlerOffset.toString());
		this.createFunction(handlerOffset, "syscall_handler");

		final Address sdklibLoadInstOffset = handlerOffset.add(9 * 4);
		final Address sdklibLoadPC = sdklibLoadInstOffset.add(2 * 4);
		final Address krnllibLoadInstOffset = handlerOffset.add(12 * 4);
		final Address krnllibLoadPC = krnllibLoadInstOffset.add(2 * 4);

		final long sdklibLoadInst = getInt(sdklibLoadInstOffset) & 0xffffffffl;
		final long krnllibLoadInst = getInt(krnllibLoadInstOffset) & 0xffffffffl;
		
		final AddressSpace as = this.getAddressFactory().getDefaultAddressSpace();
		final Address sdklibTable = as.getAddress(this.getInt(sdklibLoadPC.add(sdklibLoadInst & 0xfffl)) & 0xffffffffl);
		final Address krnllibTable = as.getAddress(this.getInt(krnllibLoadPC.add(krnllibLoadInst & 0xfffl)) & 0xffffffffl);
		printf("Found sdklib syscall table at %s and krnllib syscall table at %s\n", sdklibTable.toString(), krnllibTable.toString());

		List<Entry<Integer, String>> sdklibSyscalls = generateSyscallTableFrom(sdklib);
		List<Entry<Integer, String>> krnllibSyscalls = generateSyscallTableFrom(krnllib);
		
		for (Entry<Integer, String> entry: sdklibSyscalls) {
			if ((entry.getKey() & 0xff0000) != 0x10000) {
				printf("Warning: sdklib syscall 0x%06x (%s) has invalid prefix.\n", entry.getKey(), entry.getValue());
			}
			final Address syscallFunction = as.getAddress(this.getInt(sdklibTable.add(4 * (entry.getKey() & 0xffff))) & 0xffffffffl);
			printf("Found sdklib syscall %s at %s\n", entry.getValue(), syscallFunction.toString());
			createFunction(syscallFunction, entry.getValue());
		}
		for (Entry<Integer, String> entry: krnllibSyscalls) {
			if ((entry.getKey() & 0xff0000) != 0x20000) {
				printf("Warning: krnllib syscall 0x%06x (%s) has invalid prefix.\n", entry.getKey(), entry.getValue());
			}
			final Address syscallFunction = as.getAddress(this.getInt(krnllibTable.add(4 * (entry.getKey() & 0xffff))) & 0xffffffffl);
			printf("Found krnllib syscall %s at %s\n", entry.getValue(), syscallFunction.toString());
			createFunction(syscallFunction, entry.getValue());
		}
	}

	private List<Entry<Integer, String>> generateSyscallTableFrom(final File dllFile)
			throws FileNotFoundException, IOException {
		final FSRL fsrl = fs.getLocalFSRL(dllFile);
		printf("Processing DLL %s...\n", fsrl.toPrettyString());

		final LinkedList<Entry<Integer, String>> result = new LinkedList<>();
		final FileByteProvider bp = new FileByteProvider(dllFile, fsrl, AccessMode.READ);
		final PortableExecutable peFile = new PortableExecutable(bp, SectionLayout.FILE);
		final DataDirectory[] dirs = peFile.getNTHeader().getOptionalHeader().getDataDirectories();
		if (dirs.length <= OptionalHeader.IMAGE_DIRECTORY_ENTRY_EXPORT) {
			printf("Warning: DLL %s has no export table.\n", fsrl.toPrettyString());
			return result;
		}
		final ExportDataDirectory exports = (ExportDataDirectory) dirs[OptionalHeader.IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!exports.hasParsedCorrectly()) {
			printf("Warning: DLL %s has malformed export table.\n", fsrl.toPrettyString());
			return result;
		}
		final BinaryReader reader = new BinaryReader(bp, true);
		for (ExportInfo exp : exports.getExports()) {
			final long svcOffset = peFile.getNTHeader().vaToPointer(exp.getAddress()) + 8;
			final long svcInst = reader.readUnsignedInt(svcOffset);
			if ((svcInst & 0xff000000l) != 0xef000000l) {
				printf("Warning: Function %s does not seem to be a syscall shim.\n", exp.getName());
				continue;
			}
			result.add(Map.entry((int) (svcInst & 0xffffffl), exp.getName()));
		}
		return result;
	}
}

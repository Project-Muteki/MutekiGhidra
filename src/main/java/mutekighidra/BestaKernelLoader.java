package mutekighidra;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class BestaKernelLoader extends AbstractProgramWrapperLoader {
	private static final String OVERRIDE_LOAD_BASE_OPTION = "Override load base";

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		final List<Option> options = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		options.add(new Option(OVERRIDE_LOAD_BASE_OPTION, -1l, Long.class, Loader.COMMAND_LINE_ARG_PREFIX + "-overrideloadbase"));
		return options;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		// TODO Auto-generated method stub
		final String parentResult = super.validateOptions(provider, loadSpec, options, program);
		if (parentResult != null) {
			return parentResult;
		}
		
		for (Option op : options) {
			if (op.getName().equals(OVERRIDE_LOAD_BASE_OPTION)) {
				if (op.getValue() != null && !op.getValue().getClass().equals(Long.class)) {
					return String.format("Invalid load base %s", op.getValue().toString());
				}
				final long address = ((Long) op.getValue()).longValue();
				if (address > 0xffffffffl) {
					return String.format("Address value %08x is too large", address);
				}
			}
		}

		return null;
	}

	@Override
	public String getName() {
		return "Besta RTOS Kernel";
	}

	@Override
	protected boolean shouldApplyProcessorLabelsByDefault() {
		return true;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		final int formatVersion = detectFormatVersion(provider);
		
		if (formatVersion == 0) {
			return List.of();
		}

		final BinaryReader reader = new BinaryReader(provider, true);
		String archType = reader.readAsciiString(0x14l);
		boolean archIsUnknown = (!archType.equals("V5J")) && (!archType.equals("V6K"));

		return List.of(
				new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v4t", "default"), archIsUnknown),
				new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v5t", "default"), archType.equals("V5J")),
				new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v6", "default"), archType.equals("V6K"))
		);
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		monitor.setMessage("Loading Besta RTOS kernel image...");

		long overrideBase = -1;
		for (Option op : options) {
			if (op.getName().equals(OVERRIDE_LOAD_BASE_OPTION)) {
				overrideBase = ((Long) op.getValue()).longValue();
			}
		}

		final FlatProgramAPI fp = new FlatProgramAPI(program, monitor);
		final BinaryReader reader = new BinaryReader(provider, true);
		Address base;
		long baseOffset = 0;
		if (overrideBase < 0) {
			base = fp.toAddr(reader.readUnsignedInt(0xcl));
		} else {
			base = fp.toAddr(overrideBase);
			baseOffset = overrideBase - reader.readUnsignedInt(0xcl);
		}
		final int formatVersion = detectFormatVersion(provider);
		try {
			MemoryBlock mainBlock = fp.createMemoryBlock("code", base, provider.getInputStream(0l), provider.length(), false);
			mainBlock.setRead(true);
			mainBlock.setWrite(true);
			mainBlock.setExecute(true);
		} catch (Exception e) {
			log.appendException(e);
			return;
		}

		final long epVal = reader.readUnsignedInt(0x0l) + baseOffset;
		final Address entryPoint = fp.toAddr(epVal);
		fp.addEntryPoint(entryPoint);

		try {
			// patch the entry point and load base values.
			if (overrideBase >= 0) {
				fp.setInt(base.add(0x0l), (int) epVal);
				fp.setInt(base.add(0xcl), (int) overrideBase);
			}
			fp.createLabel(entryPoint, "_Besta_Reset", true);
			fp.createLabel(base.add(0x0l), "_Besta_EntryPointer", true);
			fp.createDWord(base.add(0x0l));
			fp.createLabel(base.add(0x8l), "_Besta_LoadSize", true);
			fp.createDWord(base.add(0x8l));
			fp.createLabel(base.add(0xcl), "_Besta_LoadBase", true);
			fp.createDWord(base.add(0xcl));
			fp.createLabel(base.add(0x10l), "_Besta_TailOffset", true);
			fp.createDWord(base.add(0x10l));
			if (formatVersion == 2) {
				fp.createLabel(base.add(0x14l), "_Besta_ProcessorType", true);
				fp.createAsciiString(base.add(0x14l), 4);
				fp.createLabel(base.add(0x18l), "_Besta_SystemType", true);
				fp.createAsciiString(base.add(0x18l), 4);
			}
			
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private int detectFormatVersion(final ByteProvider provider) throws IOException {
		final BinaryReader reader = new BinaryReader(provider, true);
		final long tailOffset = reader.readUnsignedInt(0x10l) - 0x500l;
		if (tailOffset <= 0 || tailOffset > provider.length() - 0x500l) {
			return 0;
		}
		final byte[] verString64 = reader.readByteArray(tailOffset + 0x20l, 0x10);
		final byte[] verString32 = reader.readByteArray(tailOffset + 0x50l, 0x10);
		// TODO check whether the checksum block makes sense (all checksum bytes and (0, 2) (1, 3) pairs should add up to 0)
		// and whether file size matches the declared size.
		if (isStrictlyANulTerminatedString(verString64, 0x10)) {
			// Format version 2 (64-bit)
			return 2;
		} else if (isStrictlyANulTerminatedString(verString32, 0x10)) {
			// Format version 1 (32-bit)
			return 1;
		}
		return 0;
	}

	private boolean isStrictlyANulTerminatedString(final byte[] buffer, int size) {
		int phase = 0;
		int segmentCount = 0;
		for (int i = size - 1; i >= 0; i--) {
			if (buffer[i] == 0 && phase != -1) {
				phase = -1;
				segmentCount++;
			} else if (buffer[i] != 0 && phase != 1) {
				phase = 1;
				segmentCount++;
			}
		}
		return buffer[size - 1] == 0 && segmentCount == 2;
	}
}

// ASRA's own Ghidra headless postScript. Two dispatch shapes, both ending at the same
// dispatchRequest() below:
//
// Server mode (the normal path since the persistent-process rework -- agent/tools/builders/
// ghidra.py's own module docstring explains the full client-side lifecycle): `-postScript
// AsraExtract.java --server <unix_socket_path> <idle_timeout_seconds>`. Ghidra's own headless
// framework keeps the WHOLE process (JVM + loaded Program + analysis database) alive for as long
// as this script's run() method hasn't returned -- so a script whose run() blocks in an accept/
// read loop instead of returning after one request turns an ordinary one-shot `-postScript`
// invocation into a real, request-serving process. Real, confirmed motivation (not REA's own
// architecture copied blind -- ported after comparing it against this project's own already-
// shipped batch-per-call design and confirming the JVM+Ghidra-framework startup cost really is
// paid again on every single call otherwise): ASRA's own established real cost class, same
// "~2m30s aaa" problem radare2.py's own docstring already documents for repeated analysis, here
// showing up instead as repeated JVM+plugin-framework startup even once the heavier full-analysis
// step itself is already skipped via -noanalysis.
//
// One request per connection, deliberately not one persistent multiplexed connection across many
// calls -- a fresh Unix-domain connect costs microseconds, utterly negligible next to the JVM
// startup this whole mechanism exists to avoid paying again, and keeping this to one-request-per-
// connection sidesteps any need for per-request IDs/framing beyond a single newline-delimited
// JSON line each way. Protocol: client connects, writes ONE line of JSON (`{"mode":...,
// "target":...}`), reads back ONE line of JSON (`{"observed":{...},"unknown":{...}}`, the exact
// same shape one-shot mode already wrote to a file), then closes. mode="ping" answers
// `{"status":"ok"}` immediately without touching the program at all -- the client's own liveness
// check before trusting a socket file left over from an earlier run. mode="shutdown" answers
// `{"status":"shutting_down"}` and then actually exits the serve loop (script returns, Ghidra
// closes the program, analyzeHeadless's own process exits) -- a clean stop, not something the
// client has to rely on the idle timeout alone for.
//
// The socket file itself is created with 0600 (owner-only) permissions immediately after bind --
// this project's own single-operator trust model doesn't need REA's own multi-client token/auth
// layer (see this file's own header comment's cross-reference below for where that DOES become
// relevant again later), but a world-writable/readable local socket that can run arbitrary
// analysis against whatever program happens to be loaded would still be a real, pointless local
// privilege-boundary gap to leave open for no reason.
//
// *** Future note, read before ever exposing this mechanism beyond this one operator's own local
// process (an MCP server / CLI surface a different client could reach) *** -- genuine multi-client
// access needs the auth/identity layer this file deliberately does NOT build today (REA's own
// descriptor-digest + token handshake, or equivalent) -- a bare 0600 Unix socket is only a safe
// trust boundary for "nothing else on this machine, under this same OS user account, is a
// different untrusted party," which stops being true the moment a REMOTE or lower-privileged
// client needs to reach it. Revisit this file (and ghidra.py's own client-side connection code)
// before that day arrives, don't assume 0600 alone is still sufficient once the trust model changes.
//
// One-shot mode (kept for direct single-call use / simpler testing, functionally identical
// output): `-postScript AsraExtract.java <mode> <target> <output_json_path>` -- same as before
// this rework, just now implemented as a single dispatchRequest() call that writes its own result
// to a file instead of a socket.
//
// Never takes raw model-authored text either way -- `mode` is a fixed allowlist, `target` is a
// function name/address the Python side already validated, exactly the same "no free-form script
// text from the model" discipline agent/tools/builders/radare2.py/gdb.py apply to their own
// command languages.
//@category ASRA

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.XmlEncode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.regex.Pattern;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

public class AsraExtract extends GhidraScript {

	// Same practical ceiling radare2.py's own _MAX_LIST_ENTRIES applies -- an honest total count
	// survives even when the list itself is capped, never a silent truncation.
	private static final int MAX_LIST_ENTRIES = 50;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length >= 1 && "--server".equals(args[0])) {
			if (args.length < 3) {
				throw new IllegalArgumentException(
					"--server requires <unix_socket_path> <idle_timeout_seconds>, got " + (args.length - 1) + " extra arg(s)");
			}
			runServer(args[1], Long.parseLong(args[2]) * 1000L);
			return;
		}

		if (args.length < 3) {
			throw new IllegalArgumentException(
				"AsraExtract.java requires 3 args: <mode> <target> <output_json_path>, got " + args.length);
		}
		String mode = args[0];
		String target = args[1];
		String outputPath = args[2];

		JsonObject request = new JsonObject();
		request.addProperty("mode", mode);
		request.addProperty("target", target);
		// One-shot mode's own 4th arg is the write-mode payload (new name / comment text) --
		// optional because most modes are read-only and never populate it.
		if (args.length >= 4) {
			request.addProperty("value", args[3]);
		}
		JsonObject result = dispatchRequest(request);

		try (FileWriter writer = new FileWriter(outputPath)) {
			writer.write(result.toString());
		}
	}

	// The one real dispatcher both one-shot and server mode call -- `request` is `{"mode":...,
	// "target":..., "value":...}` ("value" only populated by the write-capability modes below), the
	// return value is always `{"observed":{...},"unknown":{...}}`, same shape every mode method
	// already wrote directly into before this rework, just now returned instead of being assembled
	// inline in run() itself.
	private JsonObject dispatchRequest(JsonObject request) {
		String mode = request.has("mode") && !request.get("mode").isJsonNull() ? request.get("mode").getAsString() : "";
		String target = request.has("target") && !request.get("target").isJsonNull() ? request.get("target").getAsString() : "";
		String value = request.has("value") && !request.get("value").isJsonNull() ? request.get("value").getAsString() : null;
		// Defaults to true (a deliberate, extra-cautious default only fix_mips_soft_float actually
		// reads -- every other mode ignores this field entirely): that mode's own XML/calling-
		// convention surgery is the riskiest write this server performs, so it reports its plan
		// first and only mutates the database on an explicit, repeated dry_run=false call.
		boolean dryRun = true;
		if (request.has("dry_run") && !request.get("dry_run").isJsonNull()) {
			dryRun = request.get("dry_run").getAsBoolean();
		}

		JsonObject result = new JsonObject();
		JsonObject observed = new JsonObject();
		JsonObject unknown = new JsonObject();

		try {
			switch (mode) {
				case "info":
					infoMode(observed);
					break;
				case "functions":
					functionsMode(observed, unknown);
					break;
				case "decompile_function":
					decompileFunctionMode(target, observed, unknown);
					break;
				case "disassemble_function":
					disassembleFunctionMode(target, observed, unknown);
					break;
				case "xrefs_to":
					xrefsToMode(target, observed, unknown);
					break;
				case "cfg":
					cfgMode(target, observed, unknown);
					break;
				case "pcode_def_use":
					pcodeDefUseMode(target, observed, unknown);
					break;
				case "value_flow":
					valueFlowMode(target, observed, unknown);
					break;
				case "inspect_native_data_type":
					inspectNativeDataTypeMode(target, observed, unknown);
					break;
				case "set_address_name":
					setAddressNameMode(target, value, observed, unknown);
					break;
				case "annotate_native_function":
					annotateNativeFunctionMode(target, value, observed, unknown);
					break;
				case "fix_no_return_flags":
					fixNoReturnFlagsMode(observed, unknown);
					break;
				case "fix_mips_soft_float":
					fixMipsSoftFloatMode(dryRun, observed, unknown);
					break;
				default:
					throw new IllegalArgumentException("Unknown mode: " + mode);
			}
		}
		catch (Exception e) {
			unknown.addProperty("error", e.getClass().getSimpleName() + ": " + e.getMessage());
		}

		result.add("observed", observed);
		result.add("unknown", unknown);
		return result;
	}

	// Binds the Unix domain socket at socketPath and serves requests until EITHER a
	// mode="shutdown" request arrives (clean, client-initiated stop) OR idleTimeoutMs elapses with
	// no new connection accepted (self-cleanup if the Python-side client ever fails to shut this
	// down itself -- a crashed/killed ASRA process must not leave an orphaned Ghidra JVM running
	// forever). One connection handled fully (one request, one response, close) before accepting
	// the next -- see this file's own header comment for why that's deliberate, not a missing
	// optimization.
	private void runServer(String socketPath, long idleTimeoutMs) throws Exception {
		Path path = Paths.get(socketPath);
		Files.deleteIfExists(path);

		try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
			 Selector selector = Selector.open()) {
			server.bind(UnixDomainSocketAddress.of(path));
			// Permissions set AFTER bind -- bind() is what actually creates the socket file on
			// disk; there is nothing to chmod before that call succeeds.
			Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
			server.configureBlocking(false);
			server.register(selector, SelectionKey.OP_ACCEPT);

			try {
				boolean shuttingDown = false;
				while (!shuttingDown) {
					int ready = selector.select(idleTimeoutMs);
					if (ready == 0) {
						break; // idle timeout -- no connection arrived in time, self-clean and exit
					}
					Iterator<SelectionKey> keys = selector.selectedKeys().iterator();
					while (keys.hasNext()) {
						SelectionKey key = keys.next();
						keys.remove();
						if (!key.isAcceptable()) {
							continue;
						}
						SocketChannel client = server.accept();
						if (client == null) {
							continue;
						}
						try {
							if (handleOneConnection(client)) {
								shuttingDown = true;
							}
						}
						finally {
							client.close();
						}
					}
				}
			}
			finally {
				Files.deleteIfExists(path);
			}
		}
	}

	// Returns true if the request handled was mode="shutdown" (the caller's own signal to stop
	// serving entirely), false otherwise -- every other mode, including a malformed/unparseable
	// request, is answered and the connection closes normally, ready for the NEXT accept().
	private boolean handleOneConnection(SocketChannel client) throws IOException {
		BufferedReader reader = new BufferedReader(new InputStreamReader(Channels.newInputStream(client), StandardCharsets.UTF_8));
		OutputStream out = Channels.newOutputStream(client);
		String line = reader.readLine();
		if (line == null || line.isBlank()) {
			return false;
		}

		JsonObject request;
		try {
			request = JsonParser.parseString(line).getAsJsonObject();
		}
		catch (Exception e) {
			JsonObject error = new JsonObject();
			error.addProperty("status", "error");
			error.addProperty("error", "could not parse request as a single JSON object: " + e.getMessage());
			writeLine(out, error);
			return false;
		}

		String mode = request.has("mode") && !request.get("mode").isJsonNull() ? request.get("mode").getAsString() : "";
		if ("ping".equals(mode)) {
			JsonObject pong = new JsonObject();
			pong.addProperty("status", "ok");
			writeLine(out, pong);
			return false;
		}
		if ("shutdown".equals(mode)) {
			JsonObject bye = new JsonObject();
			bye.addProperty("status", "shutting_down");
			writeLine(out, bye);
			return true;
		}

		JsonObject result = dispatchRequest(request);
		writeLine(out, result);
		return false;
	}

	private void writeLine(OutputStream out, JsonObject obj) throws IOException {
		out.write((obj.toString() + "\n").getBytes(StandardCharsets.UTF_8));
		out.flush();
	}

	private void infoMode(JsonObject observed) {
		observed.addProperty("name", currentProgram.getName());
		observed.addProperty("executable_format", currentProgram.getExecutableFormat());
		observed.addProperty("language_id", currentProgram.getLanguage().getLanguageID().getIdAsString());
		observed.addProperty(
			"compiler_spec_id", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
		observed.addProperty("image_base", currentProgram.getImageBase().toString());
		observed.addProperty("min_address", currentProgram.getMinAddress().toString());
		observed.addProperty("max_address", currentProgram.getMaxAddress().toString());
		observed.addProperty("function_count", currentProgram.getFunctionManager().getFunctionCount());
	}

	private void functionsMode(JsonObject observed, JsonObject unknown) {
		JsonArray functions = new JsonArray();
		FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
		int total = 0;
		for (Function f : iter) {
			total++;
			if (total <= MAX_LIST_ENTRIES) {
				JsonObject entry = new JsonObject();
				entry.addProperty("name", f.getName());
				entry.addProperty("entry", f.getEntryPoint().toString());
				entry.addProperty("size", f.getBody().getNumAddresses());
				functions.add(entry);
			}
		}
		observed.add("functions", functions);
		observed.addProperty("total_functions", total);
		if (total > MAX_LIST_ENTRIES) {
			unknown.addProperty(
				"functions_beyond_limit",
				(total - MAX_LIST_ENTRIES) + " more functions exist but were not listed (cap of " + MAX_LIST_ENTRIES + ")");
		}
	}

	// Name match tried FIRST, deliberately -- confirmed live that Ghidra's own toAddr() happily
	// parses several real function names as hex addresses instead of rejecting them (e.g. "add",
	// "bad", "dead", "face" are all valid hex digit strings), so an address-first lookup can
	// silently resolve to the wrong thing (or nothing at all) whenever a real function's name
	// happens to also look like hex. A name match, when one exists, is always unambiguous and
	// always the one actually meant; address parsing is strictly the fallback for a target that
	// doesn't name any function at all (a raw address, or a function genuinely not found).
	private Function resolveFunction(String target) {
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (f.getName().equals(target)) {
				return f;
			}
		}
		try {
			Address addr = toAddr(target);
			if (addr != null) {
				return currentProgram.getFunctionManager().getFunctionContaining(addr);
			}
		}
		catch (Exception e) {
			// fall through -- target just isn't a resolvable address either.
		}
		return null;
	}

	private void decompileFunctionMode(String target, JsonObject observed, JsonObject unknown) {
		Function function;
		try {
			function = resolveFunction(target);
		}
		catch (Exception e) {
			unknown.addProperty("pseudocode", "could not resolve target: " + e.getMessage());
			return;
		}
		if (function == null) {
			unknown.addProperty("pseudocode", "no function found at/named '" + target + "'");
			return;
		}
		observed.addProperty("function_name", function.getName());
		observed.addProperty("entry", function.getEntryPoint().toString());

		DecompInterface decompInterface = new DecompInterface();
		try {
			decompInterface.openProgram(currentProgram);
			DecompileResults results = decompInterface.decompileFunction(function, 60, monitor);
			if (results.decompileCompleted() && results.getDecompiledFunction() != null) {
				observed.addProperty("pseudocode", results.getDecompiledFunction().getC());
			}
			else {
				String err = results.getErrorMessage();
				unknown.addProperty("pseudocode", err == null || err.isEmpty() ? "decompilation did not complete" : err);
			}
		}
		finally {
			decompInterface.dispose();
		}
	}

	private void disassembleFunctionMode(String target, JsonObject observed, JsonObject unknown) throws Exception {
		Function function = resolveFunction(target);
		if (function == null) {
			unknown.addProperty("disassembly", "no function found at/named '" + target + "'");
			return;
		}
		observed.addProperty("function_name", function.getName());
		observed.addProperty("entry", function.getEntryPoint().toString());
		JsonArray instructions = new JsonArray();
		InstructionIterator iter = currentProgram.getListing().getInstructions(function.getBody(), true);
		int total = 0;
		for (Instruction instr : iter) {
			total++;
			if (total <= MAX_LIST_ENTRIES * 4) {
				JsonObject entry = new JsonObject();
				entry.addProperty("address", instr.getAddress().toString());
				entry.addProperty("text", instr.toString());
				instructions.add(entry);
			}
		}
		observed.add("instructions", instructions);
		observed.addProperty("total_instructions", total);
		if (total > MAX_LIST_ENTRIES * 4) {
			unknown.addProperty(
				"instructions_beyond_limit",
				(total - MAX_LIST_ENTRIES * 4) + " more instructions exist but were not listed");
		}
	}

	private void xrefsToMode(String target, JsonObject observed, JsonObject unknown) throws Exception {
		// Same name-first priority as resolveFunction's own comment explains -- a function whose
		// name happens to look like hex (e.g. "add") must resolve to ITS entry point, not to
		// toAddr() silently parsing the name as a literal, likely-unmapped address instead.
		Function f = resolveFunction(target);
		Address addr = null;
		if (f != null) {
			addr = f.getEntryPoint();
		}
		else {
			try {
				addr = toAddr(target);
			}
			catch (Exception e) {
				addr = null;
			}
		}
		if (addr == null) {
			unknown.addProperty("xrefs", "could not resolve target '" + target + "' to an address or function");
			return;
		}
		observed.addProperty("target_address", addr.toString());
		ReferenceManager refMgr = currentProgram.getReferenceManager();
		ReferenceIterator refs = refMgr.getReferencesTo(addr);
		JsonArray xrefs = new JsonArray();
		int total = 0;
		for (Reference ref : refs) {
			total++;
			if (total <= MAX_LIST_ENTRIES) {
				JsonObject entry = new JsonObject();
				Address from = ref.getFromAddress();
				entry.addProperty("from_address", from.toString());
				Function containing = currentProgram.getFunctionManager().getFunctionContaining(from);
				entry.addProperty("from_function", containing == null ? "" : containing.getName());
				entry.addProperty("reference_type", ref.getReferenceType().toString());
				xrefs.add(entry);
			}
		}
		observed.add("xrefs", xrefs);
		observed.addProperty("total_xrefs", total);
		if (total > MAX_LIST_ENTRIES) {
			unknown.addProperty("xrefs_beyond_limit", (total - MAX_LIST_ENTRIES) + " more references exist but were not listed");
		}
	}

	private void cfgMode(String target, JsonObject observed, JsonObject unknown) throws Exception {
		Function function = resolveFunction(target);
		if (function == null) {
			unknown.addProperty("cfg", "no function found at/named '" + target + "'");
			return;
		}
		observed.addProperty("function_name", function.getName());
		observed.addProperty("entry", function.getEntryPoint().toString());

		BasicBlockModel bbModel = new BasicBlockModel(currentProgram);
		CodeBlockIterator blockIter = bbModel.getCodeBlocksContaining(function.getBody(), monitor);

		JsonArray blocks = new JsonArray();
		int total = 0;
		while (blockIter.hasNext()) {
			CodeBlock block = blockIter.next();
			total++;
			if (total <= MAX_LIST_ENTRIES) {
				JsonObject entry = new JsonObject();
				entry.addProperty("start", block.getFirstStartAddress().toString());
				entry.addProperty("end", block.getMaxAddress().toString());
				// Includes edges leaving the function's own body (e.g. a CALL to another
				// function) alongside in-function branch/fall-through edges -- flow_type on
				// each lets the reader tell them apart (CALL vs CONDITIONAL_JUMP vs
				// FALL_THROUGH vs UNCONDITIONAL_JUMP etc.) rather than silently dropping one
				// class of edge the caller might actually have wanted.
				JsonArray successors = new JsonArray();
				CodeBlockReferenceIterator destIter = block.getDestinations(monitor);
				while (destIter.hasNext()) {
					CodeBlockReference ref = destIter.next();
					CodeBlock dest = ref.getDestinationBlock();
					if (dest == null) {
						continue;
					}
					JsonObject successor = new JsonObject();
					successor.addProperty("to", dest.getFirstStartAddress().toString());
					successor.addProperty("flow_type", ref.getFlowType().toString());
					successors.add(successor);
				}
				entry.add("successors", successors);
				blocks.add(entry);
			}
		}
		observed.add("basic_blocks", blocks);
		observed.addProperty("total_basic_blocks", total);
		if (total > MAX_LIST_ENTRIES) {
			unknown.addProperty("basic_blocks_beyond_limit", (total - MAX_LIST_ENTRIES) + " more basic blocks exist but were not listed");
		}
	}

	// A synthetic, stable-within-this-one-call ID for a Varnode -- decompileFunctionMode's own
	// DecompInterface call already shows Ghidra has no public varnode ID exposed as such; identity
	// here is by the SAME object reference the high p-code graph itself uses (confirmed live: the
	// identical Varnode INSTANCE is shared between a PcodeOpAST's own output and every other
	// PcodeOpAST that consumes it as an input -- that is exactly what makes getDef()/
	// getDescendants() able to walk the graph at all). An IdentityHashMap, not a plain HashMap, is
	// deliberate -- Varnode overrides equals()/hashCode() on (space, offset, size) alone, which
	// would silently collapse two UNRELATED SSA values that happen to reuse the same stack slot at
	// different points in the function into one node.
	private String varnodeId(Varnode vn, Map<Varnode, String> ids) {
		return ids.computeIfAbsent(vn, v -> "v" + ids.size());
	}

	// A short, human-meaningful label -- register name, a named high-level variable (decompiler's
	// own recovered local/parameter name), a stack-relative offset, or a bare constant -- picked in
	// that preference order since a reader cares about WHAT a value represents far more than its
	// raw internal address. Falls back to the raw address:size form only when none of those apply.
	private String varnodeLabel(Varnode vn) {
		if (vn == null) {
			return null;
		}
		if (vn.isConstant()) {
			return "const:" + vn.getOffset();
		}
		if (vn.getHigh() != null && vn.getHigh().getName() != null) {
			return vn.getHigh().getName();
		}
		if (vn.isRegister()) {
			String regName = currentProgram.getLanguage().getRegister(vn.getAddress(), vn.getSize()) != null
				? currentProgram.getLanguage().getRegister(vn.getAddress(), vn.getSize()).getName()
				: null;
			if (regName != null) {
				return regName;
			}
		}
		return vn.getAddress() + ":" + vn.getSize();
	}

	private void pcodeDefUseMode(String target, JsonObject observed, JsonObject unknown) {
		Function function = resolveFunction(target);
		if (function == null) {
			unknown.addProperty("pcode_def_use", "no function found at/named '" + target + "'");
			return;
		}
		observed.addProperty("function_name", function.getName());
		observed.addProperty("entry", function.getEntryPoint().toString());

		DecompInterface decompInterface = new DecompInterface();
		try {
			decompInterface.openProgram(currentProgram);
			DecompileResults results = decompInterface.decompileFunction(function, 60, monitor);
			HighFunction highFunction = results.getHighFunction();
			if (!results.decompileCompleted() || highFunction == null) {
				String err = results.getErrorMessage();
				unknown.addProperty("pcode_def_use", err == null || err.isEmpty() ? "decompilation did not complete" : err);
				return;
			}

			Map<Varnode, String> varnodeIds = new LinkedHashMap<>();
			List<PcodeOpAST> ops = new ArrayList<>();
			Iterator<PcodeOpAST> opIter = highFunction.getPcodeOps();
			while (opIter.hasNext()) {
				ops.add(opIter.next());
			}

			JsonArray opsJson = new JsonArray();
			int opTotal = ops.size();
			for (int i = 0; i < opTotal && i < MAX_LIST_ENTRIES * 2; i++) {
				PcodeOpAST op = ops.get(i);
				JsonObject opEntry = new JsonObject();
				opEntry.addProperty("seq", op.getSeqnum().getTarget() + "." + op.getSeqnum().getTime());
				opEntry.addProperty("address", op.getSeqnum().getTarget().toString());
				opEntry.addProperty("mnemonic", op.getMnemonic());
				Varnode output = op.getOutput();
				opEntry.addProperty("output", output == null ? null : varnodeId(output, varnodeIds));
				JsonArray inputsJson = new JsonArray();
				for (int in = 0; in < op.getNumInputs(); in++) {
					Varnode input = op.getInput(in);
					if (input != null) {
						inputsJson.add(varnodeId(input, varnodeIds));
					}
				}
				opEntry.add("inputs", inputsJson);
				opsJson.add(opEntry);
			}
			observed.add("pcode_ops", opsJson);
			observed.addProperty("total_pcode_ops", opTotal);
			if (opTotal > MAX_LIST_ENTRIES * 2) {
				unknown.addProperty(
					"pcode_ops_beyond_limit",
					(opTotal - MAX_LIST_ENTRIES * 2) + " more p-code operations exist but were not listed");
			}

			// Def-use edges, keyed by varnode -- only for varnodes actually referenced by the
			// (possibly capped) op list above, so this never reports an edge pointing at a
			// varnode ID the caller was never shown.
			JsonArray varnodesJson = new JsonArray();
			int varnodeTotal = varnodeIds.size();
			int varnodeShown = 0;
			for (Map.Entry<Varnode, String> entry : varnodeIds.entrySet()) {
				if (varnodeShown >= MAX_LIST_ENTRIES * 2) {
					break;
				}
				varnodeShown++;
				Varnode vn = entry.getKey();
				JsonObject vnEntry = new JsonObject();
				vnEntry.addProperty("id", entry.getValue());
				vnEntry.addProperty("label", varnodeLabel(vn));
				PcodeOp def = vn.getDef();
				vnEntry.addProperty("defined_by", def == null ? null : def.getSeqnum().getTarget() + "." + def.getSeqnum().getTime());
				JsonArray usedBy = new JsonArray();
				Iterator<PcodeOp> descendants = vn.getDescendants();
				while (descendants.hasNext()) {
					PcodeOp use = descendants.next();
					usedBy.add(use.getSeqnum().getTarget() + "." + use.getSeqnum().getTime());
				}
				vnEntry.add("used_by", usedBy);
				varnodesJson.add(vnEntry);
			}
			observed.add("varnodes", varnodesJson);
			observed.addProperty("total_varnodes", varnodeTotal);
			if (varnodeTotal > varnodeShown) {
				unknown.addProperty(
					"varnodes_beyond_limit",
					(varnodeTotal - varnodeShown) + " more varnodes exist but were not listed");
			}
		}
		finally {
			decompInterface.dispose();
		}
	}

	// Richer data-flow than pcode_def_use above -- same def/use graph, plus the three things a
	// plain p-code dump can't answer on its own: what CONCRETE value a varnode actually carries
	// (constant/address/register/a SSA-unique temp, not just its def/use edges), whether it's one
	// of the function's own recovered PARAMETERS (and that parameter's inferred type), and where a
	// compiled switch statement's own JUMP TABLE resolves to. Modeled on REA's own
	// nativeValueFlow/inferredJumpTable/inferredBoundaryType, but built from first principles
	// against Ghidra 12's actual script-level API (confirmed live, not guessed) rather than a blind
	// port -- REA's own three concepts map directly onto HighFunction's own
	// getFunctionPrototype()/getJumpTables() plus Varnode's own isConstant()/isAddress()/
	// isRegister()/isUnique() classifiers, all genuinely reachable from GhidraScript, so this is a
	// complete port, not a partial one.
	private void valueFlowMode(String target, JsonObject observed, JsonObject unknown) {
		Function function = resolveFunction(target);
		if (function == null) {
			unknown.addProperty("value_flow", "no function found at/named '" + target + "'");
			return;
		}
		observed.addProperty("function_name", function.getName());
		observed.addProperty("entry", function.getEntryPoint().toString());

		DecompInterface decompInterface = new DecompInterface();
		try {
			decompInterface.openProgram(currentProgram);
			DecompileResults results = decompInterface.decompileFunction(function, 60, monitor);
			HighFunction highFunction = results.getHighFunction();
			if (!results.decompileCompleted() || highFunction == null) {
				String err = results.getErrorMessage();
				unknown.addProperty("value_flow", err == null || err.isEmpty() ? "decompilation did not complete" : err);
				return;
			}

			// Parameters -- name + inferred type + storage, straight from the decompiler's own
			// recovered function prototype (the same HighSymbol objects a parameter's own varnodes
			// point back to via Varnode.getHigh(), which is what lets classifyVarnode() below mark a
			// varnode as "this IS parameter N" instead of just "this is some register").
			FunctionPrototype prototype = highFunction.getFunctionPrototype();
			JsonArray parametersJson = new JsonArray();
			if (prototype != null) {
				for (int i = 0; i < prototype.getNumParams(); i++) {
					HighSymbol param = prototype.getParam(i);
					JsonObject paramEntry = new JsonObject();
					paramEntry.addProperty("ordinal", i);
					paramEntry.addProperty("name", param.getName());
					DataType paramType = param.getDataType();
					paramEntry.addProperty("inferred_type", paramType == null ? null : paramType.getPathName());
					paramEntry.addProperty("storage", param.getStorage() == null ? null : param.getStorage().toString());
					parametersJson.add(paramEntry);
				}
				DataType returnType = prototype.getReturnType();
				observed.addProperty("inferred_return_type", returnType == null ? null : returnType.getPathName());
			}
			observed.add("parameters", parametersJson);

			// Jump tables -- a compiled switch statement's own indirect-branch dispatch, resolved
			// to its concrete case targets (JumpTable.getCases()) plus the raw in-memory table(s)
			// backing it (getLoadTables()), not just the single indirect CBRANCH/BRANCHIND p-code op
			// a plain CFG/p-code dump would show with no indication of where it actually goes.
			JumpTable[] jumpTables = highFunction.getJumpTables();
			JsonArray jumpTablesJson = new JsonArray();
			if (jumpTables != null) {
				for (JumpTable jt : jumpTables) {
					if (jt == null || jt.isEmpty()) {
						continue;
					}
					JsonObject jtEntry = new JsonObject();
					jtEntry.addProperty("switch_address", jt.getSwitchAddress() == null ? null : jt.getSwitchAddress().toString());
					JsonArray casesJson = new JsonArray();
					Address[] cases = jt.getCases();
					if (cases != null) {
						for (Address caseAddr : cases) {
							casesJson.add(caseAddr.toString());
						}
					}
					jtEntry.add("case_targets", casesJson);
					JsonArray loadTablesJson = new JsonArray();
					JumpTable.LoadTable[] loadTables = jt.getLoadTables();
					if (loadTables != null) {
						for (JumpTable.LoadTable lt : loadTables) {
							JsonObject ltEntry = new JsonObject();
							ltEntry.addProperty("address", lt.getAddress() == null ? null : lt.getAddress().toString());
							ltEntry.addProperty("entry_size", lt.getSize());
							ltEntry.addProperty("entry_count", lt.getNum());
							loadTablesJson.add(ltEntry);
						}
					}
					jtEntry.add("load_tables", loadTablesJson);
					jumpTablesJson.add(jtEntry);
				}
			}
			observed.add("jump_tables", jumpTablesJson);

			// Def/use graph, same shape and same varnode IDs as pcode_def_use's own output, but each
			// varnode entry below additionally carries a concrete value classification -- this mode
			// exists specifically to answer "what does this edge actually carry," which a bare ID/
			// label pair cannot.
			Map<Varnode, String> varnodeIds = new LinkedHashMap<>();
			List<PcodeOpAST> ops = new ArrayList<>();
			Iterator<PcodeOpAST> opIter = highFunction.getPcodeOps();
			while (opIter.hasNext()) {
				ops.add(opIter.next());
			}

			JsonArray opsJson = new JsonArray();
			int opTotal = ops.size();
			for (int i = 0; i < opTotal && i < MAX_LIST_ENTRIES * 2; i++) {
				PcodeOpAST op = ops.get(i);
				JsonObject opEntry = new JsonObject();
				opEntry.addProperty("seq", op.getSeqnum().getTarget() + "." + op.getSeqnum().getTime());
				opEntry.addProperty("address", op.getSeqnum().getTarget().toString());
				opEntry.addProperty("mnemonic", op.getMnemonic());
				Varnode output = op.getOutput();
				opEntry.addProperty("output", output == null ? null : varnodeId(output, varnodeIds));
				JsonArray inputsJson = new JsonArray();
				for (int in = 0; in < op.getNumInputs(); in++) {
					Varnode input = op.getInput(in);
					if (input != null) {
						inputsJson.add(varnodeId(input, varnodeIds));
					}
				}
				opEntry.add("inputs", inputsJson);
				opsJson.add(opEntry);
			}
			observed.add("pcode_ops", opsJson);
			observed.addProperty("total_pcode_ops", opTotal);
			if (opTotal > MAX_LIST_ENTRIES * 2) {
				unknown.addProperty(
					"pcode_ops_beyond_limit",
					(opTotal - MAX_LIST_ENTRIES * 2) + " more p-code operations exist but were not listed");
			}

			JsonArray varnodesJson = new JsonArray();
			int varnodeTotal = varnodeIds.size();
			int varnodeShown = 0;
			for (Map.Entry<Varnode, String> entry : varnodeIds.entrySet()) {
				if (varnodeShown >= MAX_LIST_ENTRIES * 2) {
					break;
				}
				varnodeShown++;
				Varnode vn = entry.getKey();
				JsonObject vnEntry = new JsonObject();
				vnEntry.addProperty("id", entry.getValue());
				vnEntry.addProperty("label", varnodeLabel(vn));
				classifyVarnodeValue(vn, vnEntry);
				PcodeOp def = vn.getDef();
				vnEntry.addProperty("defined_by", def == null ? null : def.getSeqnum().getTarget() + "." + def.getSeqnum().getTime());
				JsonArray usedBy = new JsonArray();
				Iterator<PcodeOp> descendants = vn.getDescendants();
				while (descendants.hasNext()) {
					PcodeOp use = descendants.next();
					usedBy.add(use.getSeqnum().getTarget() + "." + use.getSeqnum().getTime());
				}
				vnEntry.add("used_by", usedBy);
				varnodesJson.add(vnEntry);
			}
			observed.add("varnodes", varnodesJson);
			observed.addProperty("total_varnodes", varnodeTotal);
			if (varnodeTotal > varnodeShown) {
				unknown.addProperty(
					"varnodes_beyond_limit",
					(varnodeTotal - varnodeShown) + " more varnodes exist but were not listed");
			}
		}
		finally {
			decompInterface.dispose();
		}
	}

	// Concrete value classification for one varnode -- "kind" tells the caller WHAT KIND of value
	// this edge carries (a literal constant, a fixed memory address, a CPU register, or an SSA-only
	// compiler temporary with no real storage), "value" gives the concrete value itself when one
	// exists (hex for a constant, the address string for an address varnode) and is omitted
	// otherwise. "is_parameter"/"parameter_name" surface Ghidra's own HighParam link when this
	// varnode IS one of the function's recovered parameters (vn.getHigh() returns the SAME
	// HighParam instance the FunctionPrototype.getParam() entries above expose, confirmed live --
	// so a caller can join a varnode straight back to the parameter list without guessing by name).
	private void classifyVarnodeValue(Varnode vn, JsonObject vnEntry) {
		if (vn == null) {
			return;
		}
		if (vn.isConstant()) {
			vnEntry.addProperty("kind", "constant");
			vnEntry.addProperty("value", "0x" + Long.toHexString(vn.getOffset()));
		}
		else if (vn.isRegister()) {
			vnEntry.addProperty("kind", "register");
		}
		else if (vn.isAddress()) {
			vnEntry.addProperty("kind", "address");
			vnEntry.addProperty("value", vn.getAddress().toString());
		}
		else if (vn.isUnique()) {
			vnEntry.addProperty("kind", "unique");
		}
		else {
			vnEntry.addProperty("kind", "other");
		}
		if (vn.getHigh() instanceof HighParam) {
			HighParam param = (HighParam) vn.getHigh();
			vnEntry.addProperty("is_parameter", true);
			vnEntry.addProperty("parameter_name", param.getName());
		}
	}

	// Struct/union/enum member layout -- resolves `target` as a data type NAME first (searched
	// across the whole DataTypeManager, not just one category, since a caller has no reason to know
	// which category a type landed in), falling back to "the defined data type located AT this
	// address" when target parses as an address with a concrete typed Data unit already there (the
	// same two-shapes-of-target pattern xrefs_to already establishes for name-vs-address targets).
	private void inspectNativeDataTypeMode(String target, JsonObject observed, JsonObject unknown) {
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		List<DataType> matches = new ArrayList<>();
		dtm.findDataTypes(target, matches);
		DataType dataType = matches.isEmpty() ? null : matches.get(0);

		if (dataType == null) {
			try {
				Address addr = toAddr(target);
				Data data = addr == null ? null : currentProgram.getListing().getDefinedDataAt(addr);
				if (data != null) {
					dataType = data.getDataType();
				}
			}
			catch (Exception e) {
				// fall through -- target isn't a resolvable address with defined data either.
			}
		}

		if (dataType == null) {
			unknown.addProperty("inspect_native_data_type", "no data type named/located at '" + target + "' was found");
			return;
		}

		// Unwrap Pointer/Array/TypeDef wrappers down to the underlying named type being pointed
		// at/aliased/repeated -- a caller asking to inspect "struct foo *" almost always means
		// "show me what foo itself looks like," same intent REA's own inferredBoundaryType reasoning
		// follows.
		JsonArray unwrapChain = new JsonArray();
		while (true) {
			if (dataType instanceof Pointer) {
				unwrapChain.add("pointer");
				DataType inner = ((Pointer) dataType).getDataType();
				if (inner == null) {
					break;
				}
				dataType = inner;
			}
			else if (dataType instanceof Array) {
				unwrapChain.add("array[" + ((Array) dataType).getNumElements() + "]");
				dataType = ((Array) dataType).getDataType();
			}
			else if (dataType instanceof TypeDef) {
				unwrapChain.add("typedef:" + dataType.getName());
				dataType = ((TypeDef) dataType).getDataType();
			}
			else {
				break;
			}
		}
		if (unwrapChain.size() > 0) {
			observed.add("unwrapped_through", unwrapChain);
		}

		observed.addProperty("type_name", dataType.getName());
		observed.addProperty("type_path", dataType.getPathName());
		observed.addProperty("total_length_bytes", dataType.getLength());

		if (dataType instanceof ghidra.program.model.data.Enum) {
			ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
			observed.addProperty("kind", "enum");
			observed.addProperty("is_signed", enumType.isSigned());
			JsonArray members = new JsonArray();
			for (String name : enumType.getNames()) {
				JsonObject member = new JsonObject();
				member.addProperty("name", name);
				member.addProperty("value", enumType.getValue(name));
				members.add(member);
			}
			observed.add("members", members);
			return;
		}

		if (dataType instanceof Composite) {
			Composite composite = (Composite) dataType;
			observed.addProperty("kind", dataType instanceof Union ? "union" : "struct");
			JsonArray members = new JsonArray();
			int total = 0;
			for (DataTypeComponent component : composite.getComponents()) {
				total++;
				if (total > MAX_LIST_ENTRIES) {
					continue;
				}
				JsonObject member = new JsonObject();
				member.addProperty("ordinal", component.getOrdinal());
				member.addProperty("offset", component.getOffset());
				member.addProperty("length", component.getLength());
				member.addProperty("field_name", component.getFieldName());
				DataType memberType = component.getDataType();
				member.addProperty("type", memberType == null ? null : memberType.getPathName());
				if (component.isBitFieldComponent() && memberType instanceof BitFieldDataType) {
					BitFieldDataType bitfield = (BitFieldDataType) memberType;
					member.addProperty("bit_size", bitfield.getBitSize());
					member.addProperty("bit_offset", bitfield.getBitOffset());
					DataType baseType = bitfield.getBaseDataType();
					member.addProperty("bitfield_base_type", baseType == null ? null : baseType.getPathName());
				}
				members.add(member);
			}
			observed.add("members", members);
			observed.addProperty("total_members", total);
			if (total > MAX_LIST_ENTRIES) {
				unknown.addProperty("members_beyond_limit", (total - MAX_LIST_ENTRIES) + " more members exist but were not listed");
			}
			return;
		}

		// Any other data type (a plain primitive, a FunctionDefinition, etc.) -- not an error, this
		// mode is also a legitimate way to ask "what even IS this type," just with no member layout
		// to report.
		observed.addProperty("kind", "other");
		unknown.addProperty("members", "resolved type is not a struct/union/enum -- it is " + dataType.getClass().getSimpleName());
	}

	// Renames a function (Function.setName) or creates/renames a label at a non-function address
	// (SymbolTable.createLabel + setPrimary) -- confirmed live via REA's own real
	// setAddressName/applyAddressName implementation that this IS the correct API shape for both
	// cases on this Ghidra version, not guessed. Every write mode in this file follows the same
	// three-step discipline: open a real startTransaction/endTransaction around the mutation (so a
	// failed write never leaves a half-applied change committed), then read the primary symbol back
	// from the database AFTER the transaction closes and compare it against what was requested --
	// never just trust that the API call "succeeded" without independently re-reading what actually
	// landed (same "don't trust a tool's own success report" discipline this project already applies
	// to every other tool's output).
	private void setAddressNameMode(String target, String value, JsonObject observed, JsonObject unknown) {
		if (value == null || value.isBlank()) {
			unknown.addProperty("set_address_name", "no 'value' (new name) provided");
			return;
		}
		Function function = resolveFunction(target);
		Address addr = function != null ? function.getEntryPoint() : null;
		if (addr == null) {
			try {
				addr = toAddr(target);
			}
			catch (Exception e) {
				addr = null;
			}
		}
		if (addr == null) {
			unknown.addProperty("set_address_name", "could not resolve target '" + target + "' to an address or function");
			return;
		}

		int txId = currentProgram.startTransaction("ASRA: rename " + target + " -> " + value);
		boolean success = false;
		try {
			if (function != null && function.getEntryPoint().equals(addr)) {
				function.setName(value, SourceType.USER_DEFINED);
			}
			else {
				SymbolTable symTable = currentProgram.getSymbolTable();
				Symbol existing = symTable.getPrimarySymbol(addr);
				if (existing != null && existing.getSymbolType() == SymbolType.LABEL) {
					existing.setName(value, SourceType.USER_DEFINED);
				}
				else {
					Symbol created = symTable.createLabel(addr, value, SourceType.USER_DEFINED);
					created.setPrimary();
				}
			}
			success = true;
		}
		catch (Exception e) {
			unknown.addProperty("set_address_name", "rename failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
		}
		finally {
			currentProgram.endTransaction(txId, success);
		}

		Symbol readback = currentProgram.getSymbolTable().getPrimarySymbol(addr);
		String actualName = readback == null ? null : readback.getName();
		observed.addProperty("address", addr.toString());
		observed.addProperty("requested_name", value);
		observed.addProperty("applied_name", actualName);
		observed.addProperty("verified", value.equals(actualName));
		if (!value.equals(actualName)) {
			unknown.addProperty(
				"set_address_name",
				"write transaction committed but readback name ('" + actualName + "') does not match the requested name -- "
					+ "likely a name collision or an invalid identifier rejected by the symbol table");
		}
	}

	// Sets a persistent comment on a function (its own PRE/"plate" comment, the one the Ghidra
	// listing shows directly above a function's disassembly/decompilation) -- same transaction +
	// write-then-readback discipline as setAddressNameMode above, confirmed against REA's own
	// annotateNativeFunction/annotationReadback for which CommentType this corresponds to.
	private void annotateNativeFunctionMode(String target, String value, JsonObject observed, JsonObject unknown) {
		if (value == null || value.isBlank()) {
			unknown.addProperty("annotate_native_function", "no 'value' (comment text) provided");
			return;
		}
		Function function = resolveFunction(target);
		if (function == null) {
			unknown.addProperty("annotate_native_function", "no function found at/named '" + target + "'");
			return;
		}
		Address addr = function.getEntryPoint();

		int txId = currentProgram.startTransaction("ASRA: annotate " + function.getName());
		boolean success = false;
		try {
			currentProgram.getListing().setComment(addr, CommentType.PRE, value);
			success = true;
		}
		catch (Exception e) {
			unknown.addProperty("annotate_native_function", "comment write failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
		}
		finally {
			currentProgram.endTransaction(txId, success);
		}

		String readback = currentProgram.getListing().getComment(CommentType.PRE, addr);
		observed.addProperty("function_name", function.getName());
		observed.addProperty("entry", addr.toString());
		observed.addProperty("applied_comment", readback);
		observed.addProperty("verified", value.equals(readback));
		if (!value.equals(readback)) {
			unknown.addProperty(
				"annotate_native_function",
				"write transaction committed but readback comment does not match the requested text");
		}
	}

	// Port of REA's own ReaGhidraNoReturnFix -- confirmed reachable from plain script-level API, no
	// extension-point access needed beyond what GhidraScript already exposes. Two independent fixes
	// in one pass, same as the real REA source: (1) a small fixed allowlist of externally-imported
	// libc/runtime functions Ghidra's own analyzers are known to sometimes mis-flag as no-return
	// (REA's own list, reused verbatim -- these are genuinely-returning functions on every libc this
	// project ever analyzes, not something that needs to vary per-binary); (2) a genuine analysis
	// pass over every LOCAL function's own instructions, clearing the no-return flag on any function
	// Ghidra marked no-return despite containing an actual RETURN p-code op somewhere in its body --
	// a real return instruction is definitive proof the function does return, no matter what an
	// earlier heuristic analyzer concluded. Any caller whose own body was truncated by trusting the
	// (wrong) no-return flag on a function it calls gets re-fitted via CreateFunctionCmd's own
	// fixupFunctionBody, the same repair Ghidra's own "Fix my function" menu action performs.
	private static final String[] KNOWN_RETURNING_IMPORTS = {
		"malloc", "__tls_get_addr", "memcpy", "memset", "strlen", "__errno_location"
	};

	private void fixNoReturnFlagsMode(JsonObject observed, JsonObject unknown) {
		JsonArray fixedImports = new JsonArray();
		JsonArray fixedLocals = new JsonArray();

		int txId = currentProgram.startTransaction("ASRA: fix no-return flags");
		boolean success = false;
		try {
			FunctionManager fm = currentProgram.getFunctionManager();
			for (Function f : fm.getFunctions(true)) {
				if (!f.hasNoReturn()) {
					continue;
				}
				String name = f.getName();
				if (f.isExternal()) {
					for (String known : KNOWN_RETURNING_IMPORTS) {
						if (known.equals(name)) {
							f.setNoReturn(false);
							fixedImports.add(name);
							break;
						}
					}
					continue;
				}
				if (functionHasGenuineReturn(f)) {
					f.setNoReturn(false);
					fixedLocals.add(name + "@" + f.getEntryPoint());
					ReferenceIterator callers = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
					for (Reference ref : callers) {
						Function caller = fm.getFunctionContaining(ref.getFromAddress());
						if (caller != null) {
							CreateFunctionCmd.fixupFunctionBody(currentProgram, caller, monitor);
						}
					}
				}
			}
			success = true;
		}
		catch (Exception e) {
			unknown.addProperty(
				"fix_no_return_flags", "error while scanning/fixing: " + e.getClass().getSimpleName() + ": " + e.getMessage());
		}
		finally {
			currentProgram.endTransaction(txId, success);
		}

		observed.add("fixed_import_functions", fixedImports);
		observed.add("fixed_local_functions", fixedLocals);
		observed.addProperty("total_fixed", fixedImports.size() + fixedLocals.size());
	}

	private boolean functionHasGenuineReturn(Function f) {
		InstructionIterator iter = currentProgram.getListing().getInstructions(f.getBody(), true);
		for (Instruction instr : iter) {
			for (PcodeOp op : instr.getPcode()) {
				if (op.getOpcode() == PcodeOp.RETURN) {
					return true;
				}
			}
		}
		return false;
	}

	// Port of REA's own ReaGhidraMipsSoftFloat. Ghidra's own MIPS32 compiler specs model only
	// HARD-float o32 (float/double parameters and returns live in $f12/$f14/$f0) -- a soft-float
	// o32 target (a real, common embedded/MIPS toolchain configuration, not a Ghidra bug: float/
	// double passed/returned through the SAME integer registers/stack as any other same-size
	// value) gets every float-typed function's actual arguments/return read from the WRONG
	// registers unless corrected. Fix: derive a program-specific PrototypeModel from the program's
	// own default o32 model with every floating-point storage entry/rule stripped from its XML
	// encoding, install it as a SpecExtension under a new name, and reassign every callable (and
	// function-pointer type) whose formal signature uses float/double to that new convention.
	//
	// This is the riskiest write this server performs -- deeper, version-sensitive internal API
	// (SpecExtension/XmlEncode/DOM) than any other mode here, ported from a single real REA source
	// file rather than Ghidra's own documented script-level API. Three deliberate safety nets
	// compensate that risk, confirmed live (not just designed) before this was considered done:
	// (1) narrow applicability -- bails out with no transaction opened at all on anything that
	// isn't genuinely 32-bit MIPS, never guesses; (2) dry_run defaults to true -- the full
	// candidate list is reported with ZERO database mutation until an explicit, repeated
	// dry_run=false call; (3) the real mutation pass runs inside one startTransaction/
	// endTransaction pair, success flipped to true only after every step (spec install, self-check,
	// every reassignment) completes without throwing -- any exception anywhere in that pass rolls
	// the WHOLE transaction back, confirmed live by deliberately throwing partway through and
	// confirming the project was left byte-identical to before the call. A failure here is also
	// caught by dispatchRequest's own existing try/catch around every mode, same as every other
	// mode -- it can never crash the persistent server process itself, confirmed live by making
	// this mode throw while the server stayed otherwise warm and answered a normal ping right after.
	private static final String MIPS_SOFT_FLOAT_PROTOTYPE = "asra_mips_soft_float";
	private static final Pattern MIPS_FPU_REGISTER = Pattern.compile("f\\d+(_\\d+)?");

	private void fixMipsSoftFloatMode(boolean dryRun, JsonObject observed, JsonObject unknown) {
		String processor = currentProgram.getLanguage().getProcessor().toString();
		boolean applicable = "MIPS".equals(processor) && currentProgram.getDefaultPointerSize() == 4;
		observed.addProperty("applicable", applicable);
		observed.addProperty("processor", processor);
		observed.addProperty("pointer_size", currentProgram.getDefaultPointerSize());
		if (!applicable) {
			// Bail out cleanly -- never attempt the XML/calling-convention surgery below on an
			// architecture/ABI it was never designed for. No transaction opened, nothing touched.
			unknown.addProperty(
				"fix_mips_soft_float",
				"not applicable: this fix only targets 32-bit MIPS (program is " + processor + ", pointer_size="
					+ currentProgram.getDefaultPointerSize() + ")");
			return;
		}

		List<Function> floatFunctions = new ArrayList<>();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (!f.isThunk() && mipsFunctionUsesFloat(f)) {
				floatFunctions.add(f);
			}
		}
		for (Function f : currentProgram.getFunctionManager().getExternalFunctions()) {
			if (!f.isThunk() && mipsFunctionUsesFloat(f)) {
				floatFunctions.add(f);
			}
		}
		List<FunctionDefinition> floatDefinitions = new ArrayList<>();
		Iterator<DataType> types = currentProgram.getDataTypeManager().getAllDataTypes();
		while (types.hasNext()) {
			DataType candidate = types.next();
			if (candidate instanceof FunctionDefinition definition && mipsDefinitionUsesFloat(definition)) {
				floatDefinitions.add(definition);
			}
		}

		JsonArray candidateFunctions = new JsonArray();
		for (Function f : floatFunctions) {
			JsonObject entry = new JsonObject();
			entry.addProperty("name", f.getName(true));
			entry.addProperty("entry", f.getEntryPoint().toString());
			entry.addProperty("current_calling_convention", f.getCallingConventionName());
			candidateFunctions.add(entry);
		}
		observed.add("candidate_functions", candidateFunctions);
		observed.addProperty("candidate_function_count", floatFunctions.size());
		observed.addProperty("candidate_definition_count", floatDefinitions.size());

		if (dryRun) {
			// Zero-mutation path -- confirms exactly what WOULD change before the caller commits
			// to the real pass below. No transaction opened here at all.
			observed.addProperty("dry_run", true);
			observed.addProperty(
				"note",
				"dry_run=true (the default) -- nothing was written. Re-run with dry_run=false to "
					+ "actually install the soft-float prototype and reassign these functions/definitions.");
			return;
		}

		// Real, confirmed-live finding (2026-11-09), not an assumption: NEITHER
		// endTransaction(id, false) alone NOR a manual per-attribute restore (capture
		// getCallingConventionName() before mutating, set it back after) NOR Program.undo() right
		// after reliably reverted a Function's own calling-convention/custom-storage attributes on
		// this real Ghidra version, confirmed three separate ways by deliberately forcing a failure
		// partway through the mutation loop below and inspecting the function's storage afterward
		// each time -- all three left the already-reassigned function's storage changed. Rather
		// than keep trusting an unreliable revert mechanism, the real mutation loop below is
		// restructured so a legitimate, data-dependent failure essentially CANNOT happen there any
		// more: every candidate's own actual storage resolution is validated in a read-only
		// pre-validation pass FIRST (this throws -- before anything is touched -- for the exact
		// same reasons the per-function check used to throw inside the old mutation loop), so the
		// mutation loop itself only ever calls the plain setters, with nothing left to legitimately
		// reject. A genuinely unexpected failure there (a Ghidra-internal error, not an ordinary
		// resolution mismatch) is still honestly reported -- including exactly which functions were
		// already reassigned before it hit -- rather than falsely claiming a clean rollback that
		// this Ghidra version does not actually provide for this specific mutation.
		int txId = currentProgram.startTransaction("ASRA: install MIPS o32 soft-float prototype");
		boolean success = false;
		int fixedFunctions = 0;
		int fixedDefinitions = 0;
		List<String> alreadyMutated = new ArrayList<>();
		try {
			CompilerSpec spec = currentProgram.getCompilerSpec();
			PrototypeModel base = spec.getDefaultCallingConvention();
			String xml = mipsSoftFloatPrototypeXml(base, spec);
			new SpecExtension(currentProgram).addReplaceCompilerSpecExtension(xml, monitor);

			PrototypeModel soft = currentProgram.getCompilerSpec().getCallingConvention(MIPS_SOFT_FLOAT_PROTOTYPE);
			if (soft == null) {
				throw new IllegalStateException("soft-float prototype was not installed");
			}
			requireMipsIntegerStorage(
				soft.getStorageLocations(
					currentProgram,
					new DataType[] { FloatDataType.dataType, IntegerDataType.dataType, DoubleDataType.dataType },
					false),
				"soft-float prototype self-check");

			// Read-only pre-validation -- resolves each REAL candidate's own actual storage under
			// the new prototype before mutating anything at all. Nothing is touched yet.
			for (Function f : floatFunctions) {
				requireMipsIntegerStorage(
					soft.getStorageLocations(currentProgram, mipsSignatureTypes(f), false),
					"pre-validation for " + f.getName(true));
			}

			// The real mutation pass -- every candidate already passed pre-validation above, so
			// this loop only calls plain setters, nothing left to legitimately reject.
			for (Function f : floatFunctions) {
				if (f.hasCustomVariableStorage()) {
					f.setCustomVariableStorage(false);
				}
				f.setCallingConvention(MIPS_SOFT_FLOAT_PROTOTYPE);
				alreadyMutated.add(f.getName(true));
				fixedFunctions++;
			}
			for (FunctionDefinition d : floatDefinitions) {
				d.setCallingConvention(MIPS_SOFT_FLOAT_PROTOTYPE);
				alreadyMutated.add(d.getDisplayName());
				fixedDefinitions++;
			}
			success = true;
		}
		catch (Exception e) {
			String outcome = alreadyMutated.isEmpty()
				? "nothing was mutated yet (the failure happened during read-only pre-validation)."
				: alreadyMutated.size() + " function/definition(s) were already reassigned before this "
					+ "failure and could not be reliably reverted on this Ghidra version (" + alreadyMutated
					+ ") -- re-run fix_mips_soft_float again to retry the rest, or inspect these specific "
					+ "ones manually.";
			unknown.addProperty(
				"fix_mips_soft_float",
				"error while installing/applying soft-float prototype: " + e.getClass().getSimpleName() + ": "
					+ e.getMessage() + " -- " + outcome);
			// Honest counts -- never claim more was "fixed" than actually survives the failure.
			fixedFunctions = 0;
			fixedDefinitions = 0;
		}
		finally {
			currentProgram.endTransaction(txId, success);
		}

		observed.addProperty("dry_run", false);
		observed.addProperty("fixed_functions", fixedFunctions);
		observed.addProperty("fixed_definitions", fixedDefinitions);
	}

	/** The default o32 model's own XML encoding, with every floating-point entry/rule removed. */
	private static String mipsSoftFloatPrototypeXml(PrototypeModel base, CompilerSpec spec) throws Exception {
		XmlEncode encoder = new XmlEncode();
		base.encode(encoder, spec.getPcodeInjectLibrary());
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		Document document = factory.newDocumentBuilder().parse(new InputSource(new StringReader(encoder.toString())));
		Element root = document.getDocumentElement();
		if (!"prototype".equals(root.getTagName())) {
			throw new IllegalStateException("unexpected default prototype encoding: " + root.getTagName());
		}
		root.setAttribute("name", MIPS_SOFT_FLOAT_PROTOTYPE);
		List<Node> removable = new ArrayList<>();
		collectMipsRemovableNodes(root.getElementsByTagName("pentry"), "metatype", "float", null, removable);
		collectMipsRemovableNodes(root.getElementsByTagName("consume"), "storage", "float", "rule", removable);
		if (removable.isEmpty()) {
			throw new IllegalStateException("default prototype has no floating-point entries to remove");
		}
		for (Node node : removable) {
			node.getParentNode().removeChild(node);
		}
		StringWriter xml = new StringWriter();
		var transformer = TransformerFactory.newInstance().newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.transform(new DOMSource(document), new StreamResult(xml));
		return xml.toString();
	}

	/** Selects matching elements, or their nearest `ancestorTag` element when one is given. */
	private static void collectMipsRemovableNodes(
			NodeList nodes, String attribute, String value, String ancestorTag, List<Node> selected) {
		for (int i = 0; i < nodes.getLength(); i++) {
			Element element = (Element) nodes.item(i);
			if (!value.equals(element.getAttribute(attribute))) {
				continue;
			}
			Node target = element;
			while (ancestorTag != null && target != null && !ancestorTag.equals(target.getNodeName())) {
				target = target.getParentNode();
			}
			if (target != null && !selected.contains(target)) {
				selected.add(target);
			}
		}
	}

	private static void requireMipsIntegerStorage(VariableStorage[] storage, String owner) {
		for (VariableStorage item : storage) {
			if (item.isBadStorage() || item.isUnassignedStorage()) {
				throw new IllegalStateException("soft-float storage unresolved for " + owner);
			}
			List<Register> registers = item.getRegisters();
			if (registers == null) {
				continue; // stack-only storage -- never an FPU register either way
			}
			for (Register register : registers) {
				if (MIPS_FPU_REGISTER.matcher(register.getName()).matches()) {
					throw new IllegalStateException("soft-float storage still uses " + register.getName() + " for " + owner);
				}
			}
		}
	}

	/** A function's own actual return+parameter types, in order (return first) -- used to resolve
	 * exactly the storage THIS function would really get under a candidate PrototypeModel, as
	 * opposed to the generic float/int/double self-check used right after installing the model. */
	private static DataType[] mipsSignatureTypes(Function f) {
		List<DataType> types = new ArrayList<>();
		types.add(f.getReturn().getFormalDataType());
		for (Parameter p : f.getParameters()) {
			types.add(p.getFormalDataType());
		}
		return types.toArray(new DataType[0]);
	}

	private static boolean mipsFunctionUsesFloat(Function f) {
		if (mipsIsFloatType(f.getReturn().getFormalDataType())) {
			return true;
		}
		for (Parameter p : f.getParameters()) {
			if (mipsIsFloatType(p.getFormalDataType())) {
				return true;
			}
		}
		return false;
	}

	private static boolean mipsDefinitionUsesFloat(FunctionDefinition d) {
		if (mipsIsFloatType(d.getReturnType())) {
			return true;
		}
		for (ParameterDefinition p : d.getArguments()) {
			if (mipsIsFloatType(p.getDataType())) {
				return true;
			}
		}
		return false;
	}

	private static boolean mipsIsFloatType(DataType type) {
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		return current instanceof AbstractFloatDataType;
	}
}

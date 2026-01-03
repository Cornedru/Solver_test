use crate::disassembler::RecursiveDisassembler;
use crate::parser::{
    functions::FindFunctions, magic_bits::{OpcodeParser, Opcode, normalize_bits}, offset::FindOffset,
    payload::PayloadKeyExtractor, vm::ScriptVisitor,
};
use anyhow::Context;
use oxc_allocator::Allocator;
use oxc_ast::ast::Program;
use oxc_ast_visit::{Visit, VisitMut};
use rustc_hash::FxHashMap;

// src/disassembler/disassemble.rs

pub fn parse_script_interpreter<'a>(
    program: &'a mut Program<'a>,
    allocator: &'a Allocator,
) -> Result<(
    RecursiveDisassembler<'a>,
    ScriptVisitor,
    PayloadKeyExtractor,
    String,
    String,
    FxHashMap<String, String>,
), anyhow::Error> {
    let mut find_functions = FindFunctions::default();
    find_functions.visit_program(program);

    let mut find_offset = FindOffset::new(&allocator);
    find_offset.visit_program(program);

    let mut opcode_parser =
        OpcodeParser::new(find_functions.constants, find_functions.functions.clone());
    opcode_parser.visit_program(program);

    let mut opcode_to_function_name = FxHashMap::default();

    // Helper local pour extraire les bits sans erreur de lifetime
    fn get_bits(op: &Opcode) -> &[u16] {
        match op {
            Opcode::ArrayPush(o) | Opcode::Throw(o) | Opcode::Bind(o) | Opcode::RegisterVMFunction(o) |
            Opcode::NewObject(o) | Opcode::Pop(o) | Opcode::SetProperty(o) | Opcode::GetProperty(o) |
            Opcode::SplicePop(o) | Opcode::CallFuncNoContext(o) | Opcode::SwapRegister(o) |
            Opcode::NewArray(o) | Opcode::Jump(o) | Opcode::JumpIf(o) | Opcode::Move(o) | Opcode::Call(o) => &o.bits,
            Opcode::Binary(o) => &o.bits,
            Opcode::Unary(o) => &o.bits,
            Opcode::NewLiteral(o) => &o.bits,
            Opcode::Heap(o) => &o.bits,
        }
    }

    // After building opcode_parser.opcodes (map<u16, Opcode>)
    eprintln!("[disassemble] opcode table size = {}", opcode_parser.opcodes.len());

    // Build normalized opcode map: normalized_bits -> opcode_key
    let mut normalized_opcode_map: std::collections::HashMap<Vec<u16>, u16> = Default::default();
    for (k, v) in &opcode_parser.opcodes {
        let bits = get_bits(v); // existing helper to extract Vec<u16> from Opcode enum
        let normalized = normalize_bits(bits);
        if !normalized.is_empty() {
            normalized_opcode_map.insert(normalized, *k);
        }
    }

    // Map functions -> opcode index (with normalized-bits fallback using FindFunctions captured bits)
    for (function_name, idx) in &find_functions.functions {
        if *idx == 195 || *idx == 127 || (*idx as usize) > 1000 {
            eprintln!(
                "[disassemble] SKIP mapping function '{}' -> {} (invalid index)",
                function_name, idx
            );
            continue;
        }

        // direct lookup
        if opcode_parser.opcodes.get(idx).is_some() {
            opcode_to_function_name.insert(idx.to_string(), function_name.to_string());
            continue;
        }

        // FALLBACK: try normalized-bit matching using bits captured by FindFunctions
        if let Some(candidate_bits) = find_functions.get_bits_for_index(*idx) {
            let normalized_candidate = normalize_bits(candidate_bits.as_slice());
            if let Some(matched_idx) = normalized_opcode_map.get(&normalized_candidate) {
                eprintln!(
                    "[disassemble] mapped function '{}' -> {} via normalized bits (fallback)",
                    function_name, matched_idx
                );
                opcode_to_function_name.insert(matched_idx.to_string(), function_name.to_string());
                continue;
            } else {
                eprintln!(
                    "[disassemble] no normalized match for function '{}' idx={} normalized_candidate={:?}",
                    function_name, idx, normalized_candidate
                );
            }
        }

        eprintln!("[disassemble] ❌ Fonction {} liée à un opcode non indexé : {} (lookup failed)", function_name, idx);
        let sample_keys: Vec<u16> = opcode_parser.opcodes.keys().cloned().take(20).collect();
        eprintln!("[disassemble] opcode_parser keys sample: {:?}", sample_keys);
    }

    let mut payload_key_extractor = PayloadKeyExtractor::default();
    payload_key_extractor.visit_program(program);

    let mut vm_bytecode_visitor = ScriptVisitor::default();
    vm_bytecode_visitor.visit_program(program);
    
    let initial_vm = vm_bytecode_visitor.initial_vm.as_ref().context("could not find initial vm")?;

    Ok((
        RecursiveDisassembler::new(
            opcode_parser.opcodes.clone(),
            find_offset.key_expr.expect("Key expression not found"),
            find_functions.key,
            find_offset.offset as u16,
            initial_vm.as_str(),
        )?,
        vm_bytecode_visitor,
        payload_key_extractor,
        opcode_parser.create_function_ident.to_string(),
        find_functions.function_with_opcodes.to_string(),
        opcode_to_function_name,
    ))
}
#include "hello_pass.h"
#include <deque>
#include <llvm/IR/CFG.h>

void TaintPass::initialize_sinks() {
  // Please put sinks list here!
  funcAPI f_strcpy;
  f_strcpy.argc = 1; // the second argument is sink
  f_strcpy.name = "strcpy";

  sinks.push_back(f_strcpy);
#ifdef DEBUG
  outs() << "Add strcpy to sink points!\n";
#endif
}

void print_one_entry(Instruction *inst, int idx) {
  errs() << "\t\t\U0001F504 ";
  errs() << "#" << idx;
  errs() << " " << inst->getParent()->getParent()->getName(); // module name
  errs() << " : " << *inst << "\n";
}

void TaintPass::printBackTrace(Instruction *inst) {
  int idx = 0;
  errs() << "<<<<<<<<<<<<<<<<<<<<<<<< Begin of backtrace "
            ">>>>>>>>>>>>>>>>>>>>>>>\n";
  errs() << "\t\U0001F525 Vulnerability detected \U0001F525\n";
  errs() << "\t\U0001F500 The Trace is:\n";
  print_one_entry(inst, idx++);
  for (int i = backtrace_list.size() - 1; i >= 0; i--) {
    print_one_entry(backtrace_list[i], idx);
  }
  errs() << "<<<<<<<<<<<<<<<<<<<<<<<<<<<<< END "
            ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n";
}

/**
 * Second Step of taint:
 *
 * The process of tainting population at specific function.
 *
 * @Parameters:
 *  cur_func: is the current Function that we are traversing
 *  tainted_sets: tainted sets of current function
 */
void TaintPass::traverseFunc(Function *cur_func,
                             std::set<Value *> &tainted_set) {
  int cur_index = 0;

  // the queue that stores all tainted Values that to visited
  std::deque<BasicBlock *> block_queue;
  std::set<BasicBlock *> visited;
  BasicBlock *cur_block;

  // this function do not contains basic blocks
  if (cur_func->size() == 0)
    return;

  // traverse every instruction follow the Controw Flow Graph (Breadth first
  // search)
  block_queue.push_back(&(cur_func->getEntryBlock()));

  // Notes: this algorithm is not perfect.
  // TODO. SCC componments and topological sort
  while (!block_queue.empty()) {
    cur_block = block_queue.front();
    block_queue.pop_front();

    if (visited.find(cur_block) != visited.end())
      continue;

    visited.insert(cur_block);

    for (Instruction &cur_visited_i : *cur_block) {
      // LLVM Instruction Reference:
      // https://llvm.org/docs/LangRef.html#instruction-reference
      unsigned opcode = cur_visited_i.getOpcode();
      std::set<int> tainted_slots;
      std::set<Value *> new_tainted_set;

      switch (opcode) {
      case Instruction::Store: {
        // store instruction:
        // https://llvm.org/docs/LangRef.html#store-instruction example: `store
        // i32 3, i32* %ptr`
        StoreInst *storeinst = dyn_cast<StoreInst>(&cur_visited_i);
#ifdef DEBUG
        outs() << "Current Instruction is: " << *storeinst << "\n";
#endif

        // TODO. Check if the first operand of StoreInst is tainted.
        // If so, add the second operand into tainted_set;
        // Please **Fill in**
        if (tainted_set.count(storeinst->getOperand(0))) {
            tainted_set.insert(storeinst->getOperand(1));
        }
        // END ** Fill in **

        break;
      }
      case Instruction::Load: {
        // load instruction: https://llvm.org/docs/LangRef.html#load-instruction
        // example: `%val = load i32, i32* %ptr`
        LoadInst *loadinst = dyn_cast<LoadInst>(&cur_visited_i);

#ifdef DEBUG
        outs() << "Current Instruction is: " << *loadinst << "\n";
#endif

        // TODO. Check if the first operand of LoadInst is tainted.
        // If so, add the `result` into tainted_set;
        // Please **Fill in**
        if(tainted_set.count(loadinst->getOperand(0))){
            tainted_set.insert(loadinst);
        }
        // END ** Fill in **

        break;
      }
      case Instruction::GetElementPtr: {
        // GEP instruction:
        // https://llvm.org/docs/LangRef.html#getelementptr-instruction
        GetElementPtrInst *gepinst =
            dyn_cast<GetElementPtrInst>(&cur_visited_i);

#ifdef DEBUG
        outs() << "Current Instruction is: " << *gepinst << "\n";
#endif

        // TODO. Check if the first operand of GEP is tainted.
        // If so, add the `result` into tainted_set;
        // Please **Fill in**
        if(tainted_set.count(gepinst->getOperand(0))){
            tainted_set.insert(gepinst);
        }
        // END ** Fill in **

        break;
      }

      case Instruction::BitCast: {
        // bitcast instruction:
        // https://llvm.org/docs/LangRef.html#bitcast-to-instruction
        BitCastInst *castinst = dyn_cast<BitCastInst>(&cur_visited_i);
        Value *src = castinst->getOperand(0);

        if (tainted_set.find(src) != tainted_set.end()) {
#ifdef DEBUG
          outs() << "Tainting: " << *castinst << "\n";
#endif
          tainted_set.insert(castinst);
        }
        break;
      }

      case Instruction::PHI: {
        // phi instruction:
        // https://llvm.org/docs/LangRef.html#bitcast-to-instruction
        llvm::PHINode *phi = dyn_cast<llvm::PHINode>(&cur_visited_i);

        for (int i = 0, cnt = phi->getNumIncomingValues(); i < cnt; i++) {
          auto cur_v = phi->getIncomingValue(i);

          if (tainted_set.find(cur_v) != tainted_set.end()) {
#ifdef DEBUG
            outs() << "Tainting: " << *phi << "\n";
#endif
            tainted_set.insert(phi);
            break;
          }
        }
        break;
      }
      // third step: find the sink function
      case Instruction::Call: {
        // call instruction: https://llvm.org/docs/LangRef.html#call-instruction
        CallInst *callinst = dyn_cast<CallInst>(&cur_visited_i);
        Function *called_func = callinst->getCalledFunction();

        // Check if current function is sink functin or not
        funcAPI *sink_f = nullptr;
        for (auto cur_sink : sinks) {
          if (cur_sink.name == called_func->getName()) {
            sink_f = &cur_sink;
            break;
          }
        }

        // loop through the argument of call instruction
        // to find the index of tainted argument
        int cur_arg_idx = 0;

        for (auto called_arg = callinst->arg_begin();
             called_arg != callinst->arg_end(); called_arg++) {
          if (tainted_set.find(called_arg->get()) != tainted_set.end()) {
            tainted_slots.insert(cur_arg_idx);
          }
          cur_arg_idx++;
        }

        if (sink_f) {
          // We found sink function.
          // Lets check if the argument is tainted
          if (tainted_slots.find(sink_f->argc) != tainted_slots.end()) {
            printBackTrace(&cur_visited_i);
          }
        } else { // follow the targeted function

          if (called_func->size() > 0) {

            // add backtrace list
            backtrace_list.push_back(callinst);
            cur_arg_idx = 0;

            for (auto called_arg = called_func->arg_begin();
                 called_arg != called_func->arg_end(); ++called_arg) {
              if (tainted_slots.find(cur_arg_idx) != tainted_slots.end()) {
                new_tainted_set.insert(called_arg);
              }
              cur_arg_idx++;
            }

            if (new_tainted_set.size() > 0) {
              outs() << "HELLO, traverse " << called_func->getName() << "\n";
              traverseFunc(called_func, new_tainted_set);
            }

            backtrace_list.pop_back();
          }
        }
      }
      default:
        break;
      }
    }

    // get successors of basic block
    for (auto succe : successors(cur_block)) {
      if (visited.find(succe) == visited.end()) {
        block_queue.push_back(succe);
      }
    }
  }
}

void TaintPass::taintAnalysis(Function *main_f) {
  // first step: find the `Source`
  // For this project, the source is second of main function
  std::set<Value *> tainted_set;

  // TODO. Please **Fill in**.
  // Hints. Please add the second argument
  // of `main` into tainted_set
  tainted_set.insert(main_f->arg_begin() + 1);
  // end of **Fill in**

  traverseFunc(main_f, tainted_set);
}

bool TaintPass::runOnModule(Module &M) {
  Function *main_func = nullptr;
  // looping through functions to find the main functions.
  for (auto &f : M) {

    // f_name is StringRef type in llvm.
    // StringRef reference: https://llvm.org/doxygen/classllvm_1_1StringRef.html
    auto f_name = f.getName();

    if (!strcmp(f_name.data(), "main")) {
      main_func = &f;
      break;
    }
  }

  if (!main_func) {
    errs() << "Can't find main function, exit\n";
    return false;
  }

  initialize_sinks();

  // Ok. we have main function now.
  // Perform taint analysis with Control Flow Analysis
  // and Data Flow Analysis
  taintAnalysis(main_func);

  // We do not modify the code, so return false.
  return false;
}

char TaintPass::ID = 0;
static RegisterPass<TaintPass> X("taint", "Static Taint Analysis", false,
                                 false);

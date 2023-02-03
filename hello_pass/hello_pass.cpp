#include <deque>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Use.h>
#include <llvm/IR/Value.h>
#include <llvm/Pass.h>
#include <llvm/Support/raw_ostream.h>
#include <set>
#include <unordered_set>
#include <vector>
#include <llvm/IR/DerivedTypes.h>
using namespace llvm;
namespace {

std::unordered_set<std::string> arg_parse = {
    "PyArg_ParseTuple", "PyArg_Parse", "PyArg_ParseTupleAndKeywords", "printf"};

std::unordered_set<std::string> arg_kw_parse = {
    "PyArg_VaParseTupleAndKeywords",
    "PyArg_ParseTupleAndKeywords",
};

std::unordered_set<std::string> arg_parse_va = {
    "PyArg_VaParseTupleAndKeywords",
    "PyArg_VaParse",
};
struct ArgPass : public FunctionPass {
public:
  static char ID;
  ArgPass() : FunctionPass(ID) {}
  bool runOnFunction(Function &);
  void runOnBB(BasicBlock &);

private:
  bool set_contain(std::unordered_set<std::string> s, std::string fname);
  int get_format_str(CallInst *inst, std::string &buf, int argno) {
    auto *op = dyn_cast<GlobalValue>(inst->getArgOperand(argno));
    if (!op) {
      return -1;
    }
    auto *gv = dyn_cast<GlobalVariable>(op);
    if (!gv) {
      return -2;
    }
    auto *fmt = dyn_cast<ConstantDataArray>(gv->getInitializer());
    if (!fmt) {
      return -3;
    }
    buf = fmt->getAsString().str();
    return 0;
  }
};
} // namespace
bool ArgPass::runOnFunction(Function &F) {
  for (auto &BB : F) {
    runOnBB(BB);
  }
  return false;
}

bool ArgPass::set_contain(std::unordered_set<std::string> s,
                          std::string fname) {
  return (s.find(fname) != s.end());
}

void ArgPass::runOnBB(BasicBlock &B) {
  for (auto Inst = B.begin(), IE = B.end(); Inst != IE; ++Inst) {
    auto *inst = dyn_cast<CallInst>(Inst);
    if (!inst)
      continue;
    if (!set_contain(arg_parse, inst->getCalledFunction()->getName().str()))
      continue;
    auto *f = inst->getCalledFunction();
    errs() << "funcname: " << f->getName().str() << '\n';
    errs() << "isvaarg: " << f->isVarArg() << '\n';
    for (int i = 0; i < inst->getNumOperands(); ++i) {
      auto arg = inst->getOperand(i);
      errs() << arg->getType()->getTypeID() << '\n';
    }
  }
}

char ArgPass::ID = 0;
static RegisterPass<ArgPass> X("args", "check arg str usage", false, false);

#include <llvm/IR/Function.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/Pass.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/Use.h>
#include <set>
#include <vector>

using namespace llvm;

#define DEBUG

namespace {
    struct TaintPass : public ModulePass {
        typedef struct fAPI {
            std::string name; // function name
            int argc; // the argcTh argument that we care about. //! NOT ARG COUNT
                      // That is to say, For sink functions, we need to 
                      // to check which argument is tainted.
        } funcAPI;

    private:

        // list of call instructions that can
        // construct current backtrace
        std::vector<Instruction*> backtrace_list;
        std::vector<funcAPI> sinks;

        void initialize_sinks(); // initialize sinks
        void traverseFunc(Function* cur_func, std::set<Value*>& tainted_set); // The process of tainting population at specific function
    public:
        static char ID;
        TaintPass() : ModulePass(ID){}

        bool runOnModule(Module& M);
        void printBackTrace(Instruction *);
        void taintAnalysis(Function *);
    };
}

%include "ua.hpp"

// SWIG either doesn't support arrays in Python or they are not documented
// Instead, for get_operand_immvals, use this array_class
// There is little/no safety with arrayClass
//
// Now this SHOULD work, however, if you pass this object to
// get_operand_immvals, SWIG will complain that it expected a uval_t *
// Huh? isn't that why I made an array of uval_t? 
//%array_class(uval_t, uvalArray)
// Well, it's just that SWIG *actually* expects it to be an unsigned int array.
%array_class(unsigned int, uvalArray)

// Small function to get the global cmd pointer
// In Python it returns an insn_t class instance
%inline {
insn_t * get_current_instruction()
{
	return &cmd;
}
}

// Get the nth operand from the insn_t class
%inline {
op_t *get_instruction_operand(insn_t *ins, int n)
{
	if (!ins)
	{
		return NULL;
	}

	return &(ins->Operands[n]);
}
}


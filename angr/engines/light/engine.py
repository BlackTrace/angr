import logging

import ailment
import pyvex

from ..engine import SimEngine
from ..vex.irop import operations as vex_operations
from ...analyses.code_location import CodeLocation

l = logging.getLogger("angr.engines.light.engine")


class SimEngineLight(SimEngine):
    def __init__(self, engine_type='vex'):
        super(SimEngineLight, self).__init__()

        self.engine_type = engine_type

        # local variables
        self.state = None
        self.arch = None
        self.block = None

        self.stmt_idx = None
        self.ins_addr = None
        self.tmps = None
        self._function_summaries = {}

    def process(self, state, *args, **kwargs):
        # we are using a completely different state. Therefore, we directly call our _process() method before
        # SimEngine becomes flexible enough.
        self._function_summaries = kwargs.pop('function_summaries', {})
        self._process(state, None, block=kwargs.pop('block', None))

    def _process(self, new_state, successors, *args, **kwargs):
        raise NotImplementedError()

    def _check(self, state, *args, **kwargs):
        raise NotImplementedError()


class SimEngineLightVEX(SimEngineLight):
    def __init__(self):
        super(SimEngineLightVEX, self).__init__()

        # for VEX blocks only
        self.tyenv = None

    def _process(self, state, successors, block=None):

        assert block is not None

        # initialize local variables
        self.tmps = {}
        self.block = block
        self.state = state
        self.arch = state.arch

        self.tyenv = block.vex.tyenv

        self._process_Stmt()

        self.stmt_idx = None
        self.ins_addr = None

    def _process_Stmt(self):

        for stmt_idx, stmt in enumerate(self.block.vex.statements):
            self.stmt_idx = stmt_idx

            if type(stmt) is pyvex.IRStmt.IMark:
                self.ins_addr = stmt.addr + stmt.delta

            self._handle_Stmt(stmt)

        if self.block.vex.jumpkind == 'Ijk_Call':
            self._hl_handle_Call(stmt)

    #
    # Helper methods
    #

    def _codeloc(self):
        return CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr)

    #
    # Statement handlers
    #

    def _handle_Stmt(self, stmt):
        handler = "_handle_%s" % type(stmt).__name__
        if hasattr(self, handler):
            getattr(self, handler)(stmt)
        else:
            l.error('Unsupported statement type %s.', type(stmt).__name__)

    # synchronize with function _handle_WrTmpData()
    def _handle_WrTmp(self, stmt):
        data = self._expr(stmt.data)
        if data is None:
            return

        self.tmps[stmt.tmp] = data

    # invoked by LoadG
    def _handle_WrTmpData(self, tmp, data):
        if data is None:
            return
        self.tmps[tmp] = data

    def _handle_Put(self, stmt):
        raise NotImplementedError('Please implement the Put handler with your own logic.')

    def _handle_Store(self, stmt):
        raise NotImplementedError('Please implement the Store handler with your own logic.')

    #
    # Expression handlers
    #

    def _expr(self, expr):

        handler = "_handle_%s" % type(expr).__name__
        if hasattr(self, handler):
            return getattr(self, handler)(expr)
        else:
            l.error('Unsupported expression type %s.', type(expr).__name__)
        return None

    def _handle_RdTmp(self, expr):
        tmp = expr.tmp

        if tmp in self.tmps:
            return self.tmps[tmp]
        return None

    def _handle_Get(self, expr):
        raise NotImplementedError('Please implement the Get handler with your own logic.')

    def _handle_Load(self, expr):
        raise NotImplementedError('Please implement the Load handler with your own logic.')

    def _handle_Unop(self, expr):
        simop = vex_operations[expr.op]
        if simop.op_attrs['conversion']:
            return self._handle_Conversion(expr)
        elif expr.op.startswith('Iop_Not1'):
            return self._handle_Not1(expr)
        else:
            l.error('Unsupported Unop %s.', expr.op)

        return None

    def _handle_Binop(self, expr):
        if expr.op.startswith('Iop_And'):
            return self._handle_And(expr)
        elif expr.op.startswith('Iop_Or'):
            return self._handle_Or(expr)
        elif expr.op.startswith('Iop_Add'):
            return self._handle_Add(expr)
        elif expr.op.startswith('Iop_Sub'):
            return self._handle_Sub(expr)
        elif expr.op.startswith('Iop_Xor'):
            return self._handle_Xor(expr)
        elif expr.op.startswith('Iop_Shl'):
            return self._handle_Shl(expr)
        elif expr.op.startswith('Iop_Shr'):
            return self._handle_Shr(expr)
        elif expr.op.startswith('Iop_Sal'):
            # intended use of SHL
            return self._handle_Shl(expr)
        elif expr.op.startswith('Iop_Sar'):
            return self._handle_Sar(expr)
        elif expr.op.startswith('Iop_CmpEQ'):
            return self._handle_CmpEQ(expr)
        elif expr.op.startswith('Iop_CmpNE'):
            return self._handle_CmpNE(expr)
        elif expr.op.startswith('Iop_CmpORD'):
            return self._handle_CmpORD(expr)
        elif expr.op.startswith('Const'):
            return self._handle_Const(expr)
        else:
            l.error('Unsupported Binop %s', expr.op)

        return None

    def _handle_CCall(self, expr):
        l.error('Unsupported expression type CCall with callee %s.' % str(expr.cee))
        return

    #
    # Unary operation handlers
    #

    def _handle_Conversion(self, expr):
        raise NotImplementedError('Please implement the Conversion handler with your own logic.')

    def _handle_Not1(self, expr):
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None

        if not isinstance(expr_0, (int, long)):
            l.warning('Comparison of multiple values / different types: \'%s\'.', type(expr_0).__name__)

        return expr_0 != 1

    #
    # Binary operation handlers
    #

    def _handle_And(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 & expr_1
        except TypeError as e:
            l.warning(e)
            return None

    def _handle_Or(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 | expr_1
        except TypeError as e:
            l.warning(e)
            return None

    def _handle_Add(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            if isinstance(expr_0, (int, long)) and isinstance(expr_1, (int, long)):
                # self.tyenv is not used
                mask = (1 << expr.result_size(self.tyenv)) - 1
                return (expr_0 + expr_1) & mask
            else:
                return expr_0 + expr_1
        except TypeError as e:
            l.warning(e)
            return None

    def _handle_Sub(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            if isinstance(expr_0, (int, long)) and isinstance(expr_1, (int, long)):
                # self.tyenv is not used
                mask = (1 << expr.result_size(self.tyenv)) - 1
                return (expr_0 - expr_1) & mask
            else:
                return expr_0 - expr_1
        except TypeError as e:
            l.warning(e)
            return None

    def _handle_Xor(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 ^ expr_1
        except TypeError as e:
            l.warning(e)
            return None

    def _handle_Shl(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            if isinstance(expr_0, (int, long)) and isinstance(expr_1, (int, long)):
                # self.tyenv is not used
                mask = (1 << expr.result_size(self.tyenv)) - 1
                return (expr_0 << expr_1) & mask
            else:
                return expr_0 << expr_1
        except TypeError as e:
            l.warning(e)
            return None

    def _handle_Shr(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 >> expr_1
        except TypeError as e:
            l.warning(e)
            return None

    def _handle_Sar(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        size = expr.result_size(self.tyenv)
        # check if msb is set
        if expr_0 >> (size - 1) == 0:
            head = 0
        else:
            head = ((1 << expr_1) - 1) << (size - expr_1)
        try:
            return head | (expr_0 >> expr_1)
        except TypeError as e:
            l.warning(e)
            return None

    def _handle_CmpEQ(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        return expr_0 == expr_1

    def _handle_CmpNE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        return expr_0 != expr_1

    # ppc only
    def _handle_CmpORD(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        if expr_0 < expr_1:
            return 0x08
        elif expr_0 > expr_1:
            return 0x04
        else:
            return 0x02

    def _handle_Const(self, expr):
        return expr.con.value

    def _hl_handle_Call(self, arg):
        raise NotImplementedError('Please implement the Call handler with your own logic.')


class SimEngineLightAIL(SimEngineLight):
    def __init__(self):
        super(SimEngineLightAIL, self).__init__(engine_type='ail')

    def _process(self, state, successors, block=None):

        self.tmps = {}
        self.block = block
        self.state = state
        self.arch = state.arch

        self._process_Stmt()

        self.stmt_idx = None
        self.ins_addr = None

    def _process_Stmt(self):

        for stmt_idx, stmt in enumerate(self.block.statements):
            self.stmt_idx = stmt_idx
            self.ins_addr = stmt.ins_addr

            self._ail_handle_Stmt(stmt)

    def _expr(self, expr):

        handler = "_ail_handle_%s" % type(expr).__name__
        if hasattr(self, handler):
            return getattr(self, handler)(expr)
        l.warning('Unsupported expression type %s.', type(expr).__name__)
        return None

    #
    # Helper methods
    #

    def _codeloc(self):
        return CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr)

    #
    # Statement handlers
    #

    def _ail_handle_Stmt(self, stmt):
        handler = "_ail_handle_%s" % type(stmt).__name__
        if hasattr(self, handler):
            getattr(self, handler)(stmt)
        else:
            l.warning('Unsupported statement type %s.', type(stmt).__name__)

    def _ail_handle_Jump(self, stmt):
        raise NotImplementedError('Please implement the Jump handler with your own logic.')

    def _ail_handle_Call(self, stmt):
        raise NotImplementedError('Please implement the Call handler with your own logic.')

    #
    # Expression handlers
    #

    def _ail_handle_Const(self, expr):
        return expr.value

    def _ail_handle_Tmp(self, expr):
        tmp_idx = expr.tmp_idx

        try:
            return self.tmps[tmp_idx]
        except KeyError:
            return None

    def _ail_handle_Load(self, expr):
        raise NotImplementedError('Please implement the Load handler with your own logic.')

    def _ail_handle_UnaryOp(self, expr):
        handler_name = '_ail_handle_%s' % expr.op
        try:
            handler = getattr(self, handler_name)
        except AttributeError:
            l.warning('Unsupported UnaryOp %s.', expr.op)
            return None

        return handler(expr)

    def _ail_handle_BinaryOp(self, expr):
        handler_name = '_ail_handle_%s' % expr.op
        try:
            handler = getattr(self, handler_name)
        except AttributeError:
            l.warning('Unsupported BinaryOp %s.', expr.op)
            return None

        return handler(expr)

    #
    # Binary operation handlers
    #

    def _ail_handle_Add(self, expr):

        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)
        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 + expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(expr.idx, 'Add', [expr_0, expr_1], **expr.tags)

    def _ail_handle_Sub(self, expr):

        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 - expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(expr.idx, 'Sub', [expr_0, expr_1], **expr.tags)

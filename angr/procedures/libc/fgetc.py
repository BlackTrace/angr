import angr
from angr.sim_type import SimTypeInt, SimTypeFd

######################################
# fgetc
######################################


class fgetc(angr.SimProcedure):
    # pylint:disable=arguments-differ
    def run(self, stream, simfile=None):
        self.argument_types = {0: SimTypeFd()}
        self.return_type = SimTypeInt(32, True)

        if simfile is None:
            fileno = angr.SIM_PROCEDURES['posix']['fileno']
            fd = self.inline_call(fileno, stream).ret_expr
            simfile = self.state.posix.get_file(fd)

        if simfile is None:
            return -1

        real_length, data = simfile.read_data(1)
        return self.state.solver.If(real_length == 0, -1, data.zero_extend(self.state.arch.bits - 8))

getc = fgetc

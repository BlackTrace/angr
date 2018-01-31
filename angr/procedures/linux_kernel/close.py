import angr

######################################
# close
######################################

class close(angr.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, fd):
        return self.state.posix.close(fd)
